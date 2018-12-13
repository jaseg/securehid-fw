/*
 * This file is part of the libusbhost library
 * hosted at http://github.com/libusbhost/libusbhost
 *
 * Copyright (C) 2015 Amir Hammad <amir.hammad@hotmail.com>
 *
 *
 * libusbhost is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "usart_helpers.h"
#include "usbh_core.h"
#include "usbh_lld_stm32f4.h"
#include "usbh_driver_hid.h"
#include "usbh_driver_hub.h"
#include "rand_stm32.h"
#include "packet_interface.h"
#include "noise.h"
#include "hid_keycodes.h"
#include "words.h"
#include "tracing.h"

#include "crypto/noise-c/src/protocol/internal.h"

#include <libopencm3/stm32/rcc.h>
#include <libopencm3/stm32/gpio.h>
#include <libopencm3/stm32/usart.h>
#include <libopencm3/stm32/timer.h>
#include <libopencm3/stm32/otg_hs.h>
#include <libopencm3/stm32/otg_fs.h>
#include <libopencm3/stm32/pwr.h>
#include <libopencm3/stm32/dma.h>
#include <libopencm3/cm3/nvic.h>
#include <libopencmsis/core_cm3.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifndef USE_STM32F4_USBH_DRIVER_FS
#error The full-speed USB driver must be enabled with USE_STM32F4_USBH_DRIVER_FS in usbh_config.h!
#endif

#ifndef MAX_FAILED_HANDSHAKES
#define MAX_FAILED_HANDSHAKES 5
#endif

static struct NoiseState noise_state;
static struct {
    union {
        struct {
            uint8_t local_key[CURVE25519_KEY_LEN];
            uint8_t remote_key_reference[BLAKE2S_HASH_SIZE];
        };
        uint32_t all_keys[0];
    } keys;
    struct {
        uint8_t identity_key_valid;
        uint8_t scrub_backup;
        uint8_t scrubber_armed;
        uint32_t old_scrub_pattern;
        uint32_t new_scrub_pattern;
        int scrub_idx_read;
        int scrub_idx_done;
    } mgmt __attribute__((aligned(4)));
} keystore __attribute__((section(".backup_sram"))) = {0};


void _fini(void);

static inline void delay(uint32_t n) {
	for (volatile uint32_t i = 0; i < 1490*n; i++);
}


/* Set STM32 to 168 MHz. */
static void clock_setup(void) {
	rcc_clock_setup_hse_3v3(&hse_8mhz_3v3[CLOCK_3V3_168MHZ]);

	rcc_periph_clock_enable(RCC_GPIOA);
	rcc_periph_clock_enable(RCC_GPIOB);
	rcc_periph_clock_enable(RCC_GPIOD);
	rcc_periph_clock_enable(RCC_GPIOE);

	rcc_periph_clock_enable(RCC_USART1);
	rcc_periph_clock_enable(RCC_USART2);
	rcc_periph_clock_enable(RCC_OTGFS);
	rcc_periph_clock_enable(RCC_TIM6);
	rcc_periph_clock_enable(RCC_DMA2);
	rcc_periph_clock_enable(RCC_DMA1);

	rcc_periph_clock_enable(RCC_PWR);
	rcc_periph_clock_enable(RCC_BKPSRAM);

	rcc_periph_clock_enable(RCC_RNG);
}

void arm_key_scrubber() {
    keystore.mgmt.scrubber_armed = 1;
}

static void finish_scrub(int start_index, uint32_t pattern);
static void finish_interrupted_scrub(void);

void disarm_key_scrubber() {
    keystore.mgmt.scrubber_armed = 0;
    keystore.mgmt.old_scrub_pattern = keystore.mgmt.new_scrub_pattern;
    keystore.mgmt.new_scrub_pattern = 0x00000000;
    finish_scrub(0, keystore.mgmt.old_scrub_pattern);
}

static void finish_scrub(int start_index, uint32_t pattern) {
    for (size_t i=start_index; i<sizeof(keystore.keys)/sizeof(keystore.keys.all_keys[0]); i++) {
        keystore.mgmt.scrub_backup = keystore.keys.all_keys[i];
        keystore.mgmt.scrub_idx_read = i;
        keystore.keys.all_keys[i] ^= pattern;
        keystore.mgmt.scrub_idx_done = i;
    }
}

static void finish_interrupted_scrub(void) {
    if (keystore.mgmt.scrub_idx_read != keystore.mgmt.scrub_idx_done)
        keystore.keys.all_keys[keystore.mgmt.scrub_idx_read] = keystore.mgmt.scrub_backup;

    finish_scrub(keystore.mgmt.scrub_idx_done, keystore.mgmt.old_scrub_pattern ^ keystore.mgmt.new_scrub_pattern);
}

/* setup 10kHz timer */
static void tim6_setup(void) {
	timer_reset(TIM6);
	timer_set_prescaler(TIM6, 8400 - 1);	// 84Mhz/10kHz - 1
	timer_set_period(TIM6, 65535);			// Overflow in ~6.5 seconds
    timer_enable_irq(TIM6, TIM_DIER_UIE);
    nvic_enable_irq(NVIC_TIM6_DAC_IRQ);
    nvic_set_priority(NVIC_TIM6_DAC_IRQ, 15<<4); /* really low priority */
	timer_enable_counter(TIM6);
}

void tim6_dac_isr(void) {
    /* Runs every ~6.5s on timer overrun */
    timer_clear_flag(TIM6, TIM_SR_UIF);

    if (!keystore.mgmt.scrubber_armed)
        return;

    keystore.mgmt.old_scrub_pattern = keystore.mgmt.new_scrub_pattern;
    noise_rand_bytes(&keystore.mgmt.new_scrub_pattern, sizeof(keystore.mgmt.new_scrub_pattern));
    LOG_PRINTF("Scrubbing keys using pattern %08x\n", keystore.mgmt.new_scrub_pattern);
    finish_scrub(0, keystore.mgmt.old_scrub_pattern ^ keystore.mgmt.new_scrub_pattern);
}

static uint32_t tim6_get_time_us(void)
{
	uint32_t cnt = timer_get_counter(TIM6);

	// convert to 1MHz less precise timer value -> units: microseconds
	uint32_t time_us = cnt * 100;

	return time_us;
}

static void gpio_setup(void)
{
    /* Tracing */
	gpio_mode_setup(GPIOD, GPIO_MODE_OUTPUT, GPIO_PUPD_NONE, 0xffff);

    /* D2, D3 LEDs */
	//gpio_mode_setup(GPIOA, GPIO_MODE_OUTPUT, GPIO_PUPD_NONE, GPIO6 | GPIO7);
	//gpio_set(GPIOA, GPIO6 | GPIO7);

    /* Status LEDs (PE4-15) */
	gpio_mode_setup(GPIOE, GPIO_MODE_INPUT, GPIO_PUPD_NONE, 0xfff0);

    /* Alarm LEDs (PA6,7) */
	gpio_mode_setup(GPIOA, GPIO_MODE_OUTPUT, GPIO_PUPD_NONE, GPIO6 | GPIO7);
	gpio_set(GPIOA, GPIO6 | GPIO7);
    
    /* Speaker */
	gpio_mode_setup(GPIOB, GPIO_MODE_OUTPUT, GPIO_PUPD_NONE, GPIO10);
	gpio_set(GPIOB, GPIO10);

    /* USB OTG FS phy outputs */
	gpio_mode_setup(GPIOA, GPIO_MODE_AF, GPIO_PUPD_NONE, GPIO11 | GPIO12);
	gpio_set_af(GPIOA, GPIO_AF10, GPIO11 | GPIO12);

	/* USART1 (debug) */
	gpio_mode_setup(GPIOA, GPIO_MODE_AF, GPIO_PUPD_NONE, GPIO9 | GPIO10);
	gpio_set_af(GPIOA, GPIO_AF7, GPIO9 | GPIO10);

    /* USART2 (host link) */
	gpio_mode_setup(GPIOA, GPIO_MODE_AF, GPIO_PUPD_NONE, GPIO2 | GPIO3);
	gpio_set_af(GPIOA, GPIO_AF7, GPIO2 | GPIO3);

    /* K0 (PE4)/K1 (PE3) buttons */
	//gpio_mode_setup(GPIOE, GPIO_MODE_INPUT, GPIO_PUPD_PULLUP, GPIO3 | GPIO4);
}

struct hid_report {
    uint8_t modifiers;
    uint8_t _reserved;
    uint8_t keycodes[6];
} __attribute__((__packed__));

static char pairing_buf[512];
static size_t pairing_buf_pos = 0;

int pairing_check(struct NoiseState *st, const char *buf);
void pairing_input(uint8_t modbyte, uint8_t keycode);
void pairing_parse_report(struct hid_report *buf, uint8_t len);

/* Minimum number of bytes of handshake hash to confirm during pairing */
#define MIN_PAIRING_SEQUENCE_LENGTH 8

int pairing_check(struct NoiseState *st, const char *buf) {
    //LOG_PRINTF("Checking pairing\n");
    const char *p = buf;
    int idx = 0;
    do {
        /* Skip over most special chars */
        while (*p) {
            char c = *p;
            if ('0' <= c && c <= '9') break;
            if ('a' <= c && c <= 'z') break;
            if ('A' <= c && c <= 'Z') break;
            if (c == '-') break;
            p++;
        }

        const char *found = strchr(p, ' ');
        size_t plen = found ? (size_t)(found - p) : strlen(p); /* p >= found */

        while (plen > 0) {
            char c = p[plen];
            if ('0' <= c && c <= '9') break;
            if ('a' <= c && c <= 'z') break;
            if ('A' <= c && c <= 'Z') break;
            if (c == '-') break;
            plen--;
        }
        plen++;
        //LOG_PRINTF("matching: \"%s\" - \"%s\" %d\n", p, p+plen, plen);

        if (strncasecmp(p, "and", plen)) { /* ignore "and" */
            int num = -1;
            for (int i=0; i<256; i++) {
                if ((!strncasecmp(p, even[i], plen) && plen == strlen(even[i]))
                 || (!strncasecmp(p, odd[i],      plen) && plen == strlen(odd[i]     ))) {
                    //LOG_PRINTF("    idx=%02d h=%02x i=%02x adj=%s n=%s plen=%d s=%s\n", idx, st->handshake_hash[idx], i, adjectives[i], nouns[i], plen, p);
                    num = i;
                    break;
                }
            }
            if (num == -1) {
                LOG_PRINTF("Pairing word \"%s\" not found in dictionary\n", p);
                return -1;
            }
            if (st->handshake_hash[idx] != num) {
                LOG_PRINTF("Pairing data does not match hash\n");
                return -1;
            }
            idx++;
        }

        p = strchr(p, ' ');
        if (!p)
            break; /* end of string */
        p++; /* skip space */
    } while (idx < BLAKE2S_HASH_SIZE);

    if (idx < MIN_PAIRING_SEQUENCE_LENGTH) {
        LOG_PRINTF("Pairing sequence too short, only %d bytes of hash checked\n", idx);
        return -1;
    }

    LOG_PRINTF("Pairing sequence match\n");
    return 0;
}

void pairing_input(uint8_t modbyte, uint8_t keycode) {
    char ch = 0;
    uint8_t level = modbyte & MOD_XSHIFT ? LEVEL_SHIFT : LEVEL_NONE;
    switch (keycode) {
        case KEY_ENTER:
            pairing_buf[pairing_buf_pos++] = '\0';
            if (!pairing_check(&noise_state, pairing_buf)) {
                persist_remote_key(&noise_state);
                /* FIXME write key to backup memory */

                uint8_t response = REPORT_PAIRING_SUCCESS;
                if (send_encrypted_message(&noise_state, &response, sizeof(response)))
                    LOG_PRINTF("Error sending pairing response packet\n");

            } else {
                /* FIXME sound alarm */

                pairing_buf_pos = 0; /* Reset input buffer */
                uint8_t response = REPORT_PAIRING_ERROR;
                if (send_encrypted_message(&noise_state, &response, sizeof(response)))
                    LOG_PRINTF("Error sending pairing response packet\n");
            }
            break;

        case KEY_BACKSPACE:
            if (pairing_buf_pos > 0)
                pairing_buf_pos--;
            pairing_buf[pairing_buf_pos] = '\0';
            ch = '\b';
            break;

        default:
            for (size_t i=0; keycode_mapping[i].kc != KEY_NONE; i++) {
                if (keycode_mapping[i].kc == keycode) {
                    ch = keycode_mapping[i].ch[level];
                    if (!ch)
                        break;

                    if (pairing_buf_pos < sizeof(pairing_buf)-1) /* allow for terminating null byte */ {
                        pairing_buf[pairing_buf_pos++] = ch;
                        pairing_buf[pairing_buf_pos] = '\0';
                    } else {
                        LOG_PRINTF("Pairing confirmation user input buffer full\n");

                        uint8_t response = REPORT_PAIRING_ERROR;
                        if (send_encrypted_message(&noise_state, &response, sizeof(response)))
                            LOG_PRINTF("Error sending pairing response packet\n");
                    }
                    break;
                }
            }
            break;
    }

    if (ch) {
        //LOG_PRINTF("Input: %s\n", pairing_buf);
        struct hid_report_packet pkt = {
            .type = REPORT_PAIRING_INPUT,
            .pairing_input = { .c = ch }
        };
        if (send_encrypted_message(&noise_state, (uint8_t *)&pkt, sizeof(pkt))) {
            LOG_PRINTF("Error sending pairing input packet\n");
            return;
        }
    }
}

void pairing_parse_report(struct hid_report *buf, uint8_t len) {
    static uint8_t old_keycodes[6] = {0};

    for (int i=0; i<len-2; i++) {
        if (!buf->keycodes[i])
            break; /* keycodes are always populated from low to high */

        int found = 0;
        for (int j=0; j<6; j++) {
            if (old_keycodes[j] == buf->keycodes[i]) {
                found = 1;
                break;
            }
        }
        if (!found) /* key pressed */
            pairing_input(buf->modifiers, buf->keycodes[i]);
    }

    memcpy(old_keycodes, buf->keycodes, 6);
}

static void hid_in_message_handler(uint8_t device_id, const uint8_t *data, uint32_t length) {
    TRACING_SET(TR_HID_MESSAGE_HANDLER);
	if (length < 4 || length > 8) {
		LOG_PRINTF("HID report length must be 4 < len < 8, is %d bytes\n", length);
        TRACING_CLEAR(TR_HID_MESSAGE_HANDLER);
		return;
	}

	//LOG_PRINTF("Sending event %02X %02X %02X %02X\n", data[0], data[1], data[2], data[3]);
	int type = hid_get_type(device_id);
    if (type != HID_TYPE_KEYBOARD && type != HID_TYPE_MOUSE) {
        LOG_PRINTF("Unsupported HID report type %x\n", type);
        TRACING_CLEAR(TR_HID_MESSAGE_HANDLER);
        return;
    }

    if (noise_state.handshake_state == HANDSHAKE_DONE_UNKNOWN_HOST) {
        if (type == HID_TYPE_KEYBOARD)
            pairing_parse_report((struct hid_report *)data, length);
        else
            LOG_PRINTF("Not sending HID mouse report during pairing\n");
        TRACING_CLEAR(TR_HID_MESSAGE_HANDLER);
        return;
    }

    struct hid_report_packet pkt = {
        .type = type == HID_TYPE_KEYBOARD ? REPORT_KEYBOARD : REPORT_MOUSE,
        .report = {
            .len = length,
            .report = {0}
        }
    };
    memcpy(pkt.report.report, data, length);

    if (send_encrypted_message(&noise_state, (uint8_t *)&pkt, sizeof(pkt))) {
        LOG_PRINTF("Error sending HID report packet\n");
        TRACING_CLEAR(TR_HID_MESSAGE_HANDLER);
        return;
    }
    TRACING_CLEAR(TR_HID_MESSAGE_HANDLER);
}

volatile struct {
    struct dma_buf dma;
    uint8_t data[256];
} debug_buf = { .dma = { .len = sizeof(debug_buf.data) } };

struct dma_usart_file debug_out_s = {
    .usart = DEBUG_USART,
    .baudrate = DEBUG_USART_BAUDRATE,
    .dma = DMA(DEBUG_USART_DMA_NUM),
    .stream = DEBUG_USART_DMA_STREAM_NUM,
    .channel = DEBUG_USART_DMA_CHANNEL_NUM,
    .irqn = NVIC_DMA_IRQ(DEBUG_USART_DMA_NUM, DEBUG_USART_DMA_STREAM_NUM),
    .buf = &debug_buf.dma
};
struct dma_usart_file *debug_out = &debug_out_s;

/* FIXME start unsafe debug code */
void usart1_isr(void) {
    if (USART1_SR & USART_SR_ORE) { /* Overrun handling */
        LOG_PRINTF("USART1 data register overrun\n");
        /* Clear interrupt flag */
        return (void)USART1_DR;
    }

    uint8_t data = USART1_DR; /* This automatically acknowledges the IRQ */
    for (size_t i=0; keycode_mapping[i].kc != KEY_NONE; i++) {
        struct hid_report report = {0};
        if (keycode_mapping[i].ch[0] == data)
            report.modifiers = 0;
        else if (keycode_mapping[i].ch[1] == data)
            report.modifiers = MOD_LSHIFT;
        else continue;

        report.keycodes[0] = keycode_mapping[i].kc;
        pairing_parse_report(&report, 8);
        break;
    }
    LOG_PRINTF(" %02x ", data);
    if (data == 0x7f) {
        struct hid_report report = {.modifiers=0, .keycodes={KEY_BACKSPACE, 0}};
        pairing_parse_report(&report, 8);
    } else if (data == '\r') {
        struct hid_report report = {.modifiers=0, .keycodes={KEY_ENTER, 0}};
        pairing_parse_report(&report, 8);
        LOG_PRINTF("\n");
    }

    struct hid_report report = {0};
    pairing_parse_report(&report, 8);
}
/* end unsafe debug code */

void DMA_ISR(DEBUG_USART_DMA_NUM, DEBUG_USART_DMA_STREAM_NUM)(void) {
    TRACING_SET(TR_DEBUG_OUT_DMA_IRQ);
    if (dma_get_interrupt_flag(debug_out->dma, debug_out->stream, DMA_FEIF)) {
        /* Ignore FIFO errors as they're 100% non-critical for UART applications */
        dma_clear_interrupt_flags(debug_out->dma, debug_out->stream, DMA_FEIF);
        TRACING_CLEAR(TR_DEBUG_OUT_DMA_IRQ);
        return;
    }

    /* Transfer complete */
	dma_clear_interrupt_flags(debug_out->dma, debug_out->stream, DMA_TCIF);

    if (debug_out->buf->wr_pos != debug_out->buf->xfr_end) /* buffer not empty */
        schedule_dma(debug_out);
    TRACING_CLEAR(TR_DEBUG_OUT_DMA_IRQ);
}

void handle_host_packet(struct control_packet *pkt, size_t payload_length) {
    TRACING_SET(TR_HOST_PKT_HANDLER);
    if (pkt->type == HOST_INITIATE_HANDSHAKE) {
        /* It is important that we acknowledge this command right away. Starting the handshake involves key
         * generation which takes a few milliseconds. If we'd acknowledge this later, we might run into an
         * overrun here since we would be blocking the buffer during key generation. */

        if (payload_length > 0) {
            LOG_PRINTF("Extraneous data in INITIATE_HANDSHAKE message\n");
        } else if (noise_state.failed_handshakes < MAX_FAILED_HANDSHAKES) {
            LOG_PRINTF("Starting noise protocol handshake...\n");
            if (reset_protocol_handshake(&noise_state))
                LOG_PRINTF("Error starting protocol handshake.\n");
            pairing_buf_pos = 0; /* Reset channel binding keyboard input buffer */
        } else {
            LOG_PRINTF("Too many failed handshake attempts, not starting another one\n");
            struct control_packet out = { .type=HOST_TOO_MANY_FAILS };
            send_packet(usart2_out, (uint8_t *)&out, sizeof(out));
        }

    } else if (pkt->type == HOST_HANDSHAKE) {
        LOG_PRINTF("Handling handshake packet of length %d\n", payload_length);
        TRACING_SET(TR_NOISE_HANDSHAKE);
        if (try_continue_noise_handshake(&noise_state, pkt->payload, payload_length)) {
            TRACING_CLEAR(TR_NOISE_HANDSHAKE);
            LOG_PRINTF("Reporting handshake error to host\n");
            struct control_packet out = { .type=HOST_CRYPTO_ERROR };
            send_packet(usart2_out, (uint8_t *)&out, sizeof(out));
        } else TRACING_CLEAR(TR_NOISE_HANDSHAKE);

    } else {
        LOG_PRINTF("Unhandled packet of type %d\n", pkt->type);
    }
    TRACING_CLEAR(TR_HOST_PKT_HANDLER);
}


int main(void)
{
	clock_setup();
	gpio_setup();
    pwr_disable_backup_domain_write_protect();
    PWR_CSR |= PWR_CSR_BRE; /* Enable backup SRAM battery power regulator */

    finish_interrupted_scrub();
    disarm_key_scrubber();
	tim6_setup();

#ifdef USART_DEBUG
    usart_dma_init(debug_out);
    /* FIXME start unsafe debug code */
    usart_enable_rx_interrupt(debug_out->usart);
    nvic_enable_irq(NVIC_USART1_IRQ);
    nvic_set_priority(NVIC_USART1_IRQ, 3<<4);
    /* end unsafe debug code */
#endif

    usart_dma_init(usart2_out);
    usart_enable_rx_interrupt(USART2);
    nvic_enable_irq(NVIC_USART2_IRQ);
    nvic_set_priority(NVIC_USART2_IRQ, 3<<4);
    nvic_set_priority(debug_out_s.irqn, 1<<4);

	LOG_PRINTF("\n==================================\n");
	LOG_PRINTF("SecureHID device side initializing\n");
	LOG_PRINTF("==================================\n");

    LOG_PRINTF("Initializing USB...\n");
    const hid_config_t hid_config = { .hid_in_message_handler = &hid_in_message_handler };
	hid_driver_init(&hid_config);
	hub_driver_init();
    const usbh_dev_driver_t *device_drivers[] = { &usbh_hub_driver, &usbh_hid_driver, NULL };
    const usbh_low_level_driver_t * const lld_drivers[] = { &usbh_lld_stm32f4_driver_fs, NULL };
	usbh_init(lld_drivers, device_drivers);

	LOG_PRINTF("Initializing RNG...\n");
    rand_init();

    noise_state_init(&noise_state, keystore.keys.remote_key_reference, keystore.keys.local_key);
    /* FIXME load remote key from backup memory */
    /* FIXME only run this on first boot and persist key in backup sram. Allow reset via jumper-triggered factory reset function. */
    if (!keystore.mgmt.identity_key_valid) {
        LOG_PRINTF("Generating identity key...\n");
        if (generate_identity_key(&noise_state)) {
            LOG_PRINTF("Error generating identiy key\n");
        } else {
            keystore.mgmt.identity_key_valid = 1;
        }
    }

    int poll_ctr = 0;
    int led_ctr = 0;
    int led_idx = 0;
    int spk_ctr = 0;
    int spk_ctr2 = 0;
    int spk_adv = 0;
    int spk_inc = 1;
    gpio_clear(GPIOA, GPIO6);
    gpio_clear(GPIOA, GPIO7);
    gpio_clear(GPIOB, GPIO10);
	while (23) {
        delay(1);

        led_ctr++;
        if (led_ctr == 10) {
            gpio_clear(GPIOA, GPIO6);
            gpio_clear(GPIOA, GPIO7);
        } else if (led_ctr == 300) {
            gpio_mode_setup(GPIOE, GPIO_MODE_INPUT, GPIO_PUPD_NONE, 0xfff0);
        } else if (led_ctr == 400) {
            if (++led_idx == 12)
                led_idx = 0;
            gpio_mode_setup(GPIOE, GPIO_MODE_OUTPUT, GPIO_PUPD_NONE, 1<<(4+led_idx));
            gpio_clear(GPIOE, 0xfff0);
            if (led_idx & 1)
                gpio_set(GPIOA, GPIO6);
            else
                gpio_set(GPIOA, GPIO7);
            led_ctr = 0;
        }

        spk_ctr++;
        spk_ctr2++;
        if (spk_ctr2 == 100) {
            spk_adv += spk_inc;
            if (spk_adv > 31)
                spk_inc = -3;
            if (spk_adv < 1)
                spk_inc = 1;
            spk_ctr2 = 0;
        }
        if (spk_ctr%spk_adv == 0) {
            gpio_set(GPIOB, GPIO10);
        } else {
            gpio_clear(GPIOB, GPIO10);
        }
        continue;

        if (++poll_ctr == 10) {
            poll_ctr = 0;
            TRACING_SET(TR_USBH_POLL);
            usbh_poll(tim6_get_time_us());
            TRACING_CLEAR(TR_USBH_POLL);
        }

        if (host_packet_length > 0) {
            handle_host_packet((struct control_packet *)host_packet_buf, host_packet_length - 1);
            host_packet_length = 0; /* Acknowledge to USART ISR the buffer has been handled */

        } else if (host_packet_length < 0) { /* USART error */
            host_packet_length = 0; /* Acknowledge to USART ISR the error has been handled */
            if (noise_state.handshake_state < HANDSHAKE_DONE_UNKNOWN_HOST) {
                LOG_PRINTF("USART error, aborting handshake\n")

                struct control_packet pkt = { .type=HOST_COMM_ERROR };
                send_packet(usart2_out, (uint8_t *)&pkt, sizeof(pkt));

                if (reset_protocol_handshake(&noise_state))
                    LOG_PRINTF("Error starting protocol handshake.\n");

                pairing_buf_pos = 0; /* Reset channel binding keyboard input buffer */
            }
        }

        if (noise_state.handshake_state == HANDSHAKE_IN_PROGRESS) {
            TRACING_SET(TR_NOISE_HANDSHAKE);
            if (try_continue_noise_handshake(&noise_state, NULL, 0)) { /* handle outgoing messages */
                TRACING_CLEAR(TR_NOISE_HANDSHAKE);
                LOG_PRINTF("Reporting handshake error to host\n");
                struct control_packet pkt = { .type=HOST_CRYPTO_ERROR };
                send_packet(usart2_out, (uint8_t *)&pkt, sizeof(pkt));
            } else TRACING_CLEAR(TR_NOISE_HANDSHAKE);
        }
	}
}

void _fini() {
    while (1);
}

