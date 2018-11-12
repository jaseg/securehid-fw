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

#include <libopencm3/stm32/rcc.h>
#include <libopencm3/stm32/gpio.h>
#include <libopencm3/stm32/usart.h>
#include <libopencm3/stm32/timer.h>
#include <libopencm3/stm32/otg_hs.h>
#include <libopencm3/stm32/otg_fs.h>
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
#define MAX_FAILED_HANDSHAKES 3
#endif


static struct NoiseState noise_state;
static uint8_t remote_key_reference[CURVE25519_KEY_LEN];


void _fini(void);

static inline void delay_ms_busy_loop(uint32_t ms) {
	for (volatile uint32_t i = 0; i < 14903*ms; i++);
}


/* Set STM32 to 168 MHz. */
static void clock_setup(void) {
	rcc_clock_setup_hse_3v3(&hse_8mhz_3v3[CLOCK_3V3_168MHZ]);

	rcc_periph_clock_enable(RCC_GPIOA);
	rcc_periph_clock_enable(RCC_GPIOE);

	rcc_periph_clock_enable(RCC_USART1);
	rcc_periph_clock_enable(RCC_USART2);
	rcc_periph_clock_enable(RCC_OTGFS);
	rcc_periph_clock_enable(RCC_TIM6);
	rcc_periph_clock_enable(RCC_DMA2);
	rcc_periph_clock_enable(RCC_DMA1);

	rcc_periph_clock_enable(RCC_RNG);
}


/* setup 10kHz timer */
static void tim6_setup(void) {
	timer_reset(TIM6);
	timer_set_prescaler(TIM6, 8400 - 1);	// 84Mhz/10kHz - 1
	timer_set_period(TIM6, 65535);			// Overflow in ~6.5 seconds
	timer_enable_counter(TIM6);
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
    /* D2, D3 LEDs */
	gpio_mode_setup(GPIOA, GPIO_MODE_OUTPUT, GPIO_PUPD_NONE, GPIO6 | GPIO7);
	gpio_set(GPIOA, GPIO6 | GPIO7);

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
	gpio_mode_setup(GPIOE, GPIO_MODE_INPUT, GPIO_PUPD_PULLUP, GPIO3 | GPIO4);
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
        const char *found = strchr(p, ' ');
        size_t plen = found ? (size_t)(found - p) : strlen(p); /* p >= found */

        if (strncasecmp(p, "and", plen)) { /* ignore "and" */
            int num = -1;
            /* FIXME ignore "and", ignore commata and dots */
            for (int i=0; i<256; i++) {
                if ((!strncasecmp(p, adjectives[i], plen)) || (!strncasecmp(p, nouns[i], plen))) {
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

                uint8_t response = REPORT_PAIRING_ERROR;
                if (send_encrypted_message(&noise_state, &response, sizeof(response)))
                    LOG_PRINTF("Error sending pairing response packet\n");
            }
            break;

        case KEY_BACKSPACE:
            if (pairing_buf_pos > 0)
                pairing_buf_pos--;
            pairing_buf[pairing_buf_pos] = '\0'; /* FIXME debug */
            ch = '\b';
            break;

        default:
            for (size_t i=0; keycode_mapping[i].kc != KEY_NONE; i++) {
                if (keycode_mapping[i].kc == keycode) {
                    ch = keycode_mapping[i].ch[level];
                    if (!(('a' <= ch && ch <= 'z') ||
                         ('A' <= ch && ch <= 'Z') ||
                         ('0' <= ch && ch <= '9') ||
                         (ch == ' ') ||
                         (ch == '-')))
                        break; /* ignore special chars */

                    if (pairing_buf_pos < sizeof(pairing_buf)-1) /* allow for terminating null byte */ {
                        pairing_buf[pairing_buf_pos++] = ch;
                        pairing_buf[pairing_buf_pos] = '\0'; /* FIXME debug */
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
        LOG_PRINTF("Input: %s\n", pairing_buf);
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
	if (length < 4 || length > 8) {
		LOG_PRINTF("HID report length must be 4 < len < 8, is %d bytes\n", length);
		return;
	}

	//LOG_PRINTF("Sending event %02X %02X %02X %02X\n", data[0], data[1], data[2], data[3]);
	int type = hid_get_type(device_id);
    if (type != HID_TYPE_KEYBOARD && type != HID_TYPE_MOUSE) {
        LOG_PRINTF("Unsupported HID report type %x\n", type);
        return;
    }

    if (noise_state.handshake_state == HANDSHAKE_DONE_UNKNOWN_HOST) {
        if (type == HID_TYPE_KEYBOARD)
            pairing_parse_report((struct hid_report *)data, length);
        else
            LOG_PRINTF("Not sending HID mouse report during pairing\n");
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
        return;
    }
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

void DMA_ISR(DEBUG_USART_DMA_NUM, DEBUG_USART_DMA_STREAM_NUM)(void) {
	dma_clear_interrupt_flags(debug_out->dma, debug_out->stream, DMA_TCIF);

    if (debug_out->buf->wr_pos != debug_out->buf->xfr_end) /* buffer not empty */
        schedule_dma(debug_out);
}


int main(void)
{
	clock_setup();
	gpio_setup();

	/* provides time_curr_us to usbh_poll function */
	tim6_setup();

#ifdef USART_DEBUG
    usart_dma_init(debug_out);
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

    noise_state_init(&noise_state, remote_key_reference);
    /* FIXME load remote key from backup memory */
    /* FIXME only run this on first boot and persist key in backup sram. Allow reset via jumper-triggered factory reset function. */
    LOG_PRINTF("Generating identity key...\n");
    if (generate_identity_key(&noise_state))
        LOG_PRINTF("Error generating identiy key\n");

	while (23) {
		usbh_poll(tim6_get_time_us());

        if (host_packet_length > 0) {
            struct control_packet *pkt = (struct control_packet *)host_packet_buf;
            size_t payload_length = host_packet_length - 1;

            if (pkt->type == HOST_INITIATE_HANDSHAKE) {
                /* It is important that we acknowledge this command right away. Starting the handshake involves key
                 * generation which takes a few milliseconds. If we'd acknowledge this later, we might run into an
                 * overrun here since we would be blocking the buffer during key generation. */
                host_packet_length = 0; /* Acknowledge to USART ISR the buffer has been handled */

                if (payload_length > 0) {
                    LOG_PRINTF("Extraneous data in INITIATE_HANDSHAKE message\n");
                } else if (noise_state.failed_handshakes < MAX_FAILED_HANDSHAKES) {
                    LOG_PRINTF("Starting noise protocol handshake...\n");
                    if (reset_protocol_handshake(&noise_state))
                        LOG_PRINTF("Error starting protocol handshake.\n");
                    pairing_buf_pos = 0; /* Reset channel binding keyboard input buffer */
                } else {
                    LOG_PRINTF("Too many failed handshake attempts, not starting another one\n");
                }
            } else if (pkt->type == HOST_HANDSHAKE) {
                LOG_PRINTF("Handling handshake packet of length %d\n", payload_length);
                int consumed = 0;
                try_continue_noise_handshake(&noise_state, pkt->payload, payload_length, &consumed);
                if (consumed)
                    host_packet_length = 0; /* Acknowledge to USART ISR the buffer has been handled */
                else /* Otherwise this gets called again in the next iteration of the main loop. Usually that should not happen. */
                    LOG_PRINTF("Handshake buffer unhandled. Waiting for next iteration.\n");

            } else {
                host_packet_length = 0; /* Acknowledge to USART ISR the buffer has been handled */
            }
        }

        if (noise_state.handshake_state == HANDSHAKE_IN_PROGRESS)
            try_continue_noise_handshake(&noise_state, NULL, 0, NULL); /* handle outgoing messages */

		delay_ms_busy_loop(1); /* approx 1ms interval between usbh_poll() */
	}
}

void _fini() {
    while (1);
}

