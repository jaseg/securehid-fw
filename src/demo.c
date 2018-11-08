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

#include "usart_helpers.h"			/// provides LOG_PRINTF macros used for debugging
#include "usbh_core.h"				/// provides usbh_init() and usbh_poll()
#include "usbh_lld_stm32f4.h"		/// provides low level usb host driver for stm32f4 platform
#include "usbh_driver_hid.h"		/// provides generic usb device driver for Human Interface Device (HID)
#include "usbh_driver_hub.h"		/// provides usb full speed hub driver (Low speed devices on hub are not supported)
#include "cobs.h"
#include "rand_stm32.h"

 // STM32f407 compatible
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
#include <string.h>
#include <stdlib.h>

#include <noise/protocol.h>

void _fini(void);
int generate_identity_key(void);

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

static const usbh_dev_driver_t *device_drivers[] = {
	&usbh_hub_driver,
	&usbh_hid_driver,
	NULL
};

static const usbh_low_level_driver_t * const lld_drivers[] = {
	&usbh_lld_stm32f4_driver_fs, // Make sure USE_STM32F4_USBH_DRIVER_FS is defined in usbh_config.h
	NULL
};

static void hid_in_message_handler(uint8_t device_id, const uint8_t *data, uint32_t length)
{
	UNUSED(device_id);
	UNUSED(data);
	if (length < 4) {
		LOG_PRINTF("data too short, type=%d\n", hid_get_type(device_id));
		return;
	}

	// print only first 4 bytes, since every mouse should have at least these four set.
	// Report descriptors are not read by driver for now, so we do not know what each byte means
	LOG_PRINTF("HID EVENT %02X %02X %02X %02X \n", data[0], data[1], data[2], data[3]);
    /*
	if (hid_get_type(device_id) == HID_TYPE_KEYBOARD) {
	}
    */
}

static const hid_config_t hid_config = {
	.hid_in_message_handler = &hid_in_message_handler
};

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


volatile struct {
    struct dma_buf dma;
    uint8_t data[128];
} usart2_buf = { .dma = { .len = sizeof(usart2_buf.data) } };

struct dma_usart_file usart2_out_s = {
    .usart = USART2,
    .baudrate = 1000000,
    .dma = DMA1,
    .stream = 6,
    .channel = 4,
    .irqn = NVIC_DMA_IRQ(1, 6),
    .buf = &usart2_buf.dma
};
struct dma_usart_file *usart2_out = &usart2_out_s;

void dma1_stream6_isr(void) {
	dma_clear_interrupt_flags(usart2_out->dma, usart2_out->stream, DMA_TCIF);

    if (usart2_out->buf->wr_pos != usart2_out->buf->xfr_end) /* buffer not empty */
        schedule_dma(usart2_out);
}

static struct cobs_decode_state host_cobs_state;
#define CURVE25519_KEY_LEN 32
#define MAX_HOST_PACKET_SIZE 256
static volatile uint8_t host_packet_buf[MAX_HOST_PACKET_SIZE];
static volatile uint8_t host_packet_length = 0;

void usart2_isr(void) {
    if (USART2_SR & USART_SR_ORE) { /* Overrun handling */
        LOG_PRINTF("USART2 data register overrun\n");
        /* Clear interrupt flag */
        (void)USART2_DR; /* FIXME make sure this read is not optimized out */
        return;
    }

    uint8_t data = USART2_DR; /* This automatically acknowledges the IRQ */

    if (host_packet_length) {
        LOG_PRINTF("USART2 COBS buffer overrun\n");
        return;
    }

    ssize_t rv = cobs_decode_incremental(&host_cobs_state, (char *)host_packet_buf, sizeof(host_packet_buf), data);
    if (rv == -2) {
        LOG_PRINTF("Host interface COBS packet too large\n");
    } else if (rv < 0) {
        LOG_PRINTF("Host interface COBS framing error\n");
    } else if (rv > 0) {
        host_packet_length = rv;
    } /* else just return and wait for next byte */
}

static uint8_t local_key[CURVE25519_KEY_LEN];
NoiseCipherState *tx_cipher, *rx_cipher;

#define HANDLE_NOISE_ERROR(x, msg) do { \
        err = x; \
        if (err != NOISE_ERROR_NONE) { \
            char errbuf[256]; \
            noise_strerror(err, errbuf, sizeof(errbuf)); \
            LOG_PRINTF("Error " msg ": %s\n", errbuf); \
            goto errout; \
        } \
    } while(0);

static NoiseHandshakeState *start_protocol_handshake(void) {
    /* TODO Noise-C is nice for prototyping, but we should really get rid of it for mostly two reasons:
     *   * We don't need cipher/protocol agility, and by baking the final protocol into the firmware we can save a lot
     *     of flash space by not including all the primitives we don't need as well as noise's dynamic protocol
     *     abstraction layer.
     *   * Noise-c is not very embedded-friendly, in particular it uses malloc and free. We should be able to run
     *     everything with statically allocated buffers instead.
     */
    NoiseHandshakeState *handshake;
    int err;
    
    HANDLE_NOISE_ERROR(noise_init(), "initializing noise");

    HANDLE_NOISE_ERROR(noise_handshakestate_new_by_name(&handshake, "Noise_XX_25519_ChaChaPoly_BLAKE2s", NOISE_ROLE_RESPONDER), "instantiating handshake pattern");

    NoiseDHState *dh = noise_handshakestate_get_local_keypair_dh(handshake);
    HANDLE_NOISE_ERROR(noise_dhstate_set_keypair_private(dh, local_key, sizeof(local_key)), "loading local private keys");

    HANDLE_NOISE_ERROR(noise_handshakestate_start(handshake), "starting handshake");

    return handshake;

errout:
    noise_handshakestate_free(handshake);
    return 0;
}

int generate_identity_key(void) {
    NoiseDHState *dh;
    int err;

    HANDLE_NOISE_ERROR(noise_dhstate_new_by_name(&dh, "25519"), "creating dhstate for key generation"); 
    HANDLE_NOISE_ERROR(noise_dhstate_generate_keypair(dh), "generating key pair");

    uint8_t unused[CURVE25519_KEY_LEN]; /* the noise api is a bit bad here. */
    memset(local_key, 0, sizeof(local_key));

    HANDLE_NOISE_ERROR(noise_dhstate_get_keypair(dh, local_key, sizeof(local_key), unused, sizeof(unused)), "saving key pair");

    return 0;

errout:
    if (dh)
        noise_dhstate_free(dh);
    return -1;
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
    cobs_decode_incremental_initialize(&host_cobs_state);
    usart_enable_rx_interrupt(USART2);
    nvic_enable_irq(NVIC_USART2_IRQ);

	LOG_PRINTF("\n==================================\n");
	LOG_PRINTF("SecureHID device side initializing\n");
	LOG_PRINTF("==================================\n");

    LOG_PRINTF("Initializing USB...\n");
	hid_driver_init(&hid_config);
	hub_driver_init();

	/**
	 * Pass array of supported low level drivers
	 * In case of stm32f407, there are up to two supported OTG hosts on one chip.
	 * Each one can be enabled or disabled in usbh_config.h - optimization for speed
	 *
	 * Pass array of supported device drivers
	 */
	usbh_init(lld_drivers, device_drivers);

	LOG_PRINTF("Initializing RNG...\n");
    rand_init();

    /* FIXME only run this on first boot and persist key in backup sram. Allow reset via jumper-triggered factory reset function. */
    LOG_PRINTF("Generating identity key...\n");
    if (generate_identity_key())
        LOG_PRINTF("Error generating identiy key\n");

    LOG_PRINTF("Starting noise protocol handshake...\n");
    NoiseHandshakeState *handshake = start_protocol_handshake();
    if (!handshake)
        LOG_PRINTF("Error starting protocol handshake.\n");

    int i = 0, j = 0;
	while (23) {
		usbh_poll(tim6_get_time_us());
		delay_ms_busy_loop(1); /* approx 1ms interval between usbh_poll() */
        if (i++ == 1000) {
            i = 0;
            LOG_PRINTF("Loop iteration %d\n", 1000*(j++));
        }

        if (handshake) {
#define MAX_MESSAGE_LEN 256
            uint8_t message[MAX_MESSAGE_LEN];
            NoiseBuffer noise_msg;
            /* Run the protocol handshake */
            switch (noise_handshakestate_get_action(handshake)) {
            case NOISE_ACTION_WRITE_MESSAGE:
                /* Write the next handshake message with a zero-length payload */
                noise_buffer_set_output(noise_msg, message, sizeof(message));
                if (noise_handshakestate_write_message(handshake, &noise_msg, NULL) != NOISE_ERROR_NONE) {
                    LOG_PRINTF("Error writing handshake message\n");
                    noise_handshakestate_free(handshake);
                    handshake = NULL;
                }
                send_packet(usart2_out, message, noise_msg.size);
                break;

            case NOISE_ACTION_READ_MESSAGE:
                if (host_packet_length > 0) {
                    /* Read the next handshake message and discard the payload */
                    noise_buffer_set_input(noise_msg, (uint8_t *)host_packet_buf, host_packet_length);
                    if (noise_handshakestate_read_message(handshake, &noise_msg, NULL) != NOISE_ERROR_NONE) {
                        LOG_PRINTF("Error reading handshake message\n");
                        noise_handshakestate_free(handshake);
                        handshake = NULL;
                    }
                }
                break;

            case NOISE_ACTION_SPLIT:
                if (noise_handshakestate_split(handshake, &tx_cipher, &rx_cipher) != NOISE_ERROR_NONE) {
                    LOG_PRINTF("Error splitting handshake state\n");
                } else {
                    LOG_PRINTF("Noise protocol handshake completed successfully\n");
                }

                noise_handshakestate_free(handshake);
                handshake = NULL;
                break;

            default:
                LOG_PRINTF("Noise protocol handshake failed\n");
                noise_handshakestate_free(handshake);
                handshake = 0;
                break;
            }
        }
	}
	return 0;
}

void _fini() {
    while (1);
}

