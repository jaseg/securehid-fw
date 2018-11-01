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

 // STM32f407 compatible
#include <libopencm3/stm32/rcc.h>
#include <libopencm3/stm32/gpio.h>
#include <libopencm3/stm32/usart.h>
#include <libopencm3/stm32/timer.h>
#include <libopencm3/stm32/otg_hs.h>
#include <libopencm3/stm32/otg_fs.h>

#include <stdint.h>
#include <string.h>
#include <stdlib.h>


static inline void delay_ms_busy_loop(uint32_t ms)
{
	volatile uint32_t i;
	for (i = 0; i < 14903*ms; i++);
}


/* Set STM32 to 168 MHz. */
static void clock_setup(void)
{
	rcc_clock_setup_hse_3v3(&hse_8mhz_3v3[CLOCK_3V3_168MHZ]);

	// GPIO
	rcc_periph_clock_enable(RCC_GPIOA); // USART + OTG_FS + button
	rcc_periph_clock_enable(RCC_GPIOB); // OTG_HS
	rcc_periph_clock_enable(RCC_GPIOC); // OTG_FS charge pump
	rcc_periph_clock_enable(RCC_GPIOD); // LEDS

	// periphery
	rcc_periph_clock_enable(RCC_USART1); // USART
	rcc_periph_clock_enable(RCC_OTGFS); // OTG_FS
	rcc_periph_clock_enable(RCC_OTGHS); // OTG_HS
	rcc_periph_clock_enable(RCC_TIM6); // TIM6
}


/*
 * setup 10kHz timer
 */
static void tim6_setup(void)
{
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
	/* Set GPIO12-15 (in GPIO port D) to 'output push-pull'. */
	gpio_mode_setup(GPIOD, GPIO_MODE_OUTPUT,
			GPIO_PUPD_NONE, GPIO12 | GPIO13 | GPIO14 | GPIO15);

	/* Set	 */
	gpio_mode_setup(GPIOC, GPIO_MODE_OUTPUT, GPIO_PUPD_NONE, GPIO0);
	gpio_clear(GPIOC, GPIO0);

	// OTG_FS
	gpio_mode_setup(GPIOA, GPIO_MODE_AF, GPIO_PUPD_NONE, GPIO11 | GPIO12);
	gpio_set_af(GPIOA, GPIO_AF10, GPIO11 | GPIO12);

	// OTG_HS
	gpio_mode_setup(GPIOB, GPIO_MODE_AF, GPIO_PUPD_NONE, GPIO15 | GPIO14);
	gpio_set_af(GPIOB, GPIO_AF12, GPIO14 | GPIO15);

	// USART
	gpio_mode_setup(GPIOA, GPIO_MODE_AF, GPIO_PUPD_NONE, GPIO9 | GPIO10);
	gpio_set_af(GPIOA, GPIO_AF7, GPIO9 | GPIO10);

	// button
	gpio_mode_setup(GPIOA, GPIO_MODE_INPUT, GPIO_PUPD_NONE, GPIO0);
}

static const usbh_dev_driver_t *device_drivers[] = {
	&usbh_hub_driver,
	&usbh_hid_driver,
	NULL
};

static const usbh_low_level_driver_t * const lld_drivers[] = {
#ifdef USE_STM32F4_USBH_DRIVER_FS
	&usbh_lld_stm32f4_driver_fs, // Make sure USE_STM32F4_USBH_DRIVER_FS is defined in usbh_config.h
#endif

#ifdef USE_STM32F4_USBH_DRIVER_HS
	&usbh_lld_stm32f4_driver_hs, // Make sure USE_STM32F4_USBH_DRIVER_HS is defined in usbh_config.h
#endif
	NULL
	};

static void hid_in_message_handler(uint8_t device_id, const uint8_t *data, uint32_t length)
{
	(void)device_id;
	(void)data;
	if (length < 4) {
		LOG_PRINTF("data too short, type=%d\n", hid_get_type(device_id));
		return;
	}

	// print only first 4 bytes, since every mouse should have at least these four set.
	// Report descriptors are not read by driver for now, so we do not know what each byte means
	LOG_PRINTF("HID EVENT %02X %02X %02X %02X \n", data[0], data[1], data[2], data[3]);
    /*
	if (hid_get_type(device_id) == HID_TYPE_KEYBOARD) {
		static int x = 0;
		if (x != data[2]) {
			x = data[2];
			hid_set_report(device_id, x);
		}
	}
    */
}

static const hid_config_t hid_config = {
	.hid_in_message_handler = &hid_in_message_handler
};

int main(void)
{
	clock_setup();
	gpio_setup();

	// provides time_curr_us to usbh_poll function
	tim6_setup();

#ifdef USART_DEBUG
    //USART_BRR(USART1) = rcc_apb2_frequency / (16 * 1000000);
	usart_init(USART1, 1000000);
#endif
	LOG_PRINTF("\n\n\n\n\n###################\nInit\n");

	/**
	 * device driver initialization
	 *
	 * Pass configuration struct where the callbacks are defined
	 */
	hid_driver_init(&hid_config);
	hub_driver_init();

	gpio_set(GPIOD,  GPIO13);
	/**
	 * Pass array of supported low level drivers
	 * In case of stm32f407, there are up to two supported OTG hosts on one chip.
	 * Each one can be enabled or disabled in usbh_config.h - optimization for speed
	 *
	 * Pass array of supported device drivers
	 */
	usbh_init(lld_drivers, device_drivers);
	gpio_clear(GPIOD,  GPIO13);

	LOG_PRINTF("USB init complete\n");

	LOG_FLUSH();

	while (1) {
		// set busy led
		gpio_set(GPIOD,  GPIO14);

		uint32_t time_curr_us = tim6_get_time_us();

		usbh_poll(time_curr_us);

		// clear busy led
		gpio_clear(GPIOD,  GPIO14);

		LOG_FLUSH();

		// approx 1ms interval between usbh_poll()
		delay_ms_busy_loop(1);
	}

	return 0;
}
