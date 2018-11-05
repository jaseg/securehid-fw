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
#define TINYPRINTF_OVERRIDE_LIBC 0
#define TINYPRINTF_DEFINE_TFP_SPRINTF 0
#include "tinyprintf.h"

#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <libopencm3/stm32/usart.h>

uint32_t debug_usart = 0;

#define USART_FIFO_OUT_SIZE (4096)
uint8_t usart_fifo_out_data[USART_FIFO_OUT_SIZE];
uint32_t usart_fifo_out_len = 0;
uint32_t usart_fifo_out_index = 0;

#define USART_FIFO_IN_SIZE (1024)
uint8_t usart_fifo_in_data[USART_FIFO_IN_SIZE];
uint32_t usart_fifo_in_len = 0;
uint32_t usart_fifo_in_index = 0;

static uint32_t usart = 0;

static uint8_t usart_fifo_pop(void)
{
	uint8_t ret;
	usart_fifo_out_len--;
	ret = usart_fifo_out_data[usart_fifo_out_index];
	usart_fifo_out_index++;
	if (usart_fifo_out_index == USART_FIFO_OUT_SIZE ) {
		usart_fifo_out_index = 0;
	}
	return ret;
}

static void usart_fifo_push(uint8_t aData)
{
	uint32_t i;
	if( (usart_fifo_out_len + 1) == USART_FIFO_OUT_SIZE)//overflow
	{
		usart_fifo_out_len = 0;
		LOG_PRINTF("OVERFLOW!");
		return;
	}

	i = usart_fifo_out_index + usart_fifo_out_len;
	if (i >= USART_FIFO_OUT_SIZE) {
		i -= USART_FIFO_OUT_SIZE;
	}
	usart_fifo_out_data[i] = aData;
	usart_fifo_out_len++;
}


static uint8_t usart_fifo_in_pop(void)
{
	uint8_t ret;
	usart_fifo_in_len--;
	ret = usart_fifo_in_data[usart_fifo_in_index];
	usart_fifo_in_index++;
	if (usart_fifo_in_index == USART_FIFO_IN_SIZE ) {
		usart_fifo_in_index = 0;
	}
	return ret;
}

static void usart_fifo_in_push(uint8_t aData)
{
	uint32_t i;
	if( (usart_fifo_in_len + 1) == USART_FIFO_IN_SIZE)//overflow
	{
		usart_fifo_in_len = 0;
		return;
	}

	i = usart_fifo_in_index + usart_fifo_in_len;
	if (i >= USART_FIFO_IN_SIZE) {
		i -= USART_FIFO_IN_SIZE;
	}
	usart_fifo_in_data[i] = aData;
	usart_fifo_in_len++;
}

static void putf(void *arg, char c)
{
	//unused argument
	(void)arg;

	usart_fifo_push(c);
}

void usart_printf(const char *str, ...)
{
	va_list va;
	va_start(va, str);
	tfp_format(NULL, putf, str, va);
	va_end(va);
}

void usart_init(uint32_t arg_usart, uint32_t baudrate)
{
	usart_set_baudrate(arg_usart, baudrate);
	usart_set_databits(arg_usart, 8);
	usart_set_flow_control(arg_usart, USART_FLOWCONTROL_NONE);
	usart_set_mode(arg_usart, USART_MODE_TX | USART_MODE_RX);
	usart_set_parity(arg_usart, USART_PARITY_NONE);
	usart_set_stopbits(arg_usart, USART_STOPBITS_1);
	usart_enable(arg_usart);
}

#define WRITE_BUF_LEN 256
struct tx_buf {
    buf[WRITE_BUF_LEN];
    int pos;
} tx_buf[2];
int tx_buf_active;

#define DEBUG_USART_DMA_STREAM (DMA_STREAM##DEBUG_USART_DMA_STREAM_NUM)
#define DEBUG_USART_NVIC_DMA_IRQ (NVIC_##DEBUG_USART_DMA##_##DEBUG_USART_DMA_STREAM##_IRQ)
#define DEBUG_USART_DMA_ISR (DEBUG_USART_DMA##_##DEBUG_USART_DMA_STREAM##_IRQHandler)
void debug_usart_init() {
    tx_buf[0].pos = tx_buf[1].pos = 0;
    tx_buf_active = 1;

    usart_init(DEBUG_USART, DEBUG_BAUDRATE);

    dma_stream_reset(DEBUG_USART_DMA, DEBUG_USART_DMA_STREAM);
	dma_set_peripheral_address(DEBUG_USART_DMA, DEBUG_USART_DMA_STREAM, (uint32_t)&DEBUG_USART##_DR);
	dma_set_memory_address(DEBUG_USART_DMA, DEBUG_USART_DMA_STREAM, (uint32_t)tx_buf[1].buf);
	dma_set_number_of_data(DEBUG_USART_DMA, DEBUG_USART_DMA_STREAM, size);
	dma_set_read_from_memory(DEBUG_USART_DMA, DEBUG_USART_DMA_STREAM);
	dma_enable_memory_increment_mode(DEBUG_USART_DMA, DEBUG_USART_DMA_STREAM);
	dma_set_peripheral_size(DEBUG_USART_DMA, DEBUG_USART_DMA_STREAM, DMA_CCR_PSIZE_8BIT);
	dma_set_memory_size(DEBUG_USART_DMA, DEBUG_USART_DMA_STREAM, DMA_CCR_MSIZE_8BIT);
	dma_set_priority(DEBUG_USART_DMA, DEBUG_USART_DMA_STREAM, DMA_CCR_PL_VERY_HIGH);
	dma_enable_transfer_complete_interrupt(DEBUG_USART_DMA, DEBUG_USART_DMA_STREAM);
	dma_enable_channel(DEBUG_USART_DMA, DEBUG_USART_DMA_STREAM);
    usart_enable_tx_dma(DEBUG_USART);
    nvic_enable_irq(DEBUG_USART_NVIC_DMA_IRQ);
}

void DEBUG_USART_DMA_ISR

void usart_fifo_push(uint8_t c) {
    struct tx_buf *buf = &tx_buf[!tx_buf_active]; /* select inactive buffer */
    buf->buf[buf->pos++] = c;
    nvic_disable_irq(DEBUG_USART_NVIC_DMA_IRQ);
    if 
}

