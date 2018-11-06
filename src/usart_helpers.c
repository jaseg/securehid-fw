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
#include <libopencm3/stm32/dma.h>
#include <libopencm3/cm3/nvic.h>
#include <libopencmsis/core_cm3.h>

static void putf(void *file, char c) {
    UNUSED(file);
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
    uint8_t buf[WRITE_BUF_LEN];
    uint32_t pos;
} tx_buf[2];
int tx_buf_active;

/* This macro abomination templates a bunch of dma-specific register/constant names from preprocessor macros passed in
 * from cmake. */
#define DEBUG_USART_DMA_PASTE(num) DMA ## num
#define DEBUG_USART_DMA_EVAL(num) DEBUG_USART_DMA_PASTE(num)
#define DEBUG_USART_DMA DEBUG_USART_DMA_EVAL(DEBUG_USART_DMA_NUM)

#define DEBUG_USART_DMA_STREAM_PASTE(num) DMA_STREAM ## num
#define DEBUG_USART_DMA_STREAM_EVAL(num) DEBUG_USART_DMA_STREAM_PASTE(num)
#define DEBUG_USART_DMA_STREAM DEBUG_USART_DMA_STREAM_EVAL(DEBUG_USART_DMA_STREAM_NUM)

#define DEBUG_USART_NVIC_DMA_IRQ_PASTE(dma, stream) NVIC_ ## DMA ## dma ## _ ## STREAM ## stream ## _IRQ
#define DEBUG_USART_NVIC_DMA_IRQ_EVAL(dma, stream) DEBUG_USART_NVIC_DMA_IRQ_PASTE(dma, stream)
#define DEBUG_USART_NVIC_DMA_IRQ DEBUG_USART_NVIC_DMA_IRQ_EVAL(DEBUG_USART_DMA_NUM, DEBUG_USART_DMA_STREAM_NUM)

#define DEBUG_USART_DMA_ISR_PASTE(dma, stream) DMA ## dma ## _ ## STREAM ## stream ## _IRQHandler
#define DEBUG_USART_DMA_ISR_EVAL(dma, stream) DEBUG_USART_DMA_ISR_PASTE(dma, stream)
#define DEBUG_USART_DMA_ISR DEBUG_USART_DMA_ISR_EVAL(DEBUG_USART_DMA_NUM, DEBUG_USART_DMA_STREAM_NUM)

#define DEBUG_USART_DMA_CHANNEL_PASTE(channel) DMA_SxCR_CHSEL_ ## channel
#define DEBUG_USART_DMA_CHANNEL_EVAL(channel) DEBUG_USART_DMA_CHANNEL_PASTE(channel)
#define DEBUG_USART_DMA_CHANNEL DEBUG_USART_DMA_CHANNEL_EVAL(DEBUG_USART_DMA_CHANNEL_NUM)

void debug_usart_init() {
    tx_buf[0].pos = tx_buf[1].pos = 0;
    tx_buf_active = 1;

    usart_init(DEBUG_USART, DEBUG_USART_BAUDRATE);

    dma_stream_reset(DEBUG_USART_DMA, DEBUG_USART_DMA_STREAM);
    dma_channel_select(DEBUG_USART_DMA, DEBUG_USART_DMA_STREAM, DEBUG_USART_DMA_CHANNEL);
	dma_set_peripheral_address(DEBUG_USART_DMA, DEBUG_USART_DMA_STREAM, (uint32_t)&USART_DR(DEBUG_USART));
	dma_set_transfer_mode(DEBUG_USART_DMA, DEBUG_USART_DMA_STREAM, DMA_SxCR_DIR_MEM_TO_PERIPHERAL);
	dma_enable_memory_increment_mode(DEBUG_USART_DMA, DEBUG_USART_DMA_STREAM);
	dma_set_peripheral_size(DEBUG_USART_DMA, DEBUG_USART_DMA_STREAM, DMA_SxCR_PSIZE_8BIT);
	dma_set_memory_size(DEBUG_USART_DMA, DEBUG_USART_DMA_STREAM, DMA_SxCR_MSIZE_8BIT);
	dma_set_priority(DEBUG_USART_DMA, DEBUG_USART_DMA_STREAM, DMA_SxCR_PL_VERY_HIGH);
	dma_enable_transfer_complete_interrupt(DEBUG_USART_DMA, DEBUG_USART_DMA_STREAM);
    usart_enable_tx_dma(DEBUG_USART);
}

static void usart_kickoff_dma(void) {
    tx_buf[tx_buf_active].pos = 0; /* clear old buffer */
    tx_buf_active = !tx_buf_active; /* swap buffers */
    /* initiate transmission of new buffer */
	dma_set_memory_address(DEBUG_USART_DMA, DEBUG_USART_DMA_STREAM, (uint32_t)&tx_buf[tx_buf_active].buf); /* select active buffer address */
	dma_set_number_of_data(DEBUG_USART_DMA, DEBUG_USART_DMA_STREAM, tx_buf[tx_buf_active].pos);
	dma_enable_stream(DEBUG_USART_DMA, DEBUG_USART_DMA_STREAM);
}

void DEBUG_USART_DMA_ISR(void) {
	dma_clear_interrupt_flags(DEBUG_USART_DMA, DEBUG_USART_DMA_STREAM, DMA_TCIF);

    struct tx_buf *buf = &tx_buf[!tx_buf_active]; /* select inactive buffer */
    if (buf->pos != 0) {
        usart_kickoff_dma();
    }
}

void usart_fifo_push(uint8_t c) {
    nvic_disable_irq(DEBUG_USART_NVIC_DMA_IRQ);
    struct tx_buf *buf = &tx_buf[!tx_buf_active]; /* select inactive buffer */
    buf->buf[buf->pos++] = c;
    if (!(DMA_SCR(DEBUG_USART_DMA, DEBUG_USART_DMA_STREAM) & DMA_SxCR_EN) /* DMA is not running */
            && !dma_get_interrupt_flag(DEBUG_USART_DMA, DEBUG_USART_DMA_STREAM, DMA_TCIF)/* DMA interrupt is clear */) {
        usart_kickoff_dma();
    }
    nvic_enable_irq(DEBUG_USART_NVIC_DMA_IRQ);
}

