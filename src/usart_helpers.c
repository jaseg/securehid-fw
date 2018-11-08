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
#include "cobs.h"

#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <libopencm3/stm32/usart.h>
#include <libopencm3/stm32/dma.h>
#include <libopencm3/cm3/nvic.h>
#include <libopencmsis/core_cm3.h>


void usart_fprintf(struct dma_usart_file *f, const char *str, ...) {
	va_list va;
	va_start(va, str);
	tfp_format(f, (void (*)(void *, char c))putf, str, va);
	va_end(va);
    flush(f);
}

void usart_init(uint32_t arg_usart, uint32_t baudrate) {
	usart_set_baudrate(arg_usart, baudrate);
	usart_set_databits(arg_usart, 8);
	usart_set_flow_control(arg_usart, USART_FLOWCONTROL_NONE);
	usart_set_mode(arg_usart, USART_MODE_TX | USART_MODE_RX);
	usart_set_parity(arg_usart, USART_PARITY_NONE);
	usart_set_stopbits(arg_usart, USART_STOPBITS_1);
	usart_enable(arg_usart);
}

void usart_dma_init(struct dma_usart_file *f) {
    usart_init(f->usart, f->baudrate);

    f->buf->xfr_start = -1,
    f->buf->xfr_end = 0,
    f->buf->wr_pos = 0,

    dma_stream_reset(f->dma, f->stream);
    dma_channel_select(f->dma, f->stream, DMA_SxCR_CHSEL(f->channel));
	dma_set_peripheral_address(f->dma, f->stream, (uint32_t)&USART_DR(f->usart));
	dma_set_transfer_mode(f->dma, f->stream, DMA_SxCR_DIR_MEM_TO_PERIPHERAL);
	dma_enable_memory_increment_mode(f->dma, f->stream);
	dma_set_peripheral_size(f->dma, f->stream, DMA_SxCR_PSIZE_8BIT);
	dma_set_memory_size(f->dma, f->stream, DMA_SxCR_MSIZE_8BIT);
	dma_set_priority(f->dma, f->stream, DMA_SxCR_PL_VERY_HIGH);
	dma_enable_transfer_complete_interrupt(f->dma, f->stream);
    usart_enable_tx_dma(f->usart);
}

void usart_kickoff_dma(uint32_t dma, uint8_t stream, volatile uint8_t *buf, size_t len) {
    /* initiate transmission of new buffer */
	dma_set_memory_address(dma, stream, (uint32_t)buf); /* select active buffer address */
	dma_set_number_of_data(dma, stream, len);
	dma_enable_stream(dma, stream);
}

void schedule_dma(volatile struct dma_usart_file *f) {
    volatile struct dma_buf *buf = f->buf;

    uint32_t xfr_len, xfr_start = buf->xfr_end;
    if (buf->wr_pos > xfr_start) /* no wraparound */
        xfr_len = buf->wr_pos - xfr_start;
    else /* wraparound */
        xfr_len = buf->len - xfr_start; /* schedule transfer until end of buffer */

    buf->xfr_start = xfr_start;
    buf->xfr_end = (xfr_start + xfr_len) % buf->len; /* handle wraparound */
    usart_kickoff_dma(f->dma, f->stream, buf->data + xfr_start, xfr_len);
}

int dma_fifo_push(volatile struct dma_buf *buf, char c) {
    if (buf->wr_pos == buf->xfr_start)
        return -EBUSY;

    buf->data[buf->wr_pos] = c;
    buf->wr_pos = (buf->wr_pos + 1) % buf->len;
    return 0;
}

int putf(void *file, char c) {
    volatile struct dma_usart_file *f = (struct dma_usart_file *)file;

    nvic_disable_irq(f->irqn);
    /* push char to fifo, busy-loop if stalled to wait for USART to empty fifo via DMA */
    while (dma_fifo_push(f->buf, c) == -EBUSY) {
        nvic_enable_irq(f->irqn);
        nvic_disable_irq(f->irqn);
    }
    nvic_enable_irq(f->irqn);
    return 0;
}

int putb(void *file, const uint8_t *buf, size_t len) {
    volatile struct dma_usart_file *f = (struct dma_usart_file *)file;

    nvic_disable_irq(f->irqn);
    for (size_t i=0; i<len; i++) {
        /* push char to fifo, busy-loop if stalled to wait for USART to empty fifo via DMA */
        while (dma_fifo_push(f->buf, buf[i]) == -EBUSY) {
            nvic_enable_irq(f->irqn);
            nvic_disable_irq(f->irqn);
        }
    }
    nvic_enable_irq(f->irqn);
    return 0;
}

void flush(void *file) {
    volatile struct dma_usart_file *f = (struct dma_usart_file *)file;

    nvic_disable_irq(f->irqn);
    /* If the DMA stream is idle right now, schedule a transfer */
    if (!(DMA_SCR(f->dma, f->stream) & DMA_SxCR_EN) /* DMA is not running */
            && !dma_get_interrupt_flag(f->dma, f->stream, DMA_TCIF)/* DMA interrupt is clear */) {
        schedule_dma(f);
    }
    nvic_enable_irq(f->irqn);
}

