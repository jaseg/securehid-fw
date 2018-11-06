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

#ifndef USBH_USART_HELPERS_H
#define USBH_USART_HELPERS_H

#include "usbh_core.h"
#include <stdint.h>
#include <stdarg.h>
#include <errno.h>

BEGIN_DECLS

struct dma_buf {
    uint32_t xfr_start; /* Start index of running DMA transfer */
    uint32_t xfr_end; /* End index of running DMA transfer plus one */
    uint32_t wr_pos; /* Next index to be written */
    uint32_t len;
    uint8_t data[0];
};

struct dma_usart_file {
    uint32_t usart;
    uint32_t baudrate;
    uint32_t dma;
    uint8_t stream;
    uint8_t channel;
    uint8_t irqn;
    volatile struct dma_buf *buf;
};


extern struct dma_usart_file *debug_out;


void usart_init(uint32_t usart, uint32_t baudrate);
void usart_fprintf(struct dma_usart_file *f, const char *str, ...);
void usart_fifo_push(uint8_t c);

void usart_dma_init(struct dma_usart_file *f);
void usart_kickoff_dma(uint32_t dma, uint8_t stream, volatile uint8_t *buf, size_t len);
void schedule_dma(volatile struct dma_usart_file *f);
int dma_fifo_push(volatile struct dma_buf *buf, char c);
int putf(void *file, char c);
int putb(void *file, const uint8_t *buf, size_t len);
void flush(void *file);
void send_packet(struct dma_usart_file *f, const uint8_t *data, size_t len);

/* This macro abomination templates a bunch of dma-specific register/constant names from preprocessor macros passed in
 * from cmake. */
#define DMA_PASTE(num) DMA ## num
#define DMA(num) DMA_PASTE(num)

#define NVIC_DMA_IRQ_PASTE(dma, stream) NVIC_ ## DMA ## dma ## _ ## STREAM ## stream ## _IRQ
#define NVIC_DMA_IRQ(dma, stream) NVIC_DMA_IRQ_PASTE(dma, stream)

#define DMA_ISR_PASTE(dma, stream) DMA ## dma ## _ ## STREAM ## stream ## _IRQHandler
#define DMA_ISR(dma, stream) DMA_ISR_PASTE(dma, stream)

#ifdef USART_DEBUG
#define LOG_PRINTF(format, ...) usart_fprintf(debug_out, format, ##__VA_ARGS__);
#else
#define LOG_PRINTF(dummy, ...) ((void)dummy)
#endif

#define UNUSED(var) ((void)var)

END_DECLS

#endif
