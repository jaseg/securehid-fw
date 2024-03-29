
#include "packet_interface.h"
#include "noise.h"
#include "cobs.h"
#include "tracing.h"

#include <libopencm3/stm32/usart.h>
#include <libopencm3/stm32/dma.h>
#include <libopencm3/cm3/nvic.h>
#include <libopencmsis/core_cm3.h>

volatile struct {
    struct dma_buf dma;
    uint8_t data[256];
} usart2_buf = { .dma = { .len = sizeof(usart2_buf.data) } };

struct dma_usart_file usart2_out_s = {
    .usart = USART2,
    .baudrate = 115200,
    .dma = DMA1,
    .stream = 6,
    .channel = 4,
    .irqn = NVIC_DMA_IRQ(1, 6),
    .buf = &usart2_buf.dma
};
struct dma_usart_file *usart2_out = &usart2_out_s;

void dma1_stream6_isr(void) {
    TRACING_SET(TR_HOST_IF_DMA_IRQ);
    static unsigned int fifo_errors = 0; /* debug */
    if (dma_get_interrupt_flag(usart2_out->dma, usart2_out->stream, DMA_FEIF)) {
        /* Ignore FIFO errors as they're 100% non-critical for UART applications */
        dma_clear_interrupt_flags(usart2_out->dma, usart2_out->stream, DMA_FEIF);
        fifo_errors++;
        TRACING_CLEAR(TR_HOST_IF_DMA_IRQ);
        return;
    }

    /* Transfer complete interrupt */
    dma_clear_interrupt_flags(usart2_out->dma, usart2_out->stream, DMA_TCIF);

    if (usart2_out->buf->wr_pos != usart2_out->buf->xfr_end) /* buffer not empty */
        schedule_dma(usart2_out);
    TRACING_CLEAR(TR_HOST_IF_DMA_IRQ);
}

void usart2_isr(void) {
    TRACING_SET(TR_HOST_IF_USART_IRQ);
    static struct cobs_decode_state host_cobs_state = {0};
    if (USART2_SR & USART_SR_ORE) { /* Overrun handling */
        LOG_PRINTF("USART2 data register overrun\n");
        /* Clear interrupt flag */
        (void)USART2_DR; /* FIXME make sure this read is not optimized out */
        host_packet_length = -1;
        TRACING_CLEAR(TR_HOST_IF_USART_IRQ);
        return;
    }

    uint8_t data = USART2_DR; /* This automatically acknowledges the IRQ */

    if (host_packet_length) {
        LOG_PRINTF("USART2 COBS buffer overrun\n");
        host_packet_length = -1;
        TRACING_CLEAR(TR_HOST_IF_USART_IRQ);
        return;
    }

    ssize_t rv = cobs_decode_incremental(&host_cobs_state, (char *)host_packet_buf, sizeof(host_packet_buf), data);
    if (rv == 0) {
        /* good, empty frame */
        LOG_PRINTF("Got empty frame from host\n");
        host_packet_length = -1;
    } else if (rv == -1) {
        /* Decoding frame, wait for next byte */
    } else if (rv == -2) {
        LOG_PRINTF("Host interface COBS framing error\n");
        host_packet_length = -1;
    } else if (rv == -3) {
        /* invalid empty frame */
        LOG_PRINTF("Got double null byte from host\n");
        host_packet_length = -1;
    } else if (rv == -4) {
        /* frame too large */
        LOG_PRINTF("Got too large frame from host\n");
        host_packet_length = -1;
    } else if (rv > 0) {
        /* Good, non-empty frame */
        host_packet_length = rv;
    }
    TRACING_CLEAR(TR_HOST_IF_USART_IRQ);
}

void send_packet(struct dma_usart_file *f, const uint8_t *data, size_t len) {
    /* ignore return value as putf is blocking and always succeeds */
    (void)cobs_encode_incremental(f, putf, (char *)data, len);
    flush(f);
}

