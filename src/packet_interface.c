
#include "packet_interface.h"
#include "noise.h"
#include "cobs.h"

#include <libopencm3/stm32/usart.h>
#include <libopencm3/stm32/dma.h>
#include <libopencm3/cm3/nvic.h>
#include <libopencmsis/core_cm3.h>

volatile struct {
    struct dma_buf dma;
    uint8_t data[128];
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
	dma_clear_interrupt_flags(usart2_out->dma, usart2_out->stream, DMA_TCIF);

    if (usart2_out->buf->wr_pos != usart2_out->buf->xfr_end) /* buffer not empty */
        schedule_dma(usart2_out);
}

void usart2_isr(void) {
    static struct cobs_decode_state host_cobs_state = {0};
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

