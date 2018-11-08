#ifndef __PACKET_INTERFACE_H__
#define __PACKET_INTERFACE_H__

#include "usart_helpers.h"

extern struct dma_usart_file *usart2_out;

void send_packet(struct dma_usart_file *f, const uint8_t *data, size_t len);

#endif
