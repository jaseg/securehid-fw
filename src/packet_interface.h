#ifndef __PACKET_INTERFACE_H__
#define __PACKET_INTERFACE_H__

#include "usart_helpers.h"


extern struct dma_usart_file *usart2_out;

enum control_packet_types {
    _HOST_RESERVED = 0,
    HOST_INITIATE_HANDSHAKE = 1,
    HOST_HANDSHAKE = 2,
    HOST_DATA = 3,
};

enum packet_types {
    _PACKET_RESERVED = 0,
    HID_KEYBOARD_REPORT = 1,
    HID_MOUSE_REPORT = 2,
    PAIRING = 3,
};

struct hid_report_packet {
    uint8_t type;
    uint8_t len;
    uint8_t report[8];
} __attribute__((__packed__));

struct control_packet {
    uint8_t type;
    uint8_t payload[0];
} __attribute__((__packed__));


void send_packet(struct dma_usart_file *f, const uint8_t *data, size_t len);

#endif
