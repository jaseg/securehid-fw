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
    _REPORT_RESERVED = 0,
    REPORT_KEYBOARD= 1,
    REPORT_MOUSE= 2,
    REPORT_PAIRING_INPUT = 3,
    REPORT_PAIRING_SUCCESS = 4,
    REPORT_PAIRING_ERROR = 5,
};

struct hid_report_packet {
    uint8_t type;
    union {
        struct {
            uint8_t len;
            uint8_t report[8];
        } report;
        struct {
            char c;
        } pairing_input;
    };
} __attribute__((__packed__));


struct control_packet {
    uint8_t type;
    uint8_t payload[0];
} __attribute__((__packed__));


void send_packet(struct dma_usart_file *f, const uint8_t *data, size_t len);

#endif
