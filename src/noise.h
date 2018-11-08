#ifndef __NOISE_H__
#define __NOISE_H__

#include <stdint.h>

#include <noise/protocol.h>

#include "usart_helpers.h"
#include "rand_stm32.h"


#define CURVE25519_KEY_LEN 32
#define MAX_HOST_PACKET_SIZE 128


extern volatile uint8_t host_packet_buf[MAX_HOST_PACKET_SIZE];
extern volatile uint8_t host_packet_length;


NoiseHandshakeState *start_protocol_handshake(void);
int generate_identity_key(void);
NoiseHandshakeState *try_continue_noise_handshake(NoiseHandshakeState *handshake);

#endif
