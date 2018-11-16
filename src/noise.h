#ifndef __NOISE_H__
#define __NOISE_H__

#include <stdint.h>

#include <noise/protocol.h>

#include "usart_helpers.h"
#include "rand_stm32.h"


#define CURVE25519_KEY_LEN 32
#define MAX_HOST_PACKET_SIZE 128


extern volatile uint8_t host_packet_buf[MAX_HOST_PACKET_SIZE];
extern volatile int host_packet_length;

enum handshake_state {
    HANDSHAKE_UNINITIALIZED,
    HANDSHAKE_NOT_STARTED,
    HANDSHAKE_IN_PROGRESS,
    HANDSHAKE_DONE_UNKNOWN_HOST,
    HANDSHAKE_DONE_KNOWN_HOST,
};

extern volatile enum handshake_state handshake_state;

struct NoiseState {
    NoiseHandshakeState *handshake;
    enum handshake_state handshake_state;
    NoiseCipherState *tx_cipher, *rx_cipher;
    uint8_t *local_key;
    uint8_t remote_key[CURVE25519_KEY_LEN];
    uint8_t *remote_key_reference;
    uint8_t handshake_hash[BLAKE2S_HASH_SIZE];
    int failed_handshakes;
};


void uninit_handshake(struct NoiseState *st, enum handshake_state new_state);
void noise_state_init(struct NoiseState *st, uint8_t *remote_key_reference, uint8_t *local_key);
void persist_remote_key(struct NoiseState *st);
int start_protocol_handshake(struct NoiseState *st);
int reset_protocol_handshake(struct NoiseState *st);
int generate_identity_key(struct NoiseState *st);
int try_continue_noise_handshake(struct NoiseState *st, uint8_t *buf, size_t len);
int send_encrypted_message(struct NoiseState *st, uint8_t *msg, size_t len);

void arm_key_scrubber(void);
void disarm_key_scrubber(void);

#endif
