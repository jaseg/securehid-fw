
#include <string.h>

#include "noise.h"
#include "packet_interface.h"


#define HANDLE_NOISE_ERROR(x, msg) do { \
        err = x; \
        if (err != NOISE_ERROR_NONE) { \
            char errbuf[256]; \
            noise_strerror(err, errbuf, sizeof(errbuf)); \
            LOG_PRINTF("Error " msg ": %s\n", errbuf); \
            goto errout; \
        } \
    } while(0);


volatile uint8_t host_packet_buf[MAX_HOST_PACKET_SIZE];
volatile int host_packet_length = 0;


void noise_state_init(struct NoiseState *st, uint8_t *remote_key_reference) {
    st->handshake_state = HANDSHAKE_UNINITIALIZED;
    st->handshake = NULL;
    st->tx_cipher = NULL;
    st->rx_cipher = NULL;
    st->remote_key_reference = remote_key_reference;
    st->failed_handshakes = 0;
}

int reset_protocol_handshake(struct NoiseState *st) {
    uninit_handshake(st, HANDSHAKE_UNINITIALIZED);
    return start_protocol_handshake(st);
}

int start_protocol_handshake(struct NoiseState *st) {
    /* TODO Noise-C is nice for prototyping, but we should really get rid of it for mostly three reasons:
     *   * We don't need cipher/protocol agility, and by baking the final protocol into the firmware we can save a lot
     *     of flash space by not including all the primitives we don't need as well as noise's dynamic protocol
     *     abstraction layer.
     *   * Noise-c is not very embedded-friendly, in particular it uses malloc and free. We should be able to run
     *     everything with statically allocated buffers instead.
     *   * Parts of it are not written that well
     */
    NoiseHandshakeState *handshake;
    int err;
    
    HANDLE_NOISE_ERROR(noise_init(), "initializing noise");

    HANDLE_NOISE_ERROR(noise_handshakestate_new_by_name(&handshake, "Noise_XX_25519_ChaChaPoly_BLAKE2s", NOISE_ROLE_RESPONDER), "instantiating handshake pattern");

    NoiseDHState *dh = noise_handshakestate_get_local_keypair_dh(handshake);
    HANDLE_NOISE_ERROR(noise_dhstate_set_keypair_private(dh, st->local_key, sizeof(st->local_key)), "loading local private keys");

    HANDLE_NOISE_ERROR(noise_handshakestate_start(handshake), "starting handshake");

    st->handshake = handshake;
    st->handshake_state = HANDSHAKE_IN_PROGRESS;
    return 0;

errout:
    noise_handshakestate_free(handshake);
    return -1;
}

int generate_identity_key(struct NoiseState *st) {
    NoiseDHState *dh;
    int err;

    HANDLE_NOISE_ERROR(noise_dhstate_new_by_name(&dh, "25519"), "creating dhstate for key generation"); 
    HANDLE_NOISE_ERROR(noise_dhstate_generate_keypair(dh), "generating key pair");

    uint8_t unused[CURVE25519_KEY_LEN]; /* the noise api is a bit bad here. */
    memset(st->local_key, 0, sizeof(st->local_key));

    HANDLE_NOISE_ERROR(noise_dhstate_get_keypair(dh, st->local_key, sizeof(st->local_key), unused, sizeof(unused)), "saving key pair");

    return 0;
errout:
    if (dh)
        noise_dhstate_free(dh);
    return -1;
}

void uninit_handshake(struct NoiseState *st, enum handshake_state new_state) {
    if (st->handshake)
        noise_handshakestate_free(st->handshake);
    st->handshake_state = new_state;
    st->handshake = NULL;
}

int try_continue_noise_handshake(struct NoiseState *st, uint8_t *buf, size_t len) {
    int err;
    struct {
        struct control_packet header;
        uint8_t payload[MAX_HOST_PACKET_SIZE];
    } pkt;
    NoiseBuffer noise_msg;

    if (!st->handshake || st->handshake_state != HANDSHAKE_IN_PROGRESS) {
        LOG_PRINTF("Error: Invalid handshake state\n");
        goto errout;
    }

    /* Run the protocol handshake */
    switch (noise_handshakestate_get_action(st->handshake)) {
    case NOISE_ACTION_WRITE_MESSAGE:
        /* Write the next handshake message with a zero-length noise payload */
        pkt.header.type = HOST_HANDSHAKE;
        noise_buffer_set_output(noise_msg, &pkt.payload, sizeof(pkt.payload));
        HANDLE_NOISE_ERROR(noise_handshakestate_write_message(st->handshake, &noise_msg, NULL), "writing handshake message");
        send_packet(usart2_out, (uint8_t *)&pkt, noise_msg.size + sizeof(pkt.header));
        if (buf) {
            LOG_PRINTF("Warning: dropping unneeded host buffer of length %d bytes\n", len);
        }
        break;

    case NOISE_ACTION_READ_MESSAGE:
        if (buf) {
            /* Read the next handshake message and discard the payload */
            noise_buffer_set_input(noise_msg, buf, len);
            HANDLE_NOISE_ERROR(noise_handshakestate_read_message(st->handshake, &noise_msg, NULL), "reading handshake message");
        }
        break;

    case NOISE_ACTION_SPLIT:
        HANDLE_NOISE_ERROR(noise_handshakestate_split(st->handshake, &st->tx_cipher, &st->rx_cipher), "splitting handshake state");
        LOG_PRINTF("Noise protocol handshake completed successfully, handshake hash:\n");

        if (noise_handshakestate_get_handshake_hash(st->handshake, st->handshake_hash, sizeof(st->handshake_hash)) != NOISE_ERROR_NONE) {
            LOG_PRINTF("Error fetching noise handshake state\n");
        } else {
            LOG_PRINTF("    ");
            for (size_t i=0; i<sizeof(st->handshake_hash); i++)
                LOG_PRINTF("%02x ", st->handshake_hash[i]);
            LOG_PRINTF("\n");
        }

        
        NoiseDHState *remote_dh = noise_handshakestate_get_remote_public_key_dh(st->handshake);
        if (!remote_dh) {
            LOG_PRINTF("Error: Host has not identified itself\n");
            goto errout;
        }

        HANDLE_NOISE_ERROR(noise_dhstate_get_public_key(remote_dh, st->remote_key, sizeof(st->remote_key)), "getting remote pubkey");

        if (!memcmp(st->remote_key, st->remote_key_reference, sizeof(st->remote_key))) { /* keys match */
            uninit_handshake(st, HANDSHAKE_DONE_KNOWN_HOST);
            st->failed_handshakes = 0;
        } else { /* keys don't match */
            uninit_handshake(st, HANDSHAKE_DONE_UNKNOWN_HOST);
            st->failed_handshakes++;
        }
        break;

    default:
        goto errout;
    }

    return 0;
errout:
    uninit_handshake(st, HANDSHAKE_UNINITIALIZED);
    st->failed_handshakes++;
    LOG_PRINTF("Noise protocol handshake failed, %d failed attempts\n", st->failed_handshakes);
    return -1;
}

void persist_remote_key(struct NoiseState *st) {
    memcpy(st->remote_key_reference, st->remote_key, sizeof(st->remote_key));
    st->handshake_state = HANDSHAKE_DONE_KNOWN_HOST;
}

int send_encrypted_message(struct NoiseState *st, uint8_t *msg, size_t len) {
    int err;
    NoiseBuffer noise_buf;
    struct {
        struct control_packet header;
        uint8_t payload[MAX_HOST_PACKET_SIZE];
    } pkt;

    if (!st->tx_cipher) {
        LOG_PRINTF("Cannot send encrypted packet: Data ciphers not yet initialized\n");
        return -1;
    }

    if (len > sizeof(pkt.payload)) {
        LOG_PRINTF("Packet too long\n");
        return -3;
    }

    pkt.header.type = HOST_DATA;
    memcpy(pkt.payload, msg, len); /* This is necessary because noises API doesn't support separate in and out buffers. D'oh! */
    noise_buffer_set_inout(noise_buf, pkt.payload, len, sizeof(pkt.payload));

    HANDLE_NOISE_ERROR(noise_cipherstate_encrypt(st->tx_cipher, &noise_buf), "encrypting data");
    send_packet(usart2_out, (uint8_t *)&pkt, noise_buf.size + sizeof(pkt.header));

    return 0;
errout:
    return -2;
}

