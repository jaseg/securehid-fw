
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
volatile uint8_t host_packet_length = 0;

static uint8_t local_key[CURVE25519_KEY_LEN];
static NoiseCipherState *tx_cipher = NULL, *rx_cipher = NULL;


NoiseHandshakeState *start_protocol_handshake() {
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
    HANDLE_NOISE_ERROR(noise_dhstate_set_keypair_private(dh, local_key, sizeof(local_key)), "loading local private keys");

    HANDLE_NOISE_ERROR(noise_handshakestate_start(handshake), "starting handshake");

    return handshake;

errout:
    noise_handshakestate_free(handshake);
    return 0;
}

int generate_identity_key() {
    NoiseDHState *dh;
    int err;

    HANDLE_NOISE_ERROR(noise_dhstate_new_by_name(&dh, "25519"), "creating dhstate for key generation"); 
    HANDLE_NOISE_ERROR(noise_dhstate_generate_keypair(dh), "generating key pair");

    uint8_t unused[CURVE25519_KEY_LEN]; /* the noise api is a bit bad here. */
    memset(local_key, 0, sizeof(local_key));

    HANDLE_NOISE_ERROR(noise_dhstate_get_keypair(dh, local_key, sizeof(local_key), unused, sizeof(unused)), "saving key pair");

    return 0;

errout:
    if (dh)
        noise_dhstate_free(dh);
    return -1;
}

NoiseHandshakeState *try_continue_noise_handshake(NoiseHandshakeState *handshake) {
    int err;
    uint8_t message[MAX_HOST_PACKET_SIZE];
    NoiseBuffer noise_msg;
    /* Run the protocol handshake */
    switch (noise_handshakestate_get_action(handshake)) {
    case NOISE_ACTION_WRITE_MESSAGE:
        /* Write the next handshake message with a zero-length payload */
        noise_buffer_set_output(noise_msg, message, sizeof(message));
        HANDLE_NOISE_ERROR(noise_handshakestate_write_message(handshake, &noise_msg, NULL), "writing handshake message");
        send_packet(usart2_out, message, noise_msg.size);
        break;

    case NOISE_ACTION_READ_MESSAGE:
        if (host_packet_length > 0) {
            /* Read the next handshake message and discard the payload */
            noise_buffer_set_input(noise_msg, (uint8_t *)host_packet_buf, host_packet_length);
            HANDLE_NOISE_ERROR(noise_handshakestate_read_message(handshake, &noise_msg, NULL), "reading handshake message");
            host_packet_length = 0; /* Acknowledge to USART ISR the buffer has been handled */
        }
        break;

    case NOISE_ACTION_SPLIT:
        HANDLE_NOISE_ERROR(noise_handshakestate_split(handshake, &tx_cipher, &rx_cipher), "splitting handshake state");
        LOG_PRINTF("Noise protocol handshake completed successfully, handshake hash:\n");

        uint8_t buf[BLAKE2S_HASH_SIZE];
        if (noise_handshakestate_get_handshake_hash(handshake, buf, sizeof(buf)) != NOISE_ERROR_NONE) {
            LOG_PRINTF("Error fetching noise handshake state\n");
        } else {
            LOG_PRINTF("    ");
            for (size_t i=0; i<sizeof(buf); i++)
                LOG_PRINTF("%02x ", buf[i]);
            LOG_PRINTF("\n");
        }

        noise_handshakestate_free(handshake);
        return NULL;

    default:
        LOG_PRINTF("Noise protocol handshake failed\n");
        goto errout;
    }

    return handshake;

errout:
    noise_handshakestate_free(handshake);
    return NULL;
}

int send_encrypted_message(uint8_t *msg, size_t len) {
    int err;
    NoiseBuffer noise_buf;
    uint8_t raw_buf[MAX_HOST_PACKET_SIZE];

    if (!tx_cipher) {
        LOG_PRINTF("Cannot send encrypted packet: Data ciphers not yet initialized\n");
        return -1;
    }

    memcpy(raw_buf, msg, len); /* This is necessary because noises API doesn't support separate in and out buffers. D'oh! */
    noise_buffer_set_inout(noise_buf, raw_buf, len, sizeof(raw_buf));

    HANDLE_NOISE_ERROR(noise_cipherstate_encrypt(tx_cipher, &noise_buf), "encrypting data");
    send_packet(usart2_out, raw_buf, noise_buf.size);

    return 0;
errout:
    return -2;
}

