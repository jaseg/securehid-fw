
#include <string.h>

#include "noise.h"
#include "packet_interface.h"
#include "rand_stm32.h"

#include "crypto/noise-c/src/crypto/blake2/blake2s.h"


#ifdef VERIFICATION
#define HANDLE_NOISE_ERROR(x, msg) if (x) { goto errout; }
#else
#define HANDLE_NOISE_ERROR(x, msg) do { \
        err = x; \
        if (err != NOISE_ERROR_NONE) { \
            char errbuf[256]; \
            noise_strerror(err, errbuf, sizeof(errbuf)); \
            LOG_PRINTF("Error " msg ": %s\n", errbuf); \
            goto errout; \
        } \
    } while(0);
#endif

#ifdef VERIFICATION

/*@ requires \valid(s + (0..n-1));
  @ assigns s[0..n-1] \from c;
  @ assigns \result \from s;
  @ ensures result_ptr: \result == s;
  @*/
uint8_t *fc_memset_uint8(uint8_t *s, int c, size_t n);

/*@ requires \valid(dest + (0..n-1));
  @ requires \valid_read(src + (0..n-1));
  @ assigns dest[0..n-1] \from src[0..n-1];
  @ assigns \result \from dest;
  @ ensures result_ptr: \result == dest;
  @ ensures equals: \forall integer i; 0 <= i <= n-1 ==> dest[i] == src[i];
  @*/
uint8_t *fc_memcpy_uint8(uint8_t *dest, const uint8_t *src, size_t n);

#else
#define fc_memset_uint8 memset
#define fc_memcpy_uint8 memcpy
#endif


volatile uint8_t host_packet_buf[MAX_HOST_PACKET_SIZE];
volatile int host_packet_length = 0;


/*@
    requires validity: \valid(st);

    ensures equal: st->remote_key_reference == remote_key_reference && st->local_key == local_key;
    ensures equal: st->handshake_state == HANDSHAKE_UNINITIALIZED;
    ensures equal: st->failed_handshakes == 0;
    ensures equal: st->tx_cipher == NULL && st->rx_cipher == NULL && st->handshake == NULL;

    assigns *st;
 */
void noise_state_init(struct NoiseState *st, uint8_t *remote_key_reference, uint8_t *local_key) {
    st->handshake_state = HANDSHAKE_UNINITIALIZED;
    st->handshake = NULL;
    st->tx_cipher = NULL;
    st->rx_cipher = NULL;
    fc_memset_uint8(st->handshake_hash, 0, sizeof(st->handshake_hash));
    st->remote_key_reference = remote_key_reference;
    st->local_key = local_key;
    st->failed_handshakes = 0;
}

/*@
    requires validity: \valid(st) && \valid(st->handshake_hash + (0..31)) && \valid_read(st->local_key + (0..31));
    requires separation: \separated(st, st->rx_cipher, st->tx_cipher, st->handshake);

    ensures result: \result \in {0, -1};
    ensures success: \result == 0 ==> (
        \valid(st->handshake) &&
        (st->handshake_state == HANDSHAKE_IN_PROGRESS));
    ensures failure: \result != 0 ==> (
        (st->handshake == NULL) &&
        (st->handshake_state == HANDSHAKE_UNINITIALIZED));

    assigns *st, *st->rx_cipher, *st->tx_cipher;
 */
int reset_protocol_handshake(struct NoiseState *st) {
    uninit_handshake(st, HANDSHAKE_UNINITIALIZED);
    disarm_key_scrubber();
    noise_cipherstate_free(st->tx_cipher);
    noise_cipherstate_free(st->rx_cipher);
    st->tx_cipher = NULL;
    st->rx_cipher = NULL;
    st->handshake = NULL;
    fc_memset_uint8(st->handshake_hash, 0, sizeof(st->handshake_hash));
    return start_protocol_handshake(st);
}

/*@ requires validity: \valid(st) && \valid_read(st->local_key + (0..31));
  
    ensures result: \result \in {0, -1};
    ensures success: \result == 0 ==> (
        \valid(st->handshake) &&
        st->handshake_state == HANDSHAKE_IN_PROGRESS);
    ensures failure: \result != 0 ==> (
        st->handshake == \old(st->handshake) &&
        st->handshake_state == \old(st->handshake_state));

    assigns st->handshake, st->handshake_state;
 */
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
    HANDLE_NOISE_ERROR(noise_dhstate_set_keypair_private(dh, st->local_key, CURVE25519_KEY_LEN), "loading local private keys");

    HANDLE_NOISE_ERROR(noise_handshakestate_start(handshake), "starting handshake");

    st->handshake = handshake;
    st->handshake_state = HANDSHAKE_IN_PROGRESS;
    return 0;

errout:
    noise_handshakestate_free(handshake);
    return -1;
}

/*@ requires validity: \valid(st) && \valid(st->local_key + (0..31));
    requires separation: \separated(st, st->local_key + (0..31));

    assigns st->local_key[0..31];
 */
int generate_identity_key(struct NoiseState *st) {
    NoiseDHState *dh;
    int err;

    HANDLE_NOISE_ERROR(noise_dhstate_new_by_name(&dh, "25519"), "creating dhstate for key generation"); 
    HANDLE_NOISE_ERROR(noise_dhstate_generate_keypair(dh), "generating key pair");

    uint8_t unused[CURVE25519_KEY_LEN]; /* the noise api is a bit bad here. */
    fc_memset_uint8(st->local_key, 0, CURVE25519_KEY_LEN);

    HANDLE_NOISE_ERROR(noise_dhstate_get_keypair(dh, st->local_key, CURVE25519_KEY_LEN, unused, sizeof(unused)), "saving key pair");

    noise_dhstate_free(dh);
    return 0;
errout:
    if (dh)
        noise_dhstate_free(dh);
    return -1;
}

/*@requires validity: \valid(st);
   requires state_valid: new_state \in
           {HANDSHAKE_UNINITIALIZED, HANDSHAKE_NOT_STARTED, HANDSHAKE_IN_PROGRESS,
           HANDSHAKE_DONE_UNKNOWN_HOST, HANDSHAKE_DONE_KNOWN_HOST};

   ensures state: st->handshake_state == new_state;
   ensures handshake: st->handshake == NULL;

   assigns st->handshake, st->handshake_state;
 @*/
void uninit_handshake(struct NoiseState *st, enum handshake_state new_state) {
    if (st->handshake)
        noise_handshakestate_free(st->handshake);
    st->handshake_state = new_state;
    st->handshake = NULL;
    arm_key_scrubber();
}

//@ ghost int key_checked_trace;
//@ ghost int key_match_trace;
/*@ 
    requires validity: \valid(st) && \valid(usart2_out) && \valid(st->handshake);

    requires validity: \valid(st->remote_key + (0..sizeof(st->remote_key)-1));
    requires validity: \valid(st->handshake_hash + (0..sizeof(st->handshake_hash)-1));

    requires separation: \separated(&usart2_out, st, buf, st->handshake, &st->handshake_hash);

    ensures result: \result \in {0, -1};

    ensures state_legal: st->handshake_state \in
            {HANDSHAKE_UNINITIALIZED, HANDSHAKE_IN_PROGRESS, HANDSHAKE_DONE_KNOWN_HOST, HANDSHAKE_DONE_UNKNOWN_HOST};
    ensures transition_legal_advance: (\old(st->handshake_state) != HANDSHAKE_IN_PROGRESS)
            ==> st->handshake_state == HANDSHAKE_UNINITIALIZED;
    ensures transition_legal_failure: st->handshake_state == HANDSHAKE_UNINITIALIZED <==> \result == -1;

    ensures permission_valid: (st->handshake_state == HANDSHAKE_DONE_KNOWN_HOST) ==> key_checked_trace == 1;
    ensures state_advance_condition: (st->handshake_state != HANDSHAKE_IN_PROGRESS) ==>
        key_match_trace == 1 || (st->failed_handshakes > \old(st->failed_handshakes));

  @*/
int try_continue_noise_handshake(struct NoiseState * const st, uint8_t *buf, size_t len) {
    //@ ghost key_checked_trace = 0;
    //@ ghost key_match_trace = 0;
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

        //@ assert \valid(&st->handshake);
        if (noise_handshakestate_get_handshake_hash(st->handshake, st->handshake_hash, sizeof(st->handshake_hash)) != NOISE_ERROR_NONE) {
            LOG_PRINTF("Error fetching noise handshake state\n");
        } else {
            LOG_PRINTF("    ");
            for (size_t i=0; i<sizeof(st->handshake_hash); i++)
                LOG_PRINTF("%02x ", st->handshake_hash[i]);
            LOG_PRINTF("\n");
        }

        
        //@ assert \valid(&st->handshake);
        NoiseDHState *remote_dh = noise_handshakestate_get_remote_public_key_dh(st->handshake);
        if (!remote_dh) {
            LOG_PRINTF("Error: Host has not identified itself\n");
            goto errout;
        }

        HANDLE_NOISE_ERROR(noise_dhstate_get_public_key(remote_dh, st->remote_key, sizeof(st->remote_key)), "getting remote pubkey");

        /* TODO support list of known remote hosts here instead of just one */
        uint8_t remote_fp[BLAKE2S_HASH_SIZE];
        BLAKE2s_context_t bc;
        BLAKE2s_reset(&bc);
        fc_BLAKE2s_update_uint8(&bc, st->remote_key, sizeof(st->remote_key));
        BLAKE2s_finish(&bc, remote_fp);

        //@ ghost key_checked_trace = 1;
        if (!memcmp(remote_fp, st->remote_key_reference, sizeof(remote_fp))) { /* keys match */
            //@ ghost key_match_trace = 1;
            uint8_t response = REPORT_PAIRING_SUCCESS;
            if (send_encrypted_message(st, &response, sizeof(response)))
                LOG_PRINTF("Error sending pairing response packet\n");

            uninit_handshake(st, HANDSHAKE_DONE_KNOWN_HOST);
            st->failed_handshakes = 0;

        } else { /* keys don't match */
            uint8_t response = REPORT_PAIRING_START;
            if (send_encrypted_message(st, &response, sizeof(response)))
                LOG_PRINTF("Error sending pairing response packet\n");

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

/*@
    requires validity: \valid(st);
    requires validity: \valid_read(st->remote_key + (0..sizeof(st->remote_key)-1));
    requires validity: \valid(st->remote_key_reference + (0..31));

    ensures state: st->handshake_state == HANDSHAKE_DONE_KNOWN_HOST;
    assigns st->remote_key_reference[0..31], st->handshake_state;
 */
void persist_remote_key(struct NoiseState *st) {
    BLAKE2s_context_t bc;
    BLAKE2s_reset(&bc);
    fc_BLAKE2s_update_uint8(&bc, st->remote_key, sizeof(st->remote_key));
    BLAKE2s_finish(&bc, st->remote_key_reference);
    st->handshake_state = HANDSHAKE_DONE_KNOWN_HOST;
}

/*@
  requires validity: \valid(st) && \valid(usart2_out) && \valid(st->tx_cipher) && \valid_read(msg + (0..len-1));

  ensures length: !(0 <= len <= MAX_HOST_PACKET_SIZE) <==> \result == -3;
  ensures \result \in {0, -1, -2, -3};
  assigns *st->tx_cipher, *usart2_out;
 */
int send_encrypted_message(struct NoiseState *st, const uint8_t *msg, size_t len) {
    int err;
    NoiseBuffer noise_buf;
    struct {
        struct control_packet header;
        uint8_t payload[MAX_HOST_PACKET_SIZE];
    } pkt;

    if (len > sizeof(pkt.payload)) {
        LOG_PRINTF("Packet too long\n");
        return -3;
    }

    if (!st->tx_cipher) {
        LOG_PRINTF("Cannot send encrypted packet: Data ciphers not yet initialized\n");
        return -1;
    }

    pkt.header.type = HOST_DATA;
    fc_memcpy_uint8(pkt.payload, msg, len); /* This is necessary because noises API doesn't support separate in and out buffers. D'oh! */
    noise_buffer_set_inout(noise_buf, pkt.payload, len, sizeof(pkt.payload));

    HANDLE_NOISE_ERROR(noise_cipherstate_encrypt(st->tx_cipher, &noise_buf), "encrypting data");
    send_packet(usart2_out, (uint8_t *)&pkt, noise_buf.size + sizeof(pkt.header));

    return 0;
errout:
    return -2;
}

