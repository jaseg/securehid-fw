/* Quick-and-dirty cryptographic RNG based on BLAKE2s
 *
 * This system uses a 32-byte BLAKE2s hash as internal state seeded by somewhat random post-powerup SRAM content, the
 * unique device ID and the program flash contents. This seed state is mixed with values from the hardware RNG for each
 * 32-byte block of output data.
 *
 * The RNG's chaining looks like the following, with H(...) being the BLAKE2s hash function, | being binary
 * concatenation and hw_rng(...) being the hardware RNG. c and e are the fixed extraction and chain string constants
 * defined below.
 *
 * Seed:    state    = H(SRAM | FLASH | hw_rng(64 byte))
 *
 * Extract: state    = H(state | c | hw_rng(64 byte)) block[0] = H(state | e)
 *          state    = H(state | c | hw_rng(64 byte)) block[1] = H(state | e)
 *          [...]
 *          state    = H(state | c | hw_rng(64 byte)) block[n] = H(state | e)
 *          state    = H(state | c | hw_rng(64 byte))
 *
 *
 * Graphically, with C = H( state | c | rng )   being the chaining function
 *               and X = H( state | e )         being the extraction function
 * this becomes:
 *
 *            rng      rng              rng      rng
 *             |        |                |        |
 *             v        v                v        v
 * state ---> [C] ---> [C] -- . . . --> [C] ---> [C] ---> new state
 *             |        |                |
 *             v        v                v
 *            [X]      [X]              [X]
 *             |        |                |
 *             v        v                v
 *            out[0]   out[1]   . . .   out[n]
 *
 */

#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include <libopencm3/stm32/f4/rng.h>

#include "usart_helpers.h"
#include "rand_stm32.h"
#include "tracing.h"

#include "crypto/noise-c/src/protocol/internal.h"
#include "crypto/noise-c/src/crypto/blake2/blake2s.h"

/* FIXME persist state in backup sram */
extern unsigned _ram_start, _ram_end, _rom_start, _rom_end;
static uint8_t global_stm_rand_state[BLAKE2S_HASH_SIZE];

static uint32_t stm32_read_rng_raw(void) {
    if ((RNG_SR & (RNG_SR_SEIS | RNG_SR_CEIS)) || !(RNG_CR & RNG_CR_RNGEN)) {
        LOG_PRINTF("RNG error detected, bailing out.\n");
        exit(1);
    }

    while (!(RNG_SR & RNG_SR_DRDY))
        ;

    return RNG_DR;
}

static void rng_seed_blake(BLAKE2s_context_t *bc) {
    /* This pulls out 64 bytes. Even though the resulting BLAKE2s hash only is 32 bytes large, the internal state of
     * BLAKE2s is larger. Also I don't quite trust the STM32F4's hardware RNG. */
    for (int i=0; i<16; i++) {
        uint32_t val = stm32_read_rng_raw();
        BLAKE2s_update(bc, &val, sizeof(val));
    }
}

void rand_init() {
    RNG_CR |= RNG_CR_RNGEN;
    BLAKE2s_context_t bc;
    BLAKE2s_reset(&bc);

    /* Seed with entire SRAM area */
    BLAKE2s_update(&bc, &_ram_start, &_ram_end - &_ram_start);
    /* Seed with entire flash area. This includes the device unique ID if it has not been overwritten. */
    BLAKE2s_update(&bc, &_rom_start, &_rom_end - &_rom_start);
    /* Seed with 64 bytes of handware RNG input */
    rng_seed_blake(&bc);
    /* FIXME use ADC to seeed */

    BLAKE2s_finish(&bc, global_stm_rand_state);
    /* FIXME make sure this is not optimized out */
    memset(&bc, 0, sizeof(bc));
}

const char *extraction_constant = "Blake2 RNG extraction constant";
const char *chain_constant = "Blake2 RNG chaining constant";

void noise_rand_bytes(void *bytes, size_t size) {
    TRACING_SET(TR_RNG);
    BLAKE2s_context_t out_ctx, chain_ctx;
    uint8_t *out = (uint8_t *)bytes;
    uint8_t hash_buf[BLAKE2S_HASH_SIZE];

    for (size_t wr_pos = 0; wr_pos<size; wr_pos += BLAKE2S_HASH_SIZE) {
        BLAKE2s_reset(&chain_ctx);
        BLAKE2s_update(&chain_ctx, global_stm_rand_state, sizeof(global_stm_rand_state));
        BLAKE2s_update(&chain_ctx, chain_constant, strlen(chain_constant));
        rng_seed_blake(&chain_ctx);
        BLAKE2s_finish(&chain_ctx, global_stm_rand_state);

        BLAKE2s_reset(&out_ctx);
        BLAKE2s_update(&out_ctx, global_stm_rand_state, sizeof(global_stm_rand_state));
        BLAKE2s_update(&out_ctx, extraction_constant, strlen(extraction_constant));
        BLAKE2s_finish(&out_ctx, hash_buf);

        size_t rem = size-wr_pos;
        memcpy(&out[wr_pos], hash_buf, rem < BLAKE2S_HASH_SIZE ? rem : BLAKE2S_HASH_SIZE);
    }

    BLAKE2s_reset(&chain_ctx);
    BLAKE2s_update(&chain_ctx, global_stm_rand_state, sizeof(global_stm_rand_state));
    BLAKE2s_update(&chain_ctx, chain_constant, strlen(chain_constant));
    rng_seed_blake(&chain_ctx);
    BLAKE2s_finish(&chain_ctx, global_stm_rand_state);

    /* FIXME make sure this is not optimized out */
    memset(&out_ctx, 0, sizeof(out_ctx));
    memset(&chain_ctx, 0, sizeof(chain_ctx));
    memset(hash_buf, 0, sizeof(hash_buf));
    TRACING_CLEAR(TR_RNG);
}

#ifdef ED25519_CUSTOMRANDOM /* We are building against ed25519-donna, which needs a random function */
void ed25519_randombytes_unsafe(void *p, size_t len) {
    noise_rand_bytes(p, len);
}
#endif
