
include_directories (
    noise-c/include
    noise-c/include/noise/keys
    noise-c/src
    noise-c/src/crypto/goldilocks/include
    noise-c/src/crypto/goldilocks/src/include
    noise-c/src/crypto/goldilocks/src/p448/arch_arm_32
    noise-c/src/crypto/goldilocks/src/p448
    noise-c/src/protocol
)

add_library (noise
    noise-c/src/protocol/util.c
    noise-c/src/protocol/patterns.c
    noise-c/src/protocol/signstate.c
    noise-c/src/protocol/randstate.c
    noise-c/src/protocol/symmetricstate.c
    noise-c/src/protocol/internal.c
    noise-c/src/protocol/names.c
    noise-c/src/protocol/hashstate.c
    noise-c/src/protocol/errors.c
    noise-c/src/protocol/cipherstate.c
    noise-c/src/protocol/handshakestate.c
    noise-c/src/protocol/dhstate.c
    noise-c/src/keys/certificate.c
    noise-c/src/keys/loader.c
    noise-c/src/crypto/sha2/sha256.c
    noise-c/src/crypto/sha2/sha512.c
    noise-c/src/crypto/ghash/ghash.c
    noise-c/src/crypto/ed25519/ed25519.c
    noise-c/src/crypto/blake2/blake2s.c
    noise-c/src/crypto/blake2/blake2b.c
    noise-c/src/crypto/chacha/chacha.c
    noise-c/src/crypto/goldilocks/src/ec_point.c
    noise-c/src/crypto/goldilocks/src/sha512.c
    noise-c/src/crypto/goldilocks/src/p448/arch_32/p448.c
    noise-c/src/crypto/goldilocks/src/p448/f_arithmetic.c
    noise-c/src/crypto/goldilocks/src/p448/arch_arm_32/p448.c
    noise-c/src/crypto/goldilocks/src/p448/magic.c
    noise-c/src/crypto/goldilocks/src/barrett_field.c
    noise-c/src/crypto/goldilocks/src/goldilocks.c
    noise-c/src/crypto/goldilocks/src/arithmetic.c
    noise-c/src/crypto/goldilocks/src/crandom.c
    noise-c/src/crypto/goldilocks/src/scalarmul.c
    noise-c/src/crypto/newhope/poly.c
    noise-c/src/crypto/newhope/randombytes.c
    noise-c/src/crypto/newhope/reduce.c
    noise-c/src/crypto/newhope/ntt.c
    noise-c/src/crypto/newhope/crypto_stream_chacha20.c
    noise-c/src/crypto/newhope/error_correction.c
    noise-c/src/crypto/newhope/batcher.c
    noise-c/src/crypto/newhope/fips202.c
    noise-c/src/crypto/newhope/newhope.c
    noise-c/src/crypto/newhope/precomp.c
    noise-c/src/crypto/aes/rijndael-alg-fst.c
    noise-c/src/crypto/curve448/curve448.c
    noise-c/src/crypto/donna/poly1305-donna.c
    noise-c/src/crypto/donna/curve25519-donna.c
    noise-c/src/protobufs/protobufs.c
    noise-c/src/backend/ref/sign-ed25519.c
    noise-c/src/backend/ref/hash-blake2b.c
    noise-c/src/backend/ref/hash-sha512.c
    noise-c/src/backend/ref/hash-sha256.c
    noise-c/src/backend/ref/cipher-aesgcm.c
    noise-c/src/backend/ref/cipher-chachapoly.c
    noise-c/src/backend/ref/dh-curve25519.c
    noise-c/src/backend/ref/dh-newhope.c
    noise-c/src/backend/ref/dh-curve448.c
    noise-c/src/backend/ref/hash-blake2s.c
)

add_definitions (
    -DUSE_LIBSODIUM=0
    -DUSE_SODIUM=0
    -DHAVE_PTHREAD=0
    -DUSE_OPENSSL=0
    -D__WORDSIZE=32
    -D__BIG_ENDIAN=4321
    -D__LITTLE_ENDIAN=1234
    -D__BYTE_ORDER=__LITTLE_ENDIAN
    -DED25519_CUSTOMRANDOM=1
    -DED25519_CUSTOMHASH=1
    -DED25519_REFHASH=1
    -DBLAKE2S_USE_VECTOR_MATH=0
    -DEXPERIMENT_CRANDOM_CUTOFF_BYTES=0
    -D__clang__=0
)

set (CMAKE_C_FLAGS
    "${CMAKE_C_FLAGS} -Wno-implicit-fallthrough -Wno-shadow -Wno-unused-parameter"
)

