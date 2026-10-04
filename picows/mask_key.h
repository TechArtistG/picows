#pragma once

#include <stdint.h>
#include <string.h>

// WebSocket masking key generator (RFC 6455 5.3 requires keys from a strong source of entropy that
// can't be predicted from previous keys).
//
// ChaCha20 block function (RFC 8439 2.3) in counter mode, used as a CSPRNG: the state is seeded
// once with 32 random key bytes and 8 random nonce bytes, every block produces 64 bytes of
// keystream = 16 masking keys. Words 12-13 are a 64-bit block counter (original ChaCha layout),
// so the keystream never repeats in practice.

#define PICOWS_MASK_KEYS_PER_BLOCK 16

#define PICOWS_ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

#define PICOWS_CHACHA_QR(a, b, c, d)                     \
    a += b; d ^= a; d = PICOWS_ROTL32(d, 16);            \
    c += d; b ^= c; b = PICOWS_ROTL32(b, 12);            \
    a += b; d ^= a; d = PICOWS_ROTL32(d, 8);             \
    c += d; b ^= c; b = PICOWS_ROTL32(b, 7)

static inline void picows_chacha20_block(const uint32_t state[16], uint32_t out[16])
{
    uint32_t x[16];
    memcpy(x, state, sizeof(x));

    for (int i = 0; i < 10; i++) {
        PICOWS_CHACHA_QR(x[0], x[4], x[8], x[12]);
        PICOWS_CHACHA_QR(x[1], x[5], x[9], x[13]);
        PICOWS_CHACHA_QR(x[2], x[6], x[10], x[14]);
        PICOWS_CHACHA_QR(x[3], x[7], x[11], x[15]);
        PICOWS_CHACHA_QR(x[0], x[5], x[10], x[15]);
        PICOWS_CHACHA_QR(x[1], x[6], x[11], x[12]);
        PICOWS_CHACHA_QR(x[2], x[7], x[8], x[13]);
        PICOWS_CHACHA_QR(x[3], x[4], x[9], x[14]);
    }

    for (int i = 0; i < 16; i++)
        out[i] = x[i] + state[i];
}

// seed: 32 bytes of key followed by 8 bytes of nonce
static inline void picows_mask_key_gen_init(uint32_t state[16], const uint8_t seed[40])
{
    state[0] = 0x61707865;  // "expand 32-byte k"
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
    memcpy(&state[4], seed, 32);
    state[12] = 0;
    state[13] = 0;
    memcpy(&state[14], seed + 32, 8);
}

// Produce the next 16 masking keys into keys[] and advance the 64-bit block counter.
static inline void picows_mask_key_gen_next_block(uint32_t state[16], uint32_t keys[16])
{
    picows_chacha20_block(state, keys);
    if (++state[12] == 0)
        ++state[13];
}
