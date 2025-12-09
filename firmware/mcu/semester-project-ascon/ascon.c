#include "ascon.h"
#include <string.h>

// --- Helper Macros and Functions ---

// Rotate right by 'k' bits for a 64-bit word
static inline uint64_t ROR(uint64_t x, int n) {
    return x >> n | x << (-n & 63);
}

// Load a 64-bit word from a little-endian byte array
static inline uint64_t load_word(const uint8_t* bytes, int n) {
    uint64_t x = 0;
    for (int i = 0; i < n; ++i) {
        x |= (uint64_t)bytes[i] << (8 * i);
    }
    return x;
}

// Store a 64-bit word to a little-endian byte array
static inline void store_word(uint8_t* bytes, uint64_t x, int n) {
    for (int i = 0; i < n; ++i) {
        bytes[i] = (uint8_t)(x >> (8 * i));
    }
}

// Set padding byte in 64-bit Ascon word
#define PAD(i) ((uint64_t)0x01 << (8 * (i)))

// --- ASCON Core Permutation Implementation ---

// Round constants
static const uint64_t ASCON_RC[] = {
    0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b
};

#define ASCON_AEAD_VARIANT 1
#define ASCON_PA_ROUNDS 12
#define ASCON_128A_PB_ROUNDS 8
#define ASCON_TAG_SIZE 16
#define ASCON_128A_RATE 16

#define ASCON_128A_IV                         \
  (((uint64_t)(ASCON_AEAD_VARIANT) << 0) |    \
   ((uint64_t)(ASCON_PA_ROUNDS) << 16) |      \
   ((uint64_t)(ASCON_128A_PB_ROUNDS) << 20) | \
   ((uint64_t)(ASCON_TAG_SIZE * 8) << 24) |   \
   ((uint64_t)(ASCON_128A_RATE) << 40))

static inline void ascon_round(ascon_state_t* s, uint8_t C) {
    ascon_state_t t;

    // --- Add Round Constant ---
    s->x[2] ^= C;

    // --- Substitution Layer ---
    s->x[0] ^= s->x[4];
    s->x[4] ^= s->x[3];
    s->x[2] ^= s->x[1];
    
    // Keccak S-box
    t.x[0] = s->x[0] ^ (~s->x[1] & s->x[2]);
    t.x[1] = s->x[1] ^ (~s->x[2] & s->x[3]);
    t.x[2] = s->x[2] ^ (~s->x[3] & s->x[4]);
    t.x[3] = s->x[3] ^ (~s->x[4] & s->x[0]);
    t.x[4] = s->x[4] ^ (~s->x[0] & s->x[1]);
    
    t.x[1] ^= t.x[0];
    t.x[0] ^= t.x[4];
    t.x[3] ^= t.x[2];
    t.x[2] = ~t.x[2];

    // --- Linear Diffusion Layer ---
    s->x[0] = t.x[0] ^ ROR(t.x[0], 19) ^ ROR(t.x[0], 28);
    s->x[1] = t.x[1] ^ ROR(t.x[1], 61) ^ ROR(t.x[1], 39);
    s->x[2] = t.x[2] ^ ROR(t.x[2], 1) ^ ROR(t.x[2], 6);
    s->x[3] = t.x[3] ^ ROR(t.x[3], 10) ^ ROR(t.x[3], 17);
    s->x[4] = t.x[4] ^ ROR(t.x[4], 7) ^ ROR(t.x[4], 41);
}

static inline void ascon_p(ascon_state_t* s, int rounds) {
    for (int i = 12 - rounds; i < 12; i++) {
        ascon_round(s, ASCON_RC[i]);
    }
}

// --- AEAD Implementation ---

int ascon_aead_encrypt(
    unsigned char *c,
    unsigned long long *clen,
    const unsigned char *m,
    unsigned long long mlen,
    const unsigned char *ad,
    unsigned long long adlen,
    const unsigned char *nsec,
    const unsigned char *npub,
    const unsigned char *k
) {
    (void)nsec;

    *clen = mlen + ASCON_ABYTES;

    const uint64_t K0 = load_word(k, 8);
    const uint64_t K1 = load_word(k + 8, 8);
    const uint64_t N0 = load_word(npub, 8);
    const uint64_t N1 = load_word(npub + 8, 8);

    ascon_state_t s;
    s.x[0] = ASCON_128A_IV;
    s.x[1] = K0;
    s.x[2] = K1;
    s.x[3] = N0;
    s.x[4] = N1;
    ascon_p(&s, 12);
    s.x[3] ^= K0;
    s.x[4] ^= K1;

    if (adlen) {
        while (adlen >= ASCON_AEAD_RATE) {
            s.x[0] ^= load_word(ad, 8);
            s.x[1] ^= load_word(ad + 8, 8);
            ascon_p(&s, 8);
            ad += ASCON_AEAD_RATE;
            adlen -= ASCON_AEAD_RATE;
        }
        if (adlen >= 8) {
            s.x[0] ^= load_word(ad, 8);
            s.x[1] ^= load_word(ad + 8, adlen - 8);
            s.x[1] ^= PAD(adlen - 8);
        } else {
            s.x[0] ^= load_word(ad, adlen);
            s.x[0] ^= PAD(adlen);
        }
        ascon_p(&s, 8);
    }
    s.x[4] ^= 0x8000000000000000;

    while (mlen >= ASCON_AEAD_RATE) {
        s.x[0] ^= load_word(m, 8);
        s.x[1] ^= load_word(m + 8, 8);
        store_word(c, s.x[0], 8);
        store_word(c + 8, s.x[1], 8);
        ascon_p(&s, 8);
        m += ASCON_AEAD_RATE;
        c += ASCON_AEAD_RATE;
        mlen -= ASCON_AEAD_RATE;
    }
    if (mlen >= 8) {
        s.x[0] ^= load_word(m, 8);
        s.x[1] ^= load_word(m + 8, mlen - 8);
        store_word(c, s.x[0], 8);
        store_word(c + 8, s.x[1], mlen - 8);
        s.x[1] ^= PAD(mlen - 8);
    } else {
        s.x[0] ^= load_word(m, mlen);
        store_word(c, s.x[0], mlen);
        s.x[0] ^= PAD(mlen);
    }
    c += mlen;

    s.x[2] ^= K0;
    s.x[3] ^= K1;
    ascon_p(&s, 12);
    s.x[3] ^= K0;
    s.x[4] ^= K1;

    store_word(c, s.x[3], 8);
    store_word(c + 8, s.x[4], 8);

    return 0;
}

int ascon_aead_decrypt(
    unsigned char *m,
    unsigned long long *mlen,
    unsigned char *nsec,
    const unsigned char *c,
    unsigned long long clen,
    const unsigned char *ad,
    unsigned long long adlen,
    const unsigned char *npub,
    const unsigned char *k
) {
    (void)nsec;

    if (clen < ASCON_ABYTES) return -1;

    *mlen = clen - ASCON_ABYTES;

    const uint64_t K0 = load_word(k, 8);
    const uint64_t K1 = load_word(k + 8, 8);
    const uint64_t N0 = load_word(npub, 8);
    const uint64_t N1 = load_word(npub + 8, 8);

    ascon_state_t s;
    s.x[0] = ASCON_128A_IV;
    s.x[1] = K0;
    s.x[2] = K1;
    s.x[3] = N0;
    s.x[4] = N1;
    ascon_p(&s, 12);
    s.x[3] ^= K0;
    s.x[4] ^= K1;

    if (adlen) {
        while (adlen >= ASCON_AEAD_RATE) {
            s.x[0] ^= load_word(ad, 8);
            s.x[1] ^= load_word(ad + 8, 8);
            ascon_p(&s, 8);
            ad += ASCON_AEAD_RATE;
            adlen -= ASCON_AEAD_RATE;
        }
        if (adlen >= 8) {
            s.x[0] ^= load_word(ad, 8);
            s.x[1] ^= load_word(ad + 8, adlen - 8);
            s.x[1] ^= PAD(adlen - 8);
        } else {
            s.x[0] ^= load_word(ad, adlen);
            s.x[0] ^= PAD(adlen);
        }
        ascon_p(&s, 8);
    }
    s.x[4] ^= 0x8000000000000000;

    clen -= ASCON_ABYTES;
    while (clen >= ASCON_AEAD_RATE) {
        uint64_t c0 = load_word(c, 8);
        uint64_t c1 = load_word(c + 8, 8);
        store_word(m, s.x[0] ^ c0, 8);
        store_word(m + 8, s.x[1] ^ c1, 8);
        s.x[0] = c0;
        s.x[1] = c1;
        ascon_p(&s, 8);
        m += ASCON_AEAD_RATE;
        c += ASCON_AEAD_RATE;
        clen -= ASCON_AEAD_RATE;
    }
    if (clen >= 8) {
        uint64_t c0 = load_word(c, 8);
        uint64_t c1 = load_word(c + 8, clen - 8);
        store_word(m, s.x[0] ^ c0, 8);
        store_word(m + 8, s.x[1] ^ c1, clen - 8);
        s.x[0] = c0;
        s.x[1] &= 0xffffffffffffffff << (8 * (clen - 8));
        s.x[1] |= c1;
        s.x[1] ^= PAD(clen - 8);
    } else {
        uint64_t c0 = load_word(c, clen);
        store_word(m, s.x[0] ^ c0, clen);
        s.x[0] &= 0xffffffffffffffff << (8 * clen);
        s.x[0] |= c0;
        s.x[0] ^= PAD(clen);
    }
    c += clen;

    s.x[2] ^= K0;
    s.x[3] ^= K1;
    ascon_p(&s, 12);
    s.x[3] ^= K0;
    s.x[4] ^= K1;

    uint8_t t[ASCON_ABYTES];
    store_word(t, s.x[3], 8);
    store_word(t + 8, s.x[4], 8);

    int result = 0;
    for (int i = 0; i < ASCON_ABYTES; ++i) {
        result |= c[i] ^ t[i];
    }
    
    return ((((result - 1) >> 8) & 1) - 1);
}
