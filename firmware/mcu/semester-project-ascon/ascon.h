#ifndef ASCON_H_
#define ASCON_H_

#include <stdint.h>

#define ASCON_KEYBYTES 16
#define ASCON_NPUBBYTES 16
#define ASCON_ABYTES 16
#define ASCON_AEAD_RATE 16
#define ASCON_AEAD_VARIANT 1
#define ASCON_PA_ROUNDS 12
#define ASCON_128A_IV 0x1000808c0001

static const uint64_t ASCON_RC[] = {
    0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b
};

typedef struct {
  uint64_t x[5];
} ascon_state_t;

static inline uint64_t load_word(const uint8_t* bytes, int n) {
    uint64_t x = 0;
    for (int i = 0; i < n; ++i) x |= (uint64_t)bytes[i] << (8 * i);
    return x;
}

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
);

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
);

void ascon_round(ascon_state_t* s, uint8_t C);

#endif /* ASCON_H_ */