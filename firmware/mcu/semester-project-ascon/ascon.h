#ifndef ASCON_H_
#define ASCON_H_

#include <stdint.h>

#define ASCON_KEYBYTES 16
#define ASCON_NPUBBYTES 16
#define ASCON_ABYTES 16
#define ASCON_AEAD_RATE 16
#define ASCON_AEAD_VARIANT 1
#define ASCON_PA_ROUNDS 12

typedef struct {
  uint64_t x[5];
} ascon_state_t;

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

#endif /* ASCON_H_ */