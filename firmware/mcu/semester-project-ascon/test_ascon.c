#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include "ascon.h"

#define MAX_LINE_LEN 4096

static int hex_to_bytes(uint8_t* to, const char* from, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (sscanf(from + 2 * i, "%2hhx", &to[i]) != 1) {
            return -1;
        }
    }
    return 0;
}

static void trim(char *str) {
    int i;
    int begin = 0;
    int end = strlen(str) - 1;

    while (isspace((unsigned char) str[begin]))
        begin++;

    while ((end >= begin) && isspace((unsigned char) str[end]))
        end--;

    for (i = begin; i <= end; i++)
        str[i - begin] = str[i];

    str[i - begin] = '\0';
}

int main(void) {
    FILE* fp = fopen("LWC_AEAD_KAT_128_128.txt", "r");
    if (fp == NULL) {
        perror("Failed to open LWC_AEAD_KAT_128_128.txt");
        return 1;
    }

    char line[MAX_LINE_LEN];
    int count = 0;
    int fails = 0;

    uint8_t key[ASCON_KEYBYTES];
    uint8_t nonce[ASCON_NPUBBYTES];
    uint8_t ad[MAX_LINE_LEN / 2];
    uint8_t pt[MAX_LINE_LEN / 2];
    uint8_t ct[MAX_LINE_LEN / 2];
    uint8_t decrypted_pt[MAX_LINE_LEN / 2];

    unsigned long long adlen = 0;
    unsigned long long ptlen = 0;
    unsigned long long ctlen = 0;
    unsigned long long decrypted_ptlen = 0;


    while (fgets(line, sizeof(line), fp)) {
        trim(line);
        if (strlen(line) == 0) continue;

        if (strncmp(line, "Count = ", 8) == 0) {
            count = atoi(line + 8);
            adlen = 0;
            ptlen = 0;
        } else if (strncmp(line, "Key = ", 6) == 0) {
            hex_to_bytes(key, line + 6, ASCON_KEYBYTES);
        } else if (strncmp(line, "Nonce = ", 8) == 0) {
            hex_to_bytes(nonce, line + 8, ASCON_NPUBBYTES);
        } else if (strncmp(line, "AD = ", 5) == 0) {
            adlen = strlen(line + 5) / 2;
            hex_to_bytes(ad, line + 5, adlen);
        } else if (strncmp(line, "PT = ", 5) == 0) {
            ptlen = strlen(line + 5) / 2;
            hex_to_bytes(pt, line + 5, ptlen);
        } else if (strncmp(line, "CT = ", 5) == 0) {
            ctlen = strlen(line + 5) / 2;
            hex_to_bytes(ct, line + 5, ctlen);

            // Encrypt
            unsigned long long encrypted_ctlen = 0;
            uint8_t encrypted_ct[ptlen + ASCON_ABYTES];
            ascon_aead_encrypt(encrypted_ct, &encrypted_ctlen, pt, ptlen, ad, adlen, NULL, nonce, key);

            if (memcmp(encrypted_ct, ct, ctlen) != 0) {
                printf("FAIL: Count=%d (Ciphertext+Tag mismatch)\n", count);
                fails++;
            }

            // Decrypt
            if (ascon_aead_decrypt(decrypted_pt, &decrypted_ptlen, NULL, ct, ctlen, ad, adlen, nonce, key) != 0) {
                printf("FAIL: Count=%d (Decryption failed)\n", count);
                fails++;
            } else if (memcmp(decrypted_pt, pt, ptlen) != 0) {
                printf("FAIL: Count=%d (Plaintext mismatch)\n", count);
                fails++;
            }
        }
    }

    fclose(fp);

    if (fails == 0) {
        printf("ALL TESTS PASSED\n");
    } else {
        printf("%d TEST(S) FAILED\n", fails);
    }

    return fails == 0 ? 0 : 1;
}
