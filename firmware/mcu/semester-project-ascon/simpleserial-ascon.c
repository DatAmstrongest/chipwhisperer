#include "hal.h"
#include "simpleserial.h"
#include "ascon.h"
#include <stdint.h>
#include <string.h>

#define MAX_BUFFER_SIZE 256

// All buffers initialized to 0 by default
uint8_t key[16] = {0};
uint8_t nonce[16] = {0}; 
uint8_t ad[16] = {0};
uint8_t pt[16] = {0};

// Hardcoded lengths
uint16_t ad_len = 16;
uint16_t pt_len = 16;

// 'k' - Set Key (16 bytes)
uint8_t get_key(uint8_t* k, uint8_t len)
{
    memcpy(key, k, 16);
    return 0x00;
}

// 'n' - Set Nonce (16 bytes) AND Trigger Encryption
uint8_t get_nonce(uint8_t* n, uint8_t len)
{
    // 1. Update the nonce with incoming data
    memcpy(nonce, n, 16);
    
    uint8_t ct[32] = {0}; // 16 bytes CT + 16 bytes Tag
    unsigned long long clen;
    
    // 2. Run encryption using the default 0-valued PT and AD
    trigger_high();
    
    ascon_aead_encrypt(
        ct,
        &clen,
        pt,
        (unsigned long long)pt_len,
        ad,
        (unsigned long long)ad_len,
        NULL,
        nonce,
        key
    );
    
    trigger_low();

    // 3. Send back ciphertext + tag
    simpleserial_put('r', (uint8_t)clen, ct);
    
    return 0x00;
}

int main(void)
{
    platform_init();
    init_uart();
    trigger_setup();
    simpleserial_init();

    // Only Key and Nonce commands are registered
    simpleserial_addcmd('k', 16, get_key);
    simpleserial_addcmd('n', 16, get_nonce);

    while(1)
        simpleserial_get();
}