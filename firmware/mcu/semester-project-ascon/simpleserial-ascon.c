#include "hal.h"
#include "simpleserial.h"
#include "ascon.h"
#include <stdint.h>
#include <string.h>

#define MAX_BUFFER_SIZE 256

uint8_t key[16] = {0};
uint8_t nonce[16] = {0}; 
uint8_t ad[MAX_BUFFER_SIZE] = {0};
uint8_t pt[MAX_BUFFER_SIZE] = {0};

uint16_t ad_len = 0;
uint16_t pt_len = 0;

uint16_t ad_received = 0;
uint16_t pt_received = 0;


// 'l' - Set Lengths (Expects 16 bytes, uses first 2: [AD_LEN, PT_LEN, ...])
uint8_t set_lengths(uint8_t* x, uint8_t len)
{
    ad_len = x[0];
    pt_len = x[1];
    
    // Reset received counters
    ad_received = 0;
    pt_received = 0;
    
    return 0x00;
}

// 'k' - Set Key (16 bytes)
uint8_t get_key(uint8_t* k, uint8_t len)
{
    memcpy(key, k, 16);
    return 0x00;
}

// 'n' - Set Nonce (16 bytes)
uint8_t get_nonce(uint8_t* n, uint8_t len)
{
    memcpy(nonce, n, 16);
    return 0x00;
}

// 'a' - Receive Associated Data chunk (16 bytes at a time)
uint8_t get_ad(uint8_t* a, uint8_t len)
{
    uint16_t bytes_to_copy = ad_len - ad_received;
    if (bytes_to_copy > 16) {
        bytes_to_copy = 16;
    }
    
    if (bytes_to_copy > 0 && ad_received < MAX_BUFFER_SIZE) {
        memcpy(ad + ad_received, a, bytes_to_copy);
        ad_received += bytes_to_copy;
    }
    
    return 0x00;
}

uint8_t get_pt(uint8_t* p, uint8_t len)
{
    uint16_t bytes_to_copy = pt_len - pt_received;
    if (bytes_to_copy > 16) {
        bytes_to_copy = 16;
    }
    
    if (bytes_to_copy > 0 && pt_received < MAX_BUFFER_SIZE) {
        memcpy(pt + pt_received, p, bytes_to_copy);
        pt_received += bytes_to_copy;
    }
    
    if (pt_received >= pt_len) {
        uint8_t ct[MAX_BUFFER_SIZE + 16] = {0}; // CT + Tag
        unsigned long long clen;
        
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

        // Send back ciphertext + tag
        simpleserial_put('r', (uint8_t)clen, ct);
        
        // Reset for next encryption
        pt_received = 0;
        ad_received = 0;
    }
    
    return 0x00;
}

int main(void)
{
    platform_init();
    init_uart();
    trigger_setup();
    simpleserial_init();

    simpleserial_addcmd('k', 16, get_key);
    simpleserial_addcmd('n', 16, get_nonce);
    simpleserial_addcmd('a', 16, get_ad);
    simpleserial_addcmd('p', 16, get_pt);
    simpleserial_addcmd('l', 16, set_lengths);

    while(1)
        simpleserial_get();
}