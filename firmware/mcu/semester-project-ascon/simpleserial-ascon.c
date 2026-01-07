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

ascon_state_t base_state;
uint64_t saved_K0, saved_K1;
// 'k' - Set Key (16 bytes)
uint8_t get_key(uint8_t* k, uint8_t len)
{
    saved_K0 = load_word(k, 8);
    saved_K1 = load_word(k + 8, 8);
    
    base_state.x[0] = ASCON_128A_IV;
    base_state.x[1] = saved_K0;
    base_state.x[2] = saved_K1;
    
    return 0x00;
}

uint8_t get_nonce(uint8_t* n, uint8_t len) {
    // Copy the pre-calculated base state
    ascon_state_t s = base_state;
    
    // Load the fresh nonce
    s.x[3] = load_word(n, 8);
    s.x[4] = load_word(n + 8, 8);

    trigger_high();
    
    // Running 12 rounds is 12x slower and adds no value to the leakage of Round 1.
    ascon_round(&s, ASCON_RC[0]); 
    
    trigger_low();

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