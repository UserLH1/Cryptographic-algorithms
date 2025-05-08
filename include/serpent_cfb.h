// serpent_cfb.h
#ifndef SERPENT_CFB_H
#define SERPENT_CFB_H

#include <stdint.h>
#include <stddef.h>

int serpent_cfb_encrypt_file(
    const char* in_filename,
    const char* out_filename,
    const uint8_t* key,      
    size_t key_size_bits,    
    const uint8_t* iv        
);

int serpent_cfb_decrypt_file(
    const char* in_filename,
    const char* out_filename,
    const uint8_t* key,
    size_t key_size_bits,
    const uint8_t* iv
);

#endif
