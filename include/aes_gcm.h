// aes_gcm.h
#ifndef AES_GCM_H
#define AES_GCM_H

#include <stdint.h>
#include <stddef.h>

int aes_gcm_encrypt_file(
    const char* in_filename,
    const char* out_filename,
    const uint8_t* key,      // 256-bit key
    const uint8_t* iv,       // 96-bit IV (recomandat)
    const uint8_t* aad,      // Additional Auth Data (opțional)
    size_t aad_len
);

int aes_gcm_decrypt_file(
    const char* in_filename,
    const char* out_filename,
    const uint8_t* key,
    const uint8_t* iv,
    const uint8_t* aad,
    size_t aad_len
);

#endif
