#ifndef DES_CORE_H
#define DES_CORE_H

#include <stdint.h>
#include <stddef.h>

#define DES_BLOCK_SIZE 8    // 64 bits
#define DES_KEY_SIZE 8      // 64 bits (56 bits effective)

typedef struct {
    uint8_t subkeys[16][6]; // 16 subkeys for 16 rounds
} des_context_t;

void des_init(des_context_t *ctx, const uint8_t key[DES_KEY_SIZE]);
void des_encrypt_block(const des_context_t *ctx, const uint8_t in[8], uint8_t out[8]);
void des_decrypt_block(const des_context_t *ctx, const uint8_t in[8], uint8_t out[8]);

#endif // DES_CORE_H