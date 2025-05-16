#ifndef DES_CORE_H
#define DES_CORE_H

#include <stdint.h>
#include <stddef.h>

// DES parameters
#define DES_BLOCK_SIZE 8 // 64 bits
#define DES_KEY_SIZE 8   // 64 bits (56 effective bits + 8 parity bits)

typedef struct
{
    uint8_t subkeys[16][6]; // 16 subkeys of 48 bits each
} des_context_t;

/**
 * Initialize DES context with the given key
 */
void des_init(des_context_t *ctx, const uint8_t key[DES_KEY_SIZE]);

/**
 * Encrypt a single block using DES
 */
void des_encrypt_block(const des_context_t *ctx, const uint8_t in[DES_BLOCK_SIZE], uint8_t out[DES_BLOCK_SIZE]);

/**
 * Decrypt a single block using DES
 */
void des_decrypt_block(const des_context_t *ctx, const uint8_t in[DES_BLOCK_SIZE], uint8_t out[DES_BLOCK_SIZE]);

#endif // DES_CORE_H