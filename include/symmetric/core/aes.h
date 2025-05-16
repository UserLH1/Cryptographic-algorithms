#ifndef AES_CORE_H
#define AES_CORE_H

#include <stdint.h>
#include <stddef.h>

// AES parameters
#define AES_BLOCK_SIZE 16       // 128 bits
#define AES_KEY_SIZE   32       // 256 bits
#define AES_ROUND_KEYS 240      // 4*(Nr+1)*Nb = 4*(14+1)*4 = 240 bytes

typedef struct {
    uint8_t round_keys[AES_ROUND_KEYS];
} aes_context_t;

void aes_init(aes_context_t *ctx, const uint8_t *key, size_t key_size);
void aes_encrypt_block(const aes_context_t *ctx, const uint8_t in[16], uint8_t out[16]);
void aes_decrypt_block(const aes_context_t *ctx, const uint8_t in[16], uint8_t out[16]);

#endif // AES_CORE_H