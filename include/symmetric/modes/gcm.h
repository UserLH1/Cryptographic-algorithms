#ifndef GCM_MODE_H
#define GCM_MODE_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include "symmetric/modes/common.h"

// GCM parameters
#define GCM_IV_SIZE 12  // 96 bits nonce
#define GCM_TAG_SIZE 16 // 128 bits tag

int gcm_encrypt(const void *cipher_ctx,
                block_cipher_func encrypt_block,
                size_t block_size,
                const uint8_t *plaintext, size_t plaintext_len,
                uint8_t *ciphertext,
                const uint8_t *iv, size_t iv_len,
                const uint8_t *aad, size_t aad_len,
                uint8_t *tag, size_t tag_len);

int gcm_decrypt(const void *cipher_ctx,
                block_cipher_func encrypt_block,
                size_t block_size,
                const uint8_t *ciphertext, size_t ciphertext_len,
                uint8_t *plaintext,
                const uint8_t *iv, size_t iv_len,
                const uint8_t *aad, size_t aad_len,
                const uint8_t *tag, size_t tag_len);

int gcm_encrypt_file(const void *cipher_ctx,
                     block_cipher_func encrypt_block,
                     size_t block_size,
                     FILE *in_file, FILE *out_file,
                     const uint8_t *iv, size_t iv_len,
                     const uint8_t *aad, size_t aad_len);

int gcm_decrypt_file(const void *cipher_ctx,
                     block_cipher_func encrypt_block,
                     size_t block_size,
                     FILE *in_file, FILE *out_file,
                     const uint8_t *iv, size_t iv_len,
                     const uint8_t *aad, size_t aad_len);

#endif // GCM_MODE_H