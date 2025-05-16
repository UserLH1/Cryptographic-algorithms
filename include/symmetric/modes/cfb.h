#ifndef CFB_MODE_H
#define CFB_MODE_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include "symmetric/modes/common.h"

int cfb_encrypt(const void *cipher_ctx,
                block_cipher_func encrypt_block,
                size_t block_size,
                const uint8_t *plaintext, size_t plaintext_len,
                uint8_t *ciphertext,
                const uint8_t *iv);

int cfb_decrypt(const void *cipher_ctx,
                block_cipher_func encrypt_block,
                size_t block_size,
                const uint8_t *ciphertext, size_t ciphertext_len,
                uint8_t *plaintext,
                const uint8_t *iv);

int cfb_encrypt_file(const void *cipher_ctx,
                     block_cipher_func encrypt_block,
                     size_t block_size,
                     FILE *in_file, FILE *out_file,
                     const uint8_t *iv);

int cfb_decrypt_file(const void *cipher_ctx,
                     block_cipher_func encrypt_block,
                     size_t block_size,
                     FILE *in_file, FILE *out_file,
                     const uint8_t *iv);

#endif // CFB_MODE_H