#ifndef CFB_MODE_H
#define CFB_MODE_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include "symmetric/modes/common.h"

/**
 * Encrypt a file using CFB mode.
 * 
 * @param cipher_ctx Context for the block cipher
 * @param encrypt_block Function pointer to block encryption function
 * @param block_size Size of the cipher block in bytes
 * @param in_file Input file to encrypt
 * @param out_file Output file for encrypted data
 * @param iv Initialization Vector
 * @param iv_len Length of IV in bytes (must be equal to block_size)
 * @return 0 on success, non-zero on error
 */
int cfb_encrypt_file(const void *cipher_ctx,
                    block_cipher_func encrypt_block,
                    size_t block_size,
                    FILE *in_file, FILE *out_file,
                    const uint8_t *iv, size_t iv_len);

/**
 * Decrypt a file using CFB mode.
 * 
 * @param cipher_ctx Context for the block cipher
 * @param encrypt_block Function pointer to block encryption function
 * @param block_size Size of the cipher block in bytes
 * @param in_file Input file to decrypt
 * @param out_file Output file for decrypted data
 * @param iv Initialization Vector
 * @param iv_len Length of IV in bytes (must be equal to block_size)
 * @return 0 on success, non-zero on error
 */
int cfb_decrypt_file(const void *cipher_ctx,
                    block_cipher_func encrypt_block,
                    size_t block_size,
                    FILE *in_file, FILE *out_file,
                    const uint8_t *iv, size_t iv_len);

#endif // CFB_MODE_H