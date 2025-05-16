#include "symmetric/modes/cfb.h"
#include "symmetric/modes/common.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/**
 * Encrypts a file using Cipher Feedback (CFB) mode.
 */
int cfb_encrypt_file(const void *cipher_ctx,
                     block_cipher_func encrypt_block,
                     size_t block_size,
                     FILE *in_file, FILE *out_file,
                     const uint8_t *iv, size_t iv_len)
{
    if (iv_len != block_size)
    {
        return -1; // IV size must equal block size
    }

    uint8_t *plaintext_buffer = malloc(block_size);
    uint8_t *ciphertext_buffer = malloc(block_size);
    uint8_t *shift_register = malloc(block_size);
    uint8_t *encrypted_shift_reg = malloc(block_size);

    if (!plaintext_buffer || !ciphertext_buffer || !shift_register || !encrypted_shift_reg)
    {
        free(plaintext_buffer);
        free(ciphertext_buffer);
        free(shift_register);
        free(encrypted_shift_reg);
        return -2; // Memory allocation failed
    }

    // Initialize shift register with IV
    memcpy(shift_register, iv, block_size);

    size_t bytes_read;
    int result = 0;

    while ((bytes_read = fread(plaintext_buffer, 1, block_size, in_file)) > 0)
    {
        // 1. Encrypt the shift register
        encrypt_block(cipher_ctx, shift_register, encrypted_shift_reg);

        // 2. XOR with plaintext (only for bytes_read bytes)
        for (size_t i = 0; i < bytes_read; i++)
        {
            ciphertext_buffer[i] = plaintext_buffer[i] ^ encrypted_shift_reg[i];
        }

        // 3. Write the ciphertext
        if (fwrite(ciphertext_buffer, 1, bytes_read, out_file) != bytes_read)
        {
            result = -3; // Write error
            break;
        }

        // 4. Update shift register with ciphertext
        if (bytes_read == block_size)
        {
            memcpy(shift_register, ciphertext_buffer, block_size);
        }
        else
        {
            // For partial blocks, pad with zeros
            memset(shift_register, 0, block_size);
            memcpy(shift_register, ciphertext_buffer, bytes_read);
        }
    }

    if (ferror(in_file))
    {
        result = -4; // Read error
    }

    free(plaintext_buffer);
    free(ciphertext_buffer);
    free(shift_register);
    free(encrypted_shift_reg);

    return result;
}

/**
 * Decrypts a file using Cipher Feedback (CFB) mode.
 */
int cfb_decrypt_file(const void *cipher_ctx,
                     block_cipher_func encrypt_block,
                     size_t block_size,
                     FILE *in_file, FILE *out_file,
                     const uint8_t *iv, size_t iv_len)
{
    if (iv_len != block_size)
    {
        return -1; // IV size must equal block size
    }

    uint8_t *ciphertext_buffer = malloc(block_size);
    uint8_t *plaintext_buffer = malloc(block_size);
    uint8_t *shift_register = malloc(block_size);
    uint8_t *encrypted_shift_reg = malloc(block_size);
    uint8_t *feedback_buffer = malloc(block_size);

    if (!ciphertext_buffer || !plaintext_buffer || !shift_register ||
        !encrypted_shift_reg || !feedback_buffer)
    {
        free(ciphertext_buffer);
        free(plaintext_buffer);
        free(shift_register);
        free(encrypted_shift_reg);
        free(feedback_buffer);
        return -2; // Memory allocation failed
    }

    // Initialize shift register with IV
    memcpy(shift_register, iv, block_size);

    size_t bytes_read;
    int result = 0;

    while ((bytes_read = fread(ciphertext_buffer, 1, block_size, in_file)) > 0)
    {
        // Save ciphertext for next iteration's feedback
        memset(feedback_buffer, 0, block_size);
        memcpy(feedback_buffer, ciphertext_buffer, bytes_read);

        // 1. Encrypt the shift register
        encrypt_block(cipher_ctx, shift_register, encrypted_shift_reg);

        // 2. XOR with ciphertext to get plaintext
        for (size_t i = 0; i < bytes_read; i++)
        {
            plaintext_buffer[i] = ciphertext_buffer[i] ^ encrypted_shift_reg[i];
        }

        // 3. Write the plaintext
        if (fwrite(plaintext_buffer, 1, bytes_read, out_file) != bytes_read)
        {
            result = -3; // Write error
            break;
        }

        // 4. Update shift register with ciphertext
        memcpy(shift_register, feedback_buffer, block_size);
    }

    if (ferror(in_file))
    {
        result = -4; // Read error
    }

    free(ciphertext_buffer);
    free(plaintext_buffer);
    free(shift_register);
    free(encrypted_shift_reg);
    free(feedback_buffer);

    return result;
}