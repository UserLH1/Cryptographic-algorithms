#ifndef CIPHER_MODES_COMMON_H
#define CIPHER_MODES_COMMON_H

#include <stdint.h>
#include <stddef.h>

// Function pointer type for block cipher operations
typedef void (*block_cipher_func)(const void *ctx, const uint8_t *in, uint8_t *out);

// Common operations
void xor_blocks(uint8_t *dest, const uint8_t *src, size_t size);
void increment_counter(uint8_t *counter, size_t size);

#endif // CIPHER_MODES_COMMON_H