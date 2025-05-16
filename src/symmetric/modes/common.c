#include "symmetric/modes/common.h"
#include <string.h>

/**
 * XORs src block with dest block, storing result in dest.
 * dest = dest ⊕ src
 */
void xor_blocks(uint8_t *dest, const uint8_t *src, size_t size)
{
    for (size_t i = 0; i < size; i++)
    {
        dest[i] ^= src[i];
    }
}

/**
 * Increments counter as a big-endian integer.
 * Used primarily in CTR mode.
 */
void increment_counter(uint8_t *counter, size_t size)
{
    int i = size - 1;

    // Increment from LSB (rightmost)
    while (i >= 0)
    {
        if (++counter[i] != 0)
        {
            // No carry, we're done
            break;
        }
        // Carry to next byte
        i--;
    }
}