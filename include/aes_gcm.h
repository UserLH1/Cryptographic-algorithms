/* include/aes_gcm.h */
#ifndef AES_GCM_H
#define AES_GCM_H

#include <stdint.h>
#include <stddef.h>

// AES parameters
#define AES_BLOCK_SIZE 16       // 128 bits
#define AES_KEY_SIZE   32       // 256 bits
#define AES_ROUND_KEYS 240      // 4*(Nr+1)*Nb = 4*(14+1)*4 = 240 bytes

// GCM parameters
#define GCM_IV_SIZE    12       // 96 bits nonce
#define GCM_TAG_SIZE   16       // 128 bits tag

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Expand the 256-bit key into the round-keys array.
 *
 * @param key        32-byte input key
 * @param round_keys 240-byte output buffer for all round keys
 */
void aes_key_expansion(const uint8_t key[AES_KEY_SIZE],
                       uint8_t round_keys[AES_ROUND_KEYS]);

/**
 * Encrypt a single 16-byte block under AES-256.
 *
 * @param in         16-byte plaintext block
 * @param out        16-byte output buffer for ciphertext block
 * @param round_keys 240-byte expanded key schedule
 */
void aes_encrypt_block(const uint8_t in[AES_BLOCK_SIZE],
                       uint8_t out[AES_BLOCK_SIZE],
                       const uint8_t round_keys[AES_ROUND_KEYS]);

/**
 * GCM-encrypt a file.
 *
 * @param in_filename   path to plaintext input file
 * @param out_filename  path to ciphertext+tag output file
 * @param key           32-byte AES key
 * @param iv            12-byte GCM nonce
 * @param aad           pointer to Additional Authenticated Data
 * @param aad_len       length of AAD in bytes
 * @return 0 on success, non-zero on error
 */
int aes_gcm_encrypt_file(const char *in_filename,
                         const char *out_filename,
                         const uint8_t key[AES_KEY_SIZE],
                         const uint8_t iv[GCM_IV_SIZE],
                         const uint8_t *aad, size_t aad_len);

/**
 * GCM-decrypt a file and verify tag.
 *
 * @param in_filename   path to ciphertext+tag input file
 * @param out_filename  path to decrypted plaintext output file
 * @param key           32-byte AES key
 * @param iv            12-byte GCM nonce
 * @param aad           pointer to AAD
 * @param aad_len       length of AAD
 * @return 0 on success and tag OK, non-zero on error/tag mismatch
 */
int aes_gcm_decrypt_file(const char *in_filename,
                         const char *out_filename,
                         const uint8_t key[AES_KEY_SIZE],
                         const uint8_t iv[GCM_IV_SIZE],
                         const uint8_t *aad, size_t aad_len);

#ifdef __cplusplus
}
#endif

#endif // AES_GCM_H
