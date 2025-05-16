#include "symmetric/modes/gcm.h"
#include "symmetric/core/aes.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>/**
 * Constanta R pentru reducerea în câmpul Galois GF(2^128) în GCM.
 * Reprezintă polinomul x^128 + x^7 + x^2 + x + 1 (0xE1 urmat de 15 zerouri).
 * Folosită în înmulțirea GF(2^128) pentru reducerea rezultatului.
 */
static const uint8_t GCM_R_CONST[16] = {
    0xE1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

/**
 * gcm_galois_mult: Înmulțește doi vectori de 16 octeți în câmpul Galois GF(2^128).
 * Algoritm:
 * - Inițializează Z la 0 și V la Y.
 * - Pentru fiecare bit din X: dacă bitul e 1, Z = Z XOR V; apoi V = V >> 1.
 * - Dacă LSB-ul lui V era 1, V = V XOR R pentru reducere.
 * Folosit în GHASH pentru autentificarea GCM.
 * @param X Primul vector (16 octeți).
 * @param Y Al doilea vector (16 octeți).
 * @param product Rezultatul înmulțirii (16 octeți).
 */
static void gcm_galois_mult(const uint8_t X[16], const uint8_t Y[16], uint8_t product[16])
{
    uint8_t V[16];       // Copie a lui Y, shiftată și redusă
    uint8_t Z[16] = {0}; // Acumulatorul produsului

    memcpy(V, Y, 16); // V începe ca Y

    // Parcurge fiecare octet și bit din X
    for (int i = 0; i < 16; ++i)
    {
        for (int j = 0; j < 8; ++j)
        {
            // Dacă bitul curent din X este 1, adaugă V la Z
            if ((X[i] >> (7 - j)) & 1)
            {
                for (int k = 0; k < 16; ++k)
                {
                    Z[k] ^= V[k];
                }
            }

            // Shiftăm V la dreapta cu 1 bit
            uint8_t lsb_set = V[15] & 0x01;
            for (int k = 15; k > 0; --k)
            {
                V[k] = (V[k] >> 1) | (V[k - 1] << 7);
            }
            V[0] >>= 1;

            // Reducere cu R dacă LSB-ul era 1
            if (lsb_set)
            {
                V[0] ^= GCM_R_CONST[0]; // 0xE1
            }
        }
    }
    memcpy(product, Z, 16);
}

/**
 * gcm_ghash_stream: Calculează GHASH-ul pentru AAD și ciphertext.
 * Proces:
 * - Inițializează X la 0.
 * - Pentru fiecare bloc de 16 octeți din AAD și ciphertext: X = (X XOR bloc) * H.
 * - La final, X = (X XOR lungimi) * H, unde lungimile sunt len(AAD) || len(C) în biți.
 * @param H Subcheia de hash (E_K(0^128)).
 * @param aad Datele adiționale autentificate.
 * @param aad_len Lungimea AAD în octeți.
 * @param C_stream Fluxul de ciphertext (FILE*).
 * @param C_len Lungimea ciphertext-ului în octeți.
 * @param ghash_out Rezultatul GHASH (16 octeți).
 */
static void aes_encrypt_block_legacy(const uint8_t in[16],
                                     uint8_t out[16],
                                     const uint8_t round_keys[AES_ROUND_KEYS])
{
    // Create temporary context
    aes_context_t ctx;
    memcpy(ctx.round_keys, round_keys, AES_ROUND_KEYS);

    // Call new-style function
    aes_encrypt_block(&ctx, in, out);
}
void aes_key_expansion(const uint8_t key[AES_KEY_SIZE],
                       uint8_t round_keys[AES_ROUND_KEYS]);

static void gcm_ghash_stream(const uint8_t H[16],
                             const uint8_t *aad, size_t aad_len,
                             FILE *C_stream, uint64_t C_len,
                             uint8_t ghash_out[16])
{
    uint8_t current_block[16];
    memset(ghash_out, 0, 16); // X_0 = 0

    // Procesează AAD
    size_t offset = 0;
    while (offset < aad_len)
    {
        size_t len_to_process = (aad_len - offset < 16) ? (aad_len - offset) : 16;
        memcpy(current_block, aad + offset, len_to_process);
        if (len_to_process < 16)
        {
            memset(current_block + len_to_process, 0, 16 - len_to_process); // Padding cu zerouri
        }
        for (int i = 0; i < 16; ++i)
        {
            ghash_out[i] ^= current_block[i];
        }
        gcm_galois_mult(ghash_out, H, ghash_out);
        offset += len_to_process;
    }

    // Procesează ciphertext-ul din flux
    if (C_stream != NULL && C_len > 0)
    {
        long original_pos = ftell(C_stream);
        fseek(C_stream, 0, SEEK_SET);

        uint64_t C_processed_len = 0;
        size_t n_read;
        while (C_processed_len < C_len)
        {
            size_t len_to_read = (C_len - C_processed_len < 16) ? (size_t)(C_len - C_processed_len) : 16;
            n_read = fread(current_block, 1, len_to_read, C_stream);
            if (n_read != len_to_read)
            {
                perror("GHASH: Eroare la citirea ciphertext-ului");
                fseek(C_stream, original_pos, SEEK_SET);
                return;
            }
            if (n_read < 16)
            {
                memset(current_block + n_read, 0, 16 - n_read); // Padding ultimul bloc
            }
            for (int i = 0; i < 16; ++i)
            {
                ghash_out[i] ^= current_block[i];
            }
            gcm_galois_mult(ghash_out, H, ghash_out);
            C_processed_len += n_read;
        }
        fseek(C_stream, original_pos, SEEK_SET);
    }

    // Adaugă lungimile AAD și ciphertext (în biți, codate pe 64 biți big-endian)
    memset(current_block, 0, 16);
    uint64_t aad_len_bits = aad_len * 8;
    uint64_t C_len_bits = C_len * 8;
    for (int i = 0; i < 8; ++i)
    {
        current_block[7 - i] = (aad_len_bits >> (i * 8)) & 0xFF;
        current_block[15 - i] = (C_len_bits >> (i * 8)) & 0xFF;
    }
    for (int i = 0; i < 16; ++i)
    {
        ghash_out[i] ^= current_block[i];
    }
    gcm_galois_mult(ghash_out, H, ghash_out);
}

/* ---------- High-level GCM file routines ---------- */

int aes_gcm_encrypt_file(const char *in_filename,
                         const char *out_filename,
                         const uint8_t key[AES_KEY_SIZE],
                         const uint8_t iv[GCM_IV_SIZE],
                         const uint8_t *aad, size_t aad_len)
{
    FILE *fin = fopen(in_filename, "rb");
    if (!fin)
    {
        perror("Eroare la deschiderea fișierului de intrare");
        return -1;
    }
    FILE *fout = fopen(out_filename, "wb");
    if (!fout)
    {
        perror("Eroare la deschiderea fișierului de ieșire");
        fclose(fin);
        return -1;
    }

    // 1) Expandează cheia
    uint8_t round_keys[AES_ROUND_KEYS];
    aes_key_expansion(key, round_keys);

    // 2) Calculează H = E_K(0^128)
    uint8_t H[16] = {0};
    aes_encrypt_block_legacy(H, H, round_keys); // 3) Construiește J0 din IV
    uint8_t J0[16];
    if (GCM_IV_SIZE != 12)
    {
        fprintf(stderr, "IV-ul trebuie să aibă 12 octeți (96 biți).\n");
        fclose(fin);
        fclose(fout);
        return -2;
    }
    memcpy(J0, iv, GCM_IV_SIZE);
    J0[12] = 0;
    J0[13] = 0;
    J0[14] = 0;
    J0[15] = 1;

    // 4) Criptează în modul CTR
    uint8_t counter[16], keystream[16], plain_buf[AES_BLOCK_SIZE], cipher_buf_chunk[AES_BLOCK_SIZE];
    uint64_t total_cipher_len_bytes = 0;
    size_t n_read;

    memcpy(counter, J0, 16);
    // Incrementează counter pentru primul bloc de date (J0 e pentru tag)
    for (int i = 15; i >= 12; --i)
    {
        if (++counter[i])
            break;
    }

    while ((n_read = fread(plain_buf, 1, AES_BLOCK_SIZE, fin)) > 0)
    {
        aes_encrypt_block_legacy(counter, keystream, round_keys);
        for (size_t j = 0; j < n_read; ++j)
        {
            cipher_buf_chunk[j] = plain_buf[j] ^ keystream[j];
        }
        fwrite(cipher_buf_chunk, 1, n_read, fout);
        total_cipher_len_bytes += n_read;

        if (n_read == AES_BLOCK_SIZE)
        {
            for (int i = 15; i >= 12; --i)
            {
                if (++counter[i])
                    break;
            }
        }
    }
    fclose(fin);
    fclose(fout);

    // 5) Calculează GHASH
    FILE *f_cipher_for_ghash = fopen(out_filename, "rb");
    if (!f_cipher_for_ghash)
    {
        perror("Eroare la redeschiderea fișierului pentru GHASH");
        return -1;
    }
    uint8_t ghash_val[16];
    gcm_ghash_stream(H, aad, aad_len, f_cipher_for_ghash, total_cipher_len_bytes, ghash_val);
    fclose(f_cipher_for_ghash);

    // 6) Generează tag-ul
    uint8_t S_J0[16];
    aes_encrypt_block_legacy(J0, S_J0, round_keys);
    uint8_t final_tag[GCM_TAG_SIZE];
    for (int i = 0; i < GCM_TAG_SIZE; ++i)
    {
        final_tag[i] = ghash_val[i] ^ S_J0[i];
    }

    // 7) Adaugă tag-ul la fișier
    fout = fopen(out_filename, "ab");
    if (!fout)
    {
        perror("Eroare la adăugarea tag-ului");
        return -1;
    }
    fwrite(final_tag, 1, GCM_TAG_SIZE, fout);
    fclose(fout);

    return 0;
}

/**
 /**
 * GCM file encryption implementation
 */
int gcm_encrypt_file(const void *cipher_ctx,
                     block_cipher_func encrypt_block,
                     size_t block_size,
                     FILE *in_file, FILE *out_file,
                     const uint8_t *iv, size_t iv_len,
                     const uint8_t *aad, size_t aad_len)
{

    if (block_size != 16 || iv_len != GCM_IV_SIZE)
    {
        return -1; // Invalid parameters
    }

    // 1. Generate H = E_K(0^128)
    uint8_t H[16] = {0};
    encrypt_block(cipher_ctx, H, H);

    // 2. Create J0 = IV || 0^31 || 1
    uint8_t J0[16];
    memcpy(J0, iv, iv_len);
    memset(J0 + iv_len, 0, 16 - iv_len - 1);
    J0[15] = 1;

    // 3. Initialize counter = J0 + 1
    uint8_t counter[16];
    memcpy(counter, J0, 16);
    increment_counter(counter, 16);

    // 4. Encrypt using CTR mode
    uint8_t keystream[16];
    uint8_t buffer[16];

    size_t cipher_len = 0;

    // Create temporary file for ciphertext
    FILE *temp_file = tmpfile();
    if (!temp_file)
    {
        return -2; // Failed to create temp file
    }

    // Process all plaintext blocks
    while (!feof(in_file))
    {
        size_t read = fread(buffer, 1, 16, in_file);
        if (read == 0)
            break;

        // Zero remaining buffer if last block is partial
        if (read < 16)
        {
            memset(buffer + read, 0, 16 - read);
        }

        // Encrypt counter to get keystream
        encrypt_block(cipher_ctx, counter, keystream);

        // XOR plaintext with keystream
        for (size_t i = 0; i < read; i++)
        {
            buffer[i] ^= keystream[i];
        }

        // Write ciphertext to temporary file
        fwrite(buffer, 1, read, temp_file);
        cipher_len += read;

        // Increment counter
        increment_counter(counter, 16);
    }

    // 5. Calculate GHASH and tag
    uint8_t ghash[16];
    uint8_t tag[16];

    // Seek to beginning of temporary file
    fseek(temp_file, 0, SEEK_SET);

    // Calculate GHASH over AAD and ciphertext
    gcm_ghash_stream(H, aad, aad_len, temp_file, cipher_len, ghash);

    // Encrypt J0 to get auth key
    encrypt_block(cipher_ctx, J0, tag);

    // XOR GHASH with encrypted J0 to get tag
    xor_blocks(tag, ghash, 16);

    // 6. Write ciphertext followed by tag to output file
    // Rewind temp file
    fseek(temp_file, 0, SEEK_SET);

    // Copy ciphertext from temp file to output
    uint8_t copy_buffer[1024];
    size_t bytes_read;
    while ((bytes_read = fread(copy_buffer, 1, sizeof(copy_buffer), temp_file)) > 0)
    {
        fwrite(copy_buffer, 1, bytes_read, out_file);
    }

    // Write authentication tag
    fwrite(tag, 1, GCM_TAG_SIZE, out_file);

    // Close temporary file
    fclose(temp_file);

    return 0; // Success
}
int gcm_decrypt_file(const void *cipher_ctx,
                     block_cipher_func encrypt_block,
                     size_t block_size,
                     FILE *in_file, FILE *out_file,
                     const uint8_t *iv, size_t iv_len,
                     const uint8_t *aad, size_t aad_len)
{
    if (block_size != 16 || iv_len != GCM_IV_SIZE)
    {
        return -1; // Invalid parameters
    }

    // 1. Generate H = E_K(0^128)
    uint8_t H[16] = {0};
    encrypt_block(cipher_ctx, H, H);

    // 2. Determine file size and tag location
    long original_pos = ftell(in_file);
    fseek(in_file, 0, SEEK_END);
    long file_size = ftell(in_file);
    fseek(in_file, 0, SEEK_SET);

    if (file_size < GCM_TAG_SIZE)
    {
        return -1; // File too small
    }

    size_t ciphertext_len = file_size - GCM_TAG_SIZE;

    // 3. Read authentication tag
    uint8_t received_tag[GCM_TAG_SIZE];
    fseek(in_file, ciphertext_len, SEEK_SET);
    if (fread(received_tag, 1, GCM_TAG_SIZE, in_file) != GCM_TAG_SIZE)
    {
        return -1; // Failed to read tag
    }

    // 4. Reset to beginning to process ciphertext
    fseek(in_file, 0, SEEK_SET);

    // 5. Create J0 = IV || 0^31 || 1
    uint8_t J0[16];
    memcpy(J0, iv, iv_len);
    memset(J0 + iv_len, 0, 16 - iv_len - 1);
    J0[15] = 1;

    // 6. Calculate GHASH
    uint8_t ghash[16];
    gcm_ghash_stream(H, aad, aad_len, in_file, ciphertext_len, ghash);

    // 7. Calculate expected tag
    uint8_t expected_tag[16];
    encrypt_block(cipher_ctx, J0, expected_tag);
    xor_blocks(expected_tag, ghash, 16);

    // 8. Verify tag
    if (memcmp(received_tag, expected_tag, GCM_TAG_SIZE) != 0)
    {
        return -2; // Authentication failed
    }

    // 9. Decrypt ciphertext using CTR mode
    fseek(in_file, 0, SEEK_SET);

    uint8_t counter[16];
    memcpy(counter, J0, 16);
    increment_counter(counter, 16);

    uint8_t buffer[16], keystream[16];
    size_t remaining = ciphertext_len;

    while (remaining > 0)
    {
        size_t to_read = (remaining < 16) ? remaining : 16;
        size_t bytes_read = fread(buffer, 1, to_read, in_file);

        if (bytes_read <= 0)
            break;

        encrypt_block(cipher_ctx, counter, keystream);

        for (size_t i = 0; i < bytes_read; i++)
        {
            buffer[i] ^= keystream[i]; // Decrypt
        }

        fwrite(buffer, 1, bytes_read, out_file);

        increment_counter(counter, 16);
        remaining -= bytes_read;
    }

    return 0; // Success
}