/* src/aes_gcm.c */
#include "aes_gcm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---------- AES core ---------- */

static const uint8_t s_box[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};


// Round constants for AES key expansion (Rcon[0] is unused)
static const uint8_t Rcon[15] = {
    0x00, // placeholder pentru index 0
    0x01, // 2^0
    0x02, // 2^1
    0x04, // 2^2
    0x08, // 2^3
    0x10, // 2^4
    0x20, // 2^5
    0x40, // 2^6
    0x80, // 2^7
    0x1B, // 2^8 mod 0x11B
    0x36, // 2^9 mod 0x11B
    0x6C, // 2^10
    0xD8, // 2^11
    0xAB, // 2^12
    0x4D  // 2^13
};


#include <stdint.h>
#include "aes_gcm.h"

// RotWord: rotește un cuvânt de 4 bytes la stânga cu un byte
static void RotWord(uint8_t *w) {
    uint8_t tmp = w[0];
    w[0] = w[1];
    w[1] = w[2];
    w[2] = w[3];
    w[3] = tmp;
}

// SubWord: aplică S-Box pe fiecare byte din word
static void SubWord(uint8_t *w) {
    extern const uint8_t s_box[256];
    for (int i = 0; i < 4; ++i) {
        w[i] = s_box[w[i]];
    }
}
//deci impartim cheia in 8 cuvinte si apoi interam prin ele si la feicare facem rot si sub word si facem xor cu constanta de runda si facem asta pana obtinem 60 cuvinte. 
void aes_key_expansion(const uint8_t key[AES_KEY_SIZE],
                       uint8_t round_keys[AES_ROUND_KEYS]) {
    // Nr de cuvinte în cheia extinsă: 4*(Nr+1) = 4*(14+1) = 60 words
    // Un word = 4 bytes → 60 * 4 = 240 bytes.
    const int Nk = 8;   // 256 biți / 32 biți per word = 8 words
    const int Nb = 4;   // numărul de coloane în state-ul AES
    const int Nr = 14;  // numărul de runde
    
    // 1) Copiem cheia inițială (primii 8 words)
    for (int i = 0; i < Nk * 4; ++i) {
        round_keys[i] = key[i];
    }

    uint8_t temp[4];
    int bytesGenerated = Nk * 4;  // câți bytes de round keys avem acum
    int rconIter = 1;

    // 2) Generăm restul de round keys până la 240 bytes
    while (bytesGenerated < (Nb * (Nr + 1) * 4)) {
        // Preluăm ultimele 4 bytes generate în temp
        for (int i = 0; i < 4; ++i) {
            temp[i] = round_keys[bytesGenerated - 4 + i];
        }

        // La fiecare Nk cuvinte (aici 8), aplicăm:
        // RotWord, SubWord, XOR cu Rcon
        if ((bytesGenerated / 4) % Nk == 0) {
            RotWord(temp);
            SubWord(temp);
            temp[0] ^= Rcon[rconIter++];
        }
        // Pentru AES-256, la mijloc de cheie (la cuvântul 4): doar SubWord
        else if ((bytesGenerated / 4) % Nk == 4) {
            SubWord(temp);
        }

        // XOR cu word-ul Nk cuvinte înainte
        for (int i = 0; i < 4; ++i) {
            round_keys[bytesGenerated] =
                round_keys[bytesGenerated - (Nk * 4)] ^ temp[i];
            bytesGenerated++;
        }
    }
}


void aes_encrypt_block(const uint8_t in[AES_BLOCK_SIZE],
                       uint8_t out[AES_BLOCK_SIZE],
                       const uint8_t round_keys[AES_ROUND_KEYS]) {
    uint8_t state[4][4];
    int round;

    // 1) Copy input into state matrix (column-major)
    for (int i = 0; i < AES_BLOCK_SIZE; ++i)
        state[i % 4][i / 4] = in[i];

    // 2) Initial AddRoundKey
    // TODO: xor state with round_keys[0..15]

    // 3) Nr-1 full rounds
    for (round = 1; round < 14; ++round) {
        // SubBytes
        // TODO: for each byte state[r][c] = s_box[state[r][c]];

        // ShiftRows
        // TODO: rotate each row r by r positions left

        // MixColumns
        // TODO: mix each column with GF(2^8) matrix mult

        // AddRoundKey
        // TODO: xor state with round_keys[round*16 .. (round+1)*16-1]
    }

    // 4) Final round (no MixColumns)
    // SubBytes
    // TODO

    // ShiftRows
    // TODO

    // AddRoundKey with final round key
    // TODO

    // 5) Copy state matrix to out[]
    for (int i = 0; i < AES_BLOCK_SIZE; ++i)
        out[i] = state[i % 4][i / 4];
}

/* ---------- GCM helpers ---------- */

// Multiply two 128-bit values in GF(2^128) using the GCM polynomial
static void gcm_galois_mult(const uint8_t X[16],
                            const uint8_t Y[16],
                            uint8_t product[16]) {
    // TODO: Implement bit-wise multiplication modulo x^128 + x^7 + x^2 + x + 1
}

// GHASH over AAD and ciphertext blocks
static void gcm_ghash(const uint8_t H[16],
                      const uint8_t *aad, size_t aad_len,
                      const uint8_t *C,   size_t C_len,
                      uint8_t tag[16]) {
    // TODO: Compute GHASH: X = ((...((0 ⊕ A1)·H ⊕ A2)·H ⊕ ... )·H ⊕ C1)·H ⊕ C2 ... ⊕ lengths
}

/* ---------- High-level GCM file routines ---------- */

int aes_gcm_encrypt_file(const char *in_filename,
                         const char *out_filename,
                         const uint8_t key[AES_KEY_SIZE],
                         const uint8_t iv[GCM_IV_SIZE],
                         const uint8_t *aad, size_t aad_len) {
    FILE *fin = fopen(in_filename, "rb");
    FILE *fout = fopen(out_filename, "wb");
    if (!fin || !fout) {
        perror("File open error");
        return -1;
    }

    // 1) Expand key
    uint8_t round_keys[AES_ROUND_KEYS];
    aes_key_expansion(key, round_keys);

    // 2) Compute hash subkey H = AES_encrypt(0^128, K)
    uint8_t H[16] = {0}, J0[16];
    aes_encrypt_block(H, H, round_keys);  // H = E_K(0^128)

    // 3) Prepare initial counter J0:
    //    if IV length = 12 bytes, J0 = IV || 0x00000001
    memcpy(J0, iv, GCM_IV_SIZE);
    J0[12] = J0[13] = J0[14] = 0;
    J0[15] = 1;

    // 4) Encrypt plaintext in CTR mode
    uint8_t counter[16], keystream[16], buf[4096];
    size_t n;
    uint64_t total_cipher_len = 0;
    memcpy(counter, J0, 16);

    while ((n = fread(buf, 1, sizeof(buf), fin)) > 0) {
        for (size_t block = 0; block < n; block += AES_BLOCK_SIZE) {
            size_t chunk = (n - block < AES_BLOCK_SIZE) ? (n - block) : AES_BLOCK_SIZE;
            // generate keystream block
            aes_encrypt_block(counter, keystream, round_keys);
            // increment counter (big-endian)
            for (int i = 15; i >= 12; --i) {
                if (++counter[i]) break;
            }
            // XOR plaintext → ciphertext
            for (size_t j = 0; j < chunk; ++j)
                buf[block + j] ^= keystream[j];
            total_cipher_len += chunk;
        }
        fwrite(buf, 1, n, fout);
    }

    // 5) Compute GHASH over AAD and ciphertext
    //    We need entire ciphertext: for large files, you'd buffer or re-read
    //    For simplicity, assume small or store in memory / adapt for streams
    //    TODO: handle large-file GHASH streaming

    uint8_t tag[GCM_TAG_SIZE];
    gcm_ghash(H, aad, aad_len, /* ciphertext ptr */ NULL, total_cipher_len, tag);

    // 6) Compute final tag: E_K(J0) ⊕ GHASH
    uint8_t S[16];
    aes_encrypt_block(J0, S, round_keys);
    for (int i = 0; i < GCM_TAG_SIZE; ++i)
        tag[i] ^= S[i];

    // 7) Write tag at end of file
    fwrite(tag, 1, GCM_TAG_SIZE, fout);

    fclose(fin);
    fclose(fout);
    return 0;
}

int aes_gcm_decrypt_file(const char *in_filename,
                         const char *out_filename,
                         const uint8_t key[AES_KEY_SIZE],
                         const uint8_t iv[GCM_IV_SIZE],
                         const uint8_t *aad, size_t aad_len) {
    // TODO: mirror encrypt_file but
    //  - read tag from end
    //  - stream decrypt ciphertext
    //  - recompute GHASH + final tag
    //  - compare tags → if mismatch, error
    return 0;
}
