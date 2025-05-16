/* src/aes_gcm.c */

#include "../../../include/symmetric/core/aes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---------- AES core ---------- */

/**
 * S-box-ul AES: O matrice de 256 de intrări utilizată pentru a înlocui octetii în SubBytes.
 * Fiecare octet este înlocuit cu valoarea corespunzătoare din S-box (16x16 valori posibile).
 */
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
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

/**
 * Constanta de rundă (Rcon) pentru expansiunea cheii AES.
 * Aceste valori sunt utilizate pentru generarea subcheilor în fiecare rundă.
 * Rcon[0] este un placeholder nefolosit, valorile reale încep de la Rcon[1].
 */
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

/**
 * RotWord: Rotește un cuvânt de 4 octeți la stânga cu un octet.
 * Exemplu: [a0, a1, a2, a3] devine [a1, a2, a3, a0].
 * Folosit în expansiunea cheii pentru a varia subcheile.
 */
static void RotWord(uint8_t *w)
{
    uint8_t tmp = w[0];
    w[0] = w[1];
    w[1] = w[2];
    w[2] = w[3];
    w[3] = tmp;
}

/**
 * SubWord: Aplică S-box-ul pe fiecare octet al unui cuvânt de 4 octeți.
 * Înlocuiește fiecare octet cu valoarea corespunzătoare din S-box.
 * Folosit în expansiunea cheii pentru a introduce neliniaritate.
 */
static void SubWord(uint8_t *w)
{
    for (int i = 0; i < 4; ++i)
    {
        w[i] = s_box[w[i]];
    }
}

/**
 * aes_key_expansion: Generează subcheile de rundă din cheia inițială AES-256.
 * Împarte cheia în 8 cuvinte de 4 octeți, apoi generează 60 de cuvinte (240 octeți) în total.
 * 60 cuvinte = 15 subchei a câte 16 octeți (4x4), una pentru fiecare rundă + runda inițială.
 * @param key Cheia inițială de 32 octeți (256 biți).
 * @param round_keys Buffer de 240 octeți pentru subcheile generate.
 */
void aes_key_expansion(const uint8_t key[AES_KEY_SIZE],
                       uint8_t round_keys[AES_ROUND_KEYS])
{
    const int Nk = AES_KEY_SIZE / 4;                       // 8 pentru AES-256 (256 biți / 32 biți per cuvânt)
    const int Nb = AES_BLOCK_SIZE / 4;                     // 4 (blocuri de 16 octeți = 4 coloane)
    const int Nr = (Nk == 8) ? 14 : ((Nk == 6) ? 12 : 10); // 14 runde pentru AES-256

    // Copiază cheia inițială în round_keys (primii 32 octeți)
    memcpy(round_keys, key, AES_KEY_SIZE);

    uint8_t temp[4];
    int bytesGenerated = AES_KEY_SIZE; // Numără octeții generați (începe cu 32)
    int rconIter = 1;                  // Indice pentru Rcon

    // Generează restul subcheilor până la 240 octeți
    while (bytesGenerated < (Nb * (Nr + 1) * 4))
    {
        // Copiază ultimul cuvânt generat în temp
        for (int i = 0; i < 4; ++i)
        {
            temp[i] = round_keys[bytesGenerated - 4 + i];
        }

        // La fiecare al 8-lea cuvânt, aplică RotWord, SubWord și XOR cu Rcon
        if ((bytesGenerated / 4) % Nk == 0)
        {
            RotWord(temp);
            SubWord(temp);
            temp[0] ^= Rcon[rconIter++];
        }
        // Pentru AES-256, la cuvântul 4 al fiecărui set, aplică doar SubWord
        else if (Nk > 6 && (bytesGenerated / 4) % Nk == 4)
        {
            SubWord(temp);
        }

        // XOR cu cuvântul de la poziția anterioară (Nk cuvinte înapoi)
        for (int i = 0; i < 4; ++i)
        {
            round_keys[bytesGenerated] =
                round_keys[bytesGenerated - (Nk * 4)] ^ temp[i];
            bytesGenerated++;
        }
    }
}

/**
 * xtime: Înmulțește un octet cu 2 în câmpul Galois GF(2^8).
 * Dacă rezultatul depășește 255, aplică reducerea cu polinomul 0x1B.
 * Folosit în MixColumns pentru operații în GF(2^8).
 */
static uint8_t xtime(uint8_t x)
{
    return (x & 0x80) ? ((x << 1) ^ 0x1B) : (x << 1);
}

/**
 * mul2: Înmulțește un octet cu 2 în GF(2^8).
 * Wrapper peste xtime pentru claritate.
 */
static uint8_t mul2(uint8_t x) { return xtime(x); }

/**
 * mul3: Înmulțește un octet cu 3 în GF(2^8).
 * Calculat ca x * (2 + 1) = x*2 XOR x.
 */
static uint8_t mul3(uint8_t x) { return xtime(x) ^ x; }

/**
 * AddRoundKey: Aplică XOR între starea curentă și subcheia de rundă.
 * În AES, lucrăm cu blocuri de 16 octeți (4x4 matrice).
 * Facem XOR între fiecare octet al stării și subcheia curentă.
 * @param state Matricea 4x4 a stării.
 * @param roundKey Subcheia de rundă (16 octeți).
 */
static void AddRoundKey(uint8_t state[4][4], const uint8_t *roundKey)
{
    for (int r = 0; r < 4; ++r)
    {
        for (int c = 0; c < 4; ++c)
        {
            state[r][c] ^= roundKey[c * 4 + r];
        }
    }
}

/**
 * SubBytes: Înlocuiește fiecare octet din stare cu valoarea din S-box.
 * Luăm fiecare bloc de 16 octeți și înlocuim fiecare octet conform S-box.
 * S-box are 256 valori (16x16), acoperind toate combinațiile posibile de 8 biți.
 */
static void SubBytes(uint8_t state[4][4])
{
    for (int r = 0; r < 4; ++r)
    {
        for (int c = 0; c < 4; ++c)
        {
            state[r][c] = s_box[state[r][c]];
        }
    }
}

/**
 * ShiftRows: Shiftează circular rândurile matricei de stare la stânga.
 * - Rândul 0: neschimbat
 * - Rândul 1: shift cu 1 poziție
 * - Rândul 2: shift cu 2 poziții
 * - Rândul 3: shift cu 3 poziții
 */
static void ShiftRows(uint8_t state[4][4])
{
    uint8_t tmp;
    // Rândul 1: shift cu 1 poziție la stânga
    tmp = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = tmp;
    // Rândul 2: shift cu 2 poziții la stânga
    tmp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = tmp;
    tmp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = tmp;
    // Rândul 3: shift cu 3 poziții la stânga (echiv. 1 la dreapta)
    tmp = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = state[3][0];
    state[3][0] = tmp;
}

/**
 * MixColumns: Transformă fiecare coloană a stării în GF(2^8).
 * Fiecare element al coloanei este înmulțit cu o constantă și rezultatele sunt combinate cu XOR.
 * Exemplu: s0' = (2 * s0) XOR (3 * s1) XOR s2 XOR s3
 */
static void MixColumns(uint8_t state[4][4])
{
    for (int c = 0; c < 4; ++c)
    {
        uint8_t a0 = state[0][c], a1 = state[1][c], a2 = state[2][c], a3 = state[3][c];
        state[0][c] = mul2(a0) ^ mul3(a1) ^ a2 ^ a3;
        state[1][c] = a0 ^ mul2(a1) ^ mul3(a2) ^ a3;
        state[2][c] = a0 ^ a1 ^ mul2(a2) ^ mul3(a3);
        state[3][c] = mul3(a0) ^ a1 ^ a2 ^ mul2(a3);
    }
}
void aes_init(aes_context_t *ctx, const uint8_t *key, size_t key_size)
{
    if (key_size != AES_KEY_SIZE)
    {
        // Handle error - we only support AES-256 for now
        memset(ctx->round_keys, 0, AES_ROUND_KEYS);
        return;
    }

    aes_key_expansion(key, ctx->round_keys);
}

void aes_encrypt_block(const aes_context_t *ctx, const uint8_t in[16], uint8_t out[16])
{
    uint8_t state[4][4];
    const int Nr = 14; // AES-256 has 14 rounds

    // Load input into state array (column-major order)
    for (int i = 0; i < AES_BLOCK_SIZE; ++i)
    {
        state[i % 4][i / 4] = in[i];
    }

    // Initial AddRoundKey
    AddRoundKey(state, ctx->round_keys);

    // Main rounds
    for (int round = 1; round < Nr; ++round)
    {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, ctx->round_keys + round * AES_BLOCK_SIZE);
    }

    // Final round (no MixColumns)
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, ctx->round_keys + Nr * AES_BLOCK_SIZE);

    // Store result back to output
    for (int i = 0; i < AES_BLOCK_SIZE; ++i)
    {
        out[i] = state[i % 4][i / 4];
    }
}

void aes_decrypt_block(const aes_context_t *ctx, const uint8_t in[16], uint8_t out[16])
{
    // AES decryption is not implemented yet
    // This would use InvSubBytes, InvShiftRows, InvMixColumns
    // For GCM, we only need encryption as it's used in CTR mode
    memset(out, 0, 16); // Placeholder
}