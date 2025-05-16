#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h> // Pentru malloc/free, dacă ar fi necesar pentru teste interne
#include "symmetric/core/des.h"

// --- Tabele Standard DES ---

// Permutarea Inițială (IP)
static const uint8_t IP[64] = {
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7};

// Permutarea Finală (IP_INV)
static const uint8_t IP_INV[64] = {
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25};

// Tabelul de Expansiune (E) - extinde 32 biți la 48 biți
static const uint8_t E[48] = {
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1};

// Permutarea P - aplicată ieșirii S-Box-urilor
static const uint8_t P[32] = {
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25};

// S-Box-urile Standard DES (8 S-Box-uri, fiecare 6-biți intrare -> 4-biți ieșire)
// S_BOX[sbox_index][row_index][col_index]
static const uint8_t S_BOX[8][4][16] = {
    // S1
    {{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
     {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
     {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
     {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}},
    // S2
    {{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
     {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
     {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
     {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}},
    // S3
    {{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
     {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
     {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
     {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}},
    // S4
    {{7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
     {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
     {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
     {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}},
    // S5
    {{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
     {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
     {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
     {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}},
    // S6
    {{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
     {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
     {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
     {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}},
    // S7
    {{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
     {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
     {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
     {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}},
    // S8
    {{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
     {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
     {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
     {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}}};

// Permutare Cheie Comprimată 1 (PC-1)
// avem nevoie de array pt ca pe langa eliminarea bitilor de paritate facem o remapare
static const uint8_t PC1[56] = {
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4};

// Permutare Cheie Comprimată 2 (PC-2)
// la fel remapare si la 2
static const uint8_t PC2[48] = {
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32};

// Numărul de deplasări la stânga pentru C și D în generarea subcheilor
static const uint8_t LEFT_SHIFTS[16] = {
    1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

// --- Funcții Utilitare pentru Manipularea Biților ---

/**
 * @brief Aplică o permutare pe un bloc de biți.
 * Biții din `input` sunt selectați conform `table` și plasați în `output`.
 * `table` conține indicii biților din `input` (1-based).
 * `size` este numărul de biți din `output` (și numărul de intrări din `table`).
 */
static void permute_bits(const uint8_t *input, uint8_t *output, const uint8_t *table, int size)
{
    int output_byte_size = (size + 7) / 8;
    memset(output, 0, output_byte_size); // Inițializează output cu zero

    for (int i = 0; i < size; i++)
    {
        // `table[i]` este poziția bitului în input (1-based)
        int input_bit_pos = table[i] - 1; // Convertim la 0-based

        // Extragem bitul din input:
        // `input_bit_pos / 8` este indexul octetului
        // `7 - (input_bit_pos % 8)` este indexul bitului în octet (0=MSB, 7=LSB)
        if ((input[input_bit_pos / 8] >> (7 - (input_bit_pos % 8))) & 1)
        {
            // Setăm bitul corespunzător în output:
            // `i / 8` este indexul octetului în output
            // `7 - (i % 8)` este indexul bitului în octetul de output
            output[i / 8] |= (1 << (7 - (i % 8)));
        }
    }
}

/**
 * @brief Efectuează o operație XOR între două blocuri de octeți.
 */
static void xor_byte_arrays(const uint8_t *a, const uint8_t *b, uint8_t *result, int size_bytes)
{
    for (int i = 0; i < size_bytes; i++)
    {
        result[i] = a[i] ^ b[i];
    }
}

/**
 * @brief Deplasează circular la stânga o valoare de 28 de biți stocată într-un uint32_t.
 */
static uint32_t left_circular_shift_28(uint32_t value, int shifts)
{
    for (int i = 0; i < shifts; i++)
    {
        uint32_t msb = (value >> 27) & 1;  // Extragem bitul cel mai semnificativ din cei 28
        value = (value << 1) & 0x0FFFFFFF; // Deplasăm la stânga și mascam la 28 de biți
        value |= msb;                      // Adăugăm bitul MSB la sfârșit (LSB al celor 28 de biți)
    }
    return value;
}

// --- Generarea Subcheilor DES ---

/**
 * @brief Generează cele 16 subchei DES (K1...K16), fiecare de 48 de biți.
 */
static void generate_subkeys(const uint8_t raw_key[DES_KEY_SIZE], uint8_t subkeys[16][6])
{
    uint8_t permuted_key_56bit[7]; // 56 biți
    uint32_t C, D;                 // Registrele C și D, fiecare de 28 biți

    // 1. Aplică PC-1 cheii de 64 de biți pentru a obține 56 de biți
    permute_bits(raw_key, permuted_key_56bit, PC1, 56);

    // 2. Împarte cheia de 56 de biți în C0 și D0 (28 biți fiecare)
    // Stocăm C0 și D0 în uint32_t pentru manipulare ușoară a biților.
    // Biții sunt aranjați MSB-first în permuted_key_56bit.
    C = ((uint32_t)permuted_key_56bit[0] << 20) |
        ((uint32_t)permuted_key_56bit[1] << 12) |
        ((uint32_t)permuted_key_56bit[2] << 4) |
        ((uint32_t)permuted_key_56bit[3] >> 4); // Primii 28 de biți

    D = ((uint32_t)(permuted_key_56bit[3] & 0x0F) << 24) | // Ultimii 4 biți din octetul 3
        ((uint32_t)permuted_key_56bit[4] << 16) |
        ((uint32_t)permuted_key_56bit[5] << 8) |
        ((uint32_t)permuted_key_56bit[6]); // Următorii 28 de biți

    // 3. Generează cele 16 subchei
    uint8_t cd_combined_56bit[7]; // Pentru a stoca C_i și D_i concatenate (56 biți)
    for (int round = 0; round < 16; round++)
    {
        // a. Deplasează circular la stânga C și D
        C = left_circular_shift_28(C, LEFT_SHIFTS[round]);
        D = left_circular_shift_28(D, LEFT_SHIFTS[round]);

        // b. Concatenează C_i și D_i (rezultă 56 biți)
        // Convertim C și D înapoi într-un array de octeți
        cd_combined_56bit[0] = (C >> 20) & 0xFF;
        cd_combined_56bit[1] = (C >> 12) & 0xFF;
        cd_combined_56bit[2] = (C >> 4) & 0xFF;
        cd_combined_56bit[3] = ((C & 0x0F) << 4) | ((D >> 24) & 0x0F);
        cd_combined_56bit[4] = (D >> 16) & 0xFF;
        cd_combined_56bit[5] = (D >> 8) & 0xFF;
        cd_combined_56bit[6] = D & 0xFF;

        // c. Aplică PC-2 pentru a selecta 48 de biți și a forma subcheia K_i
        permute_bits(cd_combined_56bit, subkeys[round], PC2, 48);
    }
}

// --- Funcția Feistel (f-function) ---
/**
 * @brief Funcția Feistel f(R, K_i).
 * R: jumătatea dreaptă a blocului (32 biți).
 * K_i: subcheia rundei (48 biți).
 * output: rezultatul funcției f (32 biți).
 */
static void feistel_function(const uint8_t R_32bit[4], const uint8_t K_i_48bit[6], uint8_t output_32bit[4])
{
    uint8_t expanded_R_48bit[6];         // R extins la 48 biți
    uint8_t xor_result_48bit[6];         // Rezultatul (E(R) XOR K_i)
    uint8_t sbox_output_concat_32bit[4]; // Ieșirea concatenată a S-Box-urilor (32 biți)
    uint8_t current_sbox_input_6bit;
    uint8_t sbox_val_4bit;

    // 1. Expansiune (E): R (32 biți) -> expanded_R (48 biți)
    permute_bits(R_32bit, expanded_R_48bit, E, 48);

    // 2. XOR cu Subcheia: expanded_R_48bit XOR K_i_48bit
    xor_byte_arrays(expanded_R_48bit, K_i_48bit, xor_result_48bit, 6);

    // 3. Substiție (S-Box-uri)
    memset(sbox_output_concat_32bit, 0, 4);
    for (int i = 0; i < 8; i++)
    { // Pentru fiecare din cele 8 S-Box-uri
        // Extragem cei 6 biți pentru S-Box-ul curent din xor_result_48bit
        // Biții sunt indexați de la 0 la 47 în xor_result_48bit.
        // S-Box 'i' (0-7) folosește biții de la i*6 la i*6+5.

        int bit_offset = i * 6;
        current_sbox_input_6bit = 0;

        // Construim valoarea de 6 biți pentru S-Box (b5b4b3b2b1b0)
        for (int k = 0; k < 6; k++)
        {
            int actual_bit_pos = bit_offset + k;
            if ((xor_result_48bit[actual_bit_pos / 8] >> (7 - (actual_bit_pos % 8))) & 1)
            {
                current_sbox_input_6bit |= (1 << (5 - k)); // MSB al grupului de 6 biți este bitul 5
            }
        }

        // Determinăm rândul și coloana pentru S-Box
        // Rândul: bitul 1 (b5) și bitul 6 (b0) ale intrării de 6 biți
        uint8_t row = ((current_sbox_input_6bit >> 5) & 1) * 2 + (current_sbox_input_6bit & 1);
        // Coloana: biții 2, 3, 4, 5 (b4b3b2b1)
        uint8_t col = (current_sbox_input_6bit >> 1) & 0x0F;

        sbox_val_4bit = S_BOX[i][row][col] & 0x0F; // Luăm valoarea de 4 biți din S-Box

        // Plasează cei 4 biți de ieșire în sbox_output_concat_32bit
        // S-Box 'i' contribuie cu 4 biți la ieșirea de 32 de biți, de la bit_offset i*4.
        int output_32_bit_offset = i * 4;
        for (int k = 0; k < 4; k++)
        { // Pentru fiecare din cei 4 biți de ieșire ai S-Box-ului
            if ((sbox_val_4bit >> (3 - k)) & 1)
            { // Verificăm bitul k (0-3, MSB-first)
                sbox_output_concat_32bit[(output_32_bit_offset + k) / 8] |= (1 << (7 - ((output_32_bit_offset + k) % 8)));
            }
        }
    }

    // 4. Permutare (P): sbox_output_concat_32bit -> output_32bit
    permute_bits(sbox_output_concat_32bit, output_32bit, P, 32);
}
static void des_encrypt_block_internal(const uint8_t subkeys[16][6],
                                       const uint8_t plaintext_block[DES_BLOCK_SIZE],
                                       uint8_t ciphertext_block[DES_BLOCK_SIZE])
{
    uint8_t permuted_input[8];
    uint8_t L[4], R[4];
    uint8_t temp_L[4];
    uint8_t feistel_output[4];

    // 1. Initial Permutation (IP)
    permute_bits(plaintext_block, permuted_input, IP, 64);

    // 2. Split into L0 and R0
    memcpy(L, permuted_input, 4);
    memcpy(R, permuted_input + 4, 4);

    // 3. 16 Feistel rounds
    for (int round = 0; round < 16; round++)
    {
        memcpy(temp_L, L, 4);

        // L_i = R_{i-1}
        memcpy(L, R, 4);

        // Calculate f(R_{i-1}, K_i)
        feistel_function(R, subkeys[round], feistel_output);

        // R_i = L_{i-1} XOR f(R_{i-1}, K_i)
        xor_byte_arrays(temp_L, feistel_output, R, 4);
    }

    // 4. Concatenate L16 and R16
    uint8_t final_block_before_fp[8];
    memcpy(final_block_before_fp, L, 4);
    memcpy(final_block_before_fp + 4, R, 4);

    // 5. Final Permutation (IP_INV)
    permute_bits(final_block_before_fp, ciphertext_block, IP_INV, 64);
}

// --- Public API implementations ---

void des_init(des_context_t *ctx, const uint8_t key[DES_KEY_SIZE])
{
    generate_subkeys(key, ctx->subkeys);
}

void des_encrypt_block(const des_context_t *ctx, const uint8_t in[DES_BLOCK_SIZE], uint8_t out[DES_BLOCK_SIZE])
{
    des_encrypt_block_internal(ctx->subkeys, in, out);
}

void des_decrypt_block(const des_context_t *ctx, const uint8_t in[DES_BLOCK_SIZE], uint8_t out[DES_BLOCK_SIZE])
{
    // For DES decryption, we use the same algorithm but with subkeys in reverse order
    uint8_t reverse_subkeys[16][6];

    // Copy subkeys in reverse order
    for (int i = 0; i < 16; i++)
    {
        memcpy(reverse_subkeys[i], ctx->subkeys[15 - i], 6);
    }

    des_encrypt_block_internal(reverse_subkeys, in, out);
}