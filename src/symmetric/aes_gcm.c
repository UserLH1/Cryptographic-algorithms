/* src/aes_gcm.c */

#include "aes_gcm.h"
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

/**
 * aes_encrypt_block: Criptează un bloc de 16 octeți folosind AES-256.
 * Proces:
 * 1) Copiază intrarea în matricea de stare.
 * 2) Runda inițială: AddRoundKey.
 * 3) 13 runde complete: SubBytes, ShiftRows, MixColumns, AddRoundKey.
 * 4) Runda finală: SubBytes, ShiftRows, AddRoundKey (fără MixColumns).
 * 5) Copiază starea în ieșire.
 * @param in Blocul de intrare (16 octeți).
 * @param out Blocul de ieșire (16 octeți).
 * @param round_keys Subcheile de rundă (240 octeți).
 */
void aes_encrypt_block(const uint8_t in[AES_BLOCK_SIZE],
                       uint8_t out[AES_BLOCK_SIZE],
                       const uint8_t round_keys[AES_ROUND_KEYS])
{
    uint8_t state[4][4];
    const int Nr = 14; // Număr de runde pentru AES-256

    // Copiază intrarea în matricea de stare (ordonare pe coloane)
    for (int i = 0; i < AES_BLOCK_SIZE; ++i)
    {
        state[i % 4][i / 4] = in[i];
    }

    // Runda inițială: doar AddRoundKey
    AddRoundKey(state, round_keys);

    // 13 runde complete
    for (int round = 1; round < Nr; ++round)
    {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, round_keys + round * AES_BLOCK_SIZE);
    }

    // Runda finală (fără MixColumns)
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, round_keys + Nr * AES_BLOCK_SIZE);

    // Copiază starea în ieșire
    for (int i = 0; i < AES_BLOCK_SIZE; ++i)
    {
        out[i] = state[i % 4][i / 4];
    }
}

/* ---------- GCM helpers ---------- */

/**
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

/**
 * aes_gcm_encrypt_file: Criptează un fișier folosind AES-GCM.
 * Proces:
 * 1) Expandează cheia.
 * 2) Calculează H = E_K(0^128).
 * 3) Construiește J0 = IV || 0^31 || 1.
 * 4) Criptează plaintext-ul în modul CTR (folosind counter incrementat).
 * 5) Calculează GHASH peste AAD și ciphertext.
 * 6) Generează tag-ul: E_K(J0) XOR GHASH.
 * 7) Scrie ciphertext-ul și tag-ul în fișierul de ieșire.
 * @param in_filename Fișierul de intrare (plaintext).
 * @param out_filename Fișierul de ieșire (ciphertext + tag).
 * @param key Cheia AES de 256 biți.
 * @param iv IV-ul de 96 biți (12 octeți).
 * @param aad Date adiționale autentificate.
 * @param aad_len Lungimea AAD în octeți.
 * @return 0 la succes, non-zero la eroare.
 */
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
    aes_encrypt_block(H, H, round_keys);

    // 3) Construiește J0 din IV
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
        aes_encrypt_block(counter, keystream, round_keys);
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
    aes_encrypt_block(J0, S_J0, round_keys);
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
 * aes_gcm_decrypt_file: Decriptează un fișier criptat cu AES-GCM și verifică tag-ul.
 * Proces:
 * 1) Citește tag-ul de la sfârșitul fișierului.
 * 2) Calculează GHASH peste AAD și ciphertext.
 * 3) Recalculează tag-ul și verifică cu cel primit.
 * 4) Dacă tag-ul e valid, decriptează ciphertext-ul în modul CTR.
 * @param in_filename Fișierul de intrare (ciphertext + tag).
 * @param out_filename Fișierul de ieșire (plaintext).
 * @param key Cheia AES de 256 biți.
 * @param iv IV-ul de 96 biți (12 octeți).
 * @param aad Date adiționale autentificate.
 * @param aad_len Lungimea AAD în octeți.
 * @return 0 la succes, non-zero la eroare sau tag invalid.
 */
int aes_gcm_decrypt_file(const char *in_filename,
                         const char *out_filename,
                         const uint8_t key[AES_KEY_SIZE],
                         const uint8_t iv[GCM_IV_SIZE],
                         const uint8_t *aad, size_t aad_len)
{
    FILE *fin_crypt = fopen(in_filename, "rb");
    if (!fin_crypt)
    {
        perror("Eroare la deschiderea fișierului criptat");
        return -1;
    }

    // Determină lungimea ciphertext-ului (fără tag)
    fseek(fin_crypt, 0, SEEK_END);
    long file_size = ftell(fin_crypt);
    if (file_size < GCM_TAG_SIZE)
    {
        fprintf(stderr, "Fișierul e mai mic decât tag-ul GCM.\n");
        fclose(fin_crypt);
        return -3;
    }
    uint64_t ciphertext_actual_len = file_size - GCM_TAG_SIZE;

    // Citește tag-ul
    uint8_t received_tag[GCM_TAG_SIZE];
    fseek(fin_crypt, (long)ciphertext_actual_len, SEEK_SET);
    if (fread(received_tag, 1, GCM_TAG_SIZE, fin_crypt) != GCM_TAG_SIZE)
    {
        perror("Eroare la citirea tag-ului");
        fclose(fin_crypt);
        return -3;
    }
    fseek(fin_crypt, 0, SEEK_SET);

    // Expandează cheia
    uint8_t round_keys[AES_ROUND_KEYS];
    aes_key_expansion(key, round_keys);

    // Calculează H
    uint8_t H[16] = {0};
    aes_encrypt_block(H, H, round_keys);

    // Construiește J0
    uint8_t J0[16];
    if (GCM_IV_SIZE != 12)
    {
        fprintf(stderr, "IV-ul trebuie să aibă 12 octeți.\n");
        fclose(fin_crypt);
        return -2;
    }
    memcpy(J0, iv, GCM_IV_SIZE);
    J0[12] = 0;
    J0[13] = 0;
    J0[14] = 0;
    J0[15] = 1;

    // Calculează GHASH
    uint8_t calculated_ghash_val[16];
    gcm_ghash_stream(H, aad, aad_len, fin_crypt, ciphertext_actual_len, calculated_ghash_val);
    fseek(fin_crypt, 0, SEEK_SET);

    // Recalculează tag-ul
    uint8_t S_J0[16];
    aes_encrypt_block(J0, S_J0, round_keys);
    uint8_t recalculated_tag[GCM_TAG_SIZE];
    for (int i = 0; i < GCM_TAG_SIZE; ++i)
    {
        recalculated_tag[i] = calculated_ghash_val[i] ^ S_J0[i];
    }

    // Verifică tag-ul
    if (memcmp(received_tag, recalculated_tag, GCM_TAG_SIZE) != 0)
    {
        fprintf(stderr, "Tag-ul nu se potrivește. Autentificare eșuată.\n");
        fclose(fin_crypt);
        return -4;
    }

    // Decriptează
    FILE *fout_plain = fopen(out_filename, "wb");
    if (!fout_plain)
    {
        perror("Eroare la deschiderea fișierului de ieșire");
        fclose(fin_crypt);
        return -1;
    }

    uint8_t counter[16], keystream[16], cipher_buf_chunk[AES_BLOCK_SIZE], plain_buf_chunk[AES_BLOCK_SIZE];
    uint64_t decrypted_len = 0;
    size_t n_read;

    memcpy(counter, J0, 16);
    for (int i = 15; i >= 12; --i)
    {
        if (++counter[i])
            break;
    }

    while (decrypted_len < ciphertext_actual_len)
    {
        size_t len_to_read = (ciphertext_actual_len - decrypted_len < AES_BLOCK_SIZE) ? (size_t)(ciphertext_actual_len - decrypted_len) : AES_BLOCK_SIZE;
        n_read = fread(cipher_buf_chunk, 1, len_to_read, fin_crypt);
        if (n_read != len_to_read)
        {
            perror("Eroare la citirea ciphertext-ului");
            fclose(fin_crypt);
            fclose(fout_plain);
            remove(out_filename);
            return -3;
        }

        aes_encrypt_block(counter, keystream, round_keys);
        for (size_t j = 0; j < n_read; ++j)
        {
            plain_buf_chunk[j] = cipher_buf_chunk[j] ^ keystream[j];
        }
        fwrite(plain_buf_chunk, 1, n_read, fout_plain);
        decrypted_len += n_read;

        if (n_read == AES_BLOCK_SIZE)
        {
            for (int i = 15; i >= 12; --i)
            {
                if (++counter[i])
                    break;
            }
        }
    }

    fclose(fin_crypt);
    fclose(fout_plain);
    return 0;
}

// Define the block_cipher_func type
typedef void (*block_cipher_func)(const uint8_t *in, uint8_t *out, const void *key_schedule);

/**
 * gcm_decrypt_file: Decriptează un fișier folosind GCM.
 * @param cipher_ctx Contextul cifrului.
 * @param encrypt_block Funcția de criptare a unui bloc.
 * @param block_size Dimensiunea blocului.
 * @param in_file Fișierul de intrare.
 * @param out_file Fișierul de ieșire.
 * @param iv IV-ul.
 * @param iv_len Lungimea IV-ului.
 * @param aad Date adiționale autentificate.
 * @param aad_len Lungimea AAD.
 * @return -1 (neimplementat).
 */
int gcm_decrypt_file(const void *cipher_ctx,
                     block_cipher_func encrypt_block,
                     size_t block_size,
                     FILE *in_file, FILE *out_file,
                     const uint8_t *iv, size_t iv_len,
                     const uint8_t *aad, size_t aad_len)
{
    // For now, implement a simple stub that returns error
    // (You can implement the full functionality later)
    return -1; // Not implemented yet
}