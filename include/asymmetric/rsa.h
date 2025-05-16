#ifndef RSA_GMP_H
#define RSA_GMP_H

#include <stdint.h>
#include <stddef.h>

#define RSA_PKCS1_V15_ENCRYPT_OVERHEAD 11

/**
 * @brief Calculeaza dimensiunea maxima a plaintext-ului care poate fi criptat
 * cu o cheie RSA de 'bits' biti folosind padding PKCS#1 v1.5.
 * @param bits Lungimea cheii in biți.
 * @return Dimensiunea maxima a plaintext-ului in bytes.
 */
size_t rsa_pkcs1_v15_max_plaintext_size(size_t bits);

/**
 * @brief Calculeaza dimensiunea in bytes a modulului N pentru o cheie RSA de 'bits' biti.
 * Aceasta este si dimensiunea ciphertext-ului rezultat.
 * @param bits Lungimea cheii in biți.
 * @return Dimensiunea modulului/ciphertext-ului in bytes.
 */
size_t rsa_modulus_size_bytes(size_t bits);

// --- Functii RSA (Implementare cu GMP) ---

/**
 * @brief Generează o pereche de chei RSA (publică si privată) utilizand GMP.
 * Cheile sunt salvate in fisiere intr-un format binar simplu (lungime + bytes).
 *
 * @param bits Lungimea cheii in biti (minim 1024).
 * @param public_key_file Calea catre fisierul unde se salveaza cheia publica (N si E).
 * @param private_key_file Calea catre fisierul unde se salveaza cheia privata (N si D).
 * @return 0 in caz de succes, un cod de eroare negativ in caz de esec.
 */
int rsa_generate_keys_gmp(int bits, const char *public_key_file, const char *private_key_file);

/**
 * @brief Cripteaza un bloc de date folosind cheia publica RSA si padding PKCS#1 v1.5, utilizand GMP.
 *
 * @param plaintext Buffer-ul cu datele de criptat (dimensiune <= rsa_pkcs1_v15_max_plaintext_size(bits)).
 * @param plaintext_len Lungimea datelor de criptat.
 * @param ciphertext Buffer-ul unde se scrie textul cifrat (dimensiunea == rsa_modulus_size_bytes(bits)).
 * @param ciphertext_len Pointer catre o variabila unde se scrie lungimea textului cifrat (va fi rsa_modulus_size_bytes(bits)).
 * @param public_key_file Calea catre fisierul cu cheia publica (N si E).
 * @param bits Lungimea cheii in biti.
 * @return 0 in caz de succes, un cod de eroare negativ in caz de esec (inclusiv erori de padding sau dimensiune).
 */
int rsa_public_encrypt_block_gmp(const uint8_t *plaintext, size_t plaintext_len, uint8_t *ciphertext, size_t *ciphertext_len, const char *public_key_file, int bits);

/**
 * @brief Decripteaza un bloc de text cifrat folosind cheia privata RSA si padding PKCS#1 v1.5, utilizand GMP.
 *
 * @param ciphertext Buffer-ul cu textul cifrat de decriptat (dimensiunea == rsa_modulus_size_bytes(bits)).
 * @param ciphertext_len Lungimea textului cifrat (trebuie sa fie rsa_modulus_size_bytes(bits)).
 * @param plaintext Buffer-ul unde se scrie textul decriptat (dimensiune >= rsa_pkcs1_v15_max_plaintext_size(bits)).
 * @param plaintext_len Pointer catre o variabila unde se scrie lungimea textului decriptat.
 * @param private_key_file Calea catre fisierul cu cheia privata (N si D).
 * @param bits Lungimea cheii in biti.
 * @return 0 in caz de succes, un cod de eroare negativ in caz de esec (inclusiv erori de unpadding/padding invalid).
 */
int rsa_private_decrypt_block_gmp(const uint8_t *ciphertext, size_t ciphertext_len, uint8_t *plaintext, size_t *plaintext_len, const char *private_key_file, int bits);

/**
 * @brief Cripteaza un fisier folosind cheia publica RSA si padding PKCS#1 v1.5, utilizand GMP.
 *
 * @param input_file Calea catre fisierul de intrare care trebuie criptat.
 * @param output_file Calea catre fisierul de iesire unde se salveaza textul cifrat.
 * @param public_key_file Calea catre fisierul cu cheia publica (N si E).
 * @param bits Lungimea cheii in biti.
 * @return 0 in caz de succes, un cod de eroare negativ in caz de esec.
 */
int rsa_encrypt_file_gmp(const char *input_file, const char *output_file,
                         const char *public_key_file, int bits);

/**
 * @brief Decripteaza un fisier folosind cheia privata RSA si padding PKCS#1 v1.5, utilizand GMP.
 *
 * @param input_file Calea catre fisierul de intrare care trebuie decriptat.
 * @param output_file Calea catre fisierul de iesire unde se salveaza textul decriptat.
 * @param private_key_file Calea catre fisierul cu cheia privata (N si D).
 * @param bits Lungimea cheii in biti.
 * @return 0 in caz de succes, un cod de eroare negativ in caz de esec.
 */
int rsa_decrypt_file_gmp(const char *input_file, const char *output_file,
                         const char *private_key_file, int bits);

#endif // RSA_GMP_H