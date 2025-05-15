/* include/des_cfb.h */
#ifndef DES_CFB_H
#define DES_CFB_H

#include <stdint.h> // Pentru tipuri de date intregi cu dimensiune fixa, ex: uint8_t
#include <stddef.h> // Pentru tipul size_t

// Dimensiunea cheii DES în octeți (64 de biți, din care 56 sunt efectivi)
#define DES_KEY_SIZE 8

// Dimensiunea blocului DES în octeți (64 de biți)
#define DES_BLOCK_SIZE 8

#ifdef __cplusplus // Constructie pentru compatibilitate cu C++
extern "C"
{
#endif

    /**
     * @brief Criptează un fișier utilizând algoritmul DES în modul de operare CFB.
     *
     * Această funcție citește conținutul fișierului de intrare, îl criptează
     * bloc cu bloc folosind DES-CFB și scrie rezultatul în fișierul de ieșire.
     *
     * @param in_filename   Calea către fișierul de intrare (text clar).
     * @param out_filename  Calea către fișierul de ieșire (text cifrat).
     * @param key           Cheia DES de 8 octeți (64 de biți).
     * @param iv            Vectorul de inițializare (IV) de 8 octeți (64 de biți).
     * @return 0 în caz de succes, o valoare non-zero în caz de eroare.
     */
    int des_cfb_encrypt_file(const char *in_filename,
                             const char *out_filename,
                             const uint8_t key[DES_KEY_SIZE],
                             const uint8_t iv[DES_BLOCK_SIZE]);

    /**
     * @brief Decriptează un fișier criptat cu DES în modul de operare CFB.
     *
     * Această funcție citește conținutul fișierului de intrare (text cifrat),
     * îl decriptează bloc cu bloc folosind DES-CFB și scrie rezultatul
     * (textul clar original) în fișierul de ieșire.
     *
     * @param in_filename   Calea către fișierul de intrare (text cifrat).
     * @param out_filename  Calea către fișierul de ieșire (text clar).
     * @param key           Cheia DES de 8 octeți (64 de biți) utilizată pentru criptare.
     * @param iv            Vectorul de inițializare (IV) de 8 octeți (64 de biți) utilizat pentru criptare.
     * @return 0 în caz de succes, o valoare non-zero în caz de eroare.
     */
    int des_cfb_decrypt_file(const char *in_filename,
                             const char *out_filename,
                             const uint8_t key[DES_KEY_SIZE],
                             const uint8_t iv[DES_BLOCK_SIZE]);

#ifdef __cplusplus
}
#endif

#endif // DES_CFB_H