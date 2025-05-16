#include "include/rsa.h"
#include <gmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>   // Pentru seed la gmp_rand
#include <limits.h> // Pentru ULONG_MAX

// --- Helper Functions for BigInt (using GMP) ---

// Functie ajutatoare pentru a scrie un numar GMP intr-un fisier (format binar: lungime + bytes)
// Returneaza 0 la succes, -1 la eroare
static int write_bigint_to_file(FILE *f, const mpz_t num)
{
    size_t num_bytes;
    // Determina numarul de bytes necesari pentru a exporta numarul (MSB first)
    // mpz_sizeinbase(num, 256) da numarul de octeti, inclusiv zero-uri initial
    num_bytes = mpz_sizeinbase(num, 256);

    // Scrie lungimea numarului in bytes
    if (fwrite(&num_bytes, sizeof(size_t), 1, f) != 1)
    {
        perror("Error writing BigInt size to file");
        return -1;
    }

    // Aloca buffer pentru export
    uint8_t *buffer = malloc(num_bytes);
    if (!buffer)
    {
        perror("Error allocating buffer for BigInt export");
        return -1;
    }

    // Exporta numarul in buffer (MSB first)
    // countp = NULL pentru ca dimensiunea o stim deja
    mpz_export(buffer, NULL, 1, 1, 0, 0, num);

    // Scrie buffer-ul in fisier
    if (fwrite(buffer, 1, num_bytes, f) != num_bytes)
    {
        perror("Error writing BigInt data to file");
        free(buffer);
        return -1;
    }

    free(buffer);
    return 0;
}

// Functie ajutatoare pentru a citi un numar GMP dintr-un fisier (format binar: lungime + bytes)
// Returneaza 0 la succes, -1 la eroare
static int read_bigint_from_file(FILE *f, mpz_t num)
{
    size_t num_bytes;

    // Citeste lungimea numarului in bytes
    if (fread(&num_bytes, sizeof(size_t), 1, f) != 1)
    {
        if (feof(f))
        {
            // Sfarsit de fisier - nu e neaparat o eroare daca se citeste secvential
            return -2; // Cod special pentru EOF
        }
        perror("Error reading BigInt size from file");
        return -1;
    }

    // Aloca buffer pentru import
    uint8_t *buffer = malloc(num_bytes);
    if (!buffer)
    {
        perror("Error allocating buffer for BigInt import");
        return -1;
    }

    // Citeste buffer-ul din fisier
    if (fread(buffer, 1, num_bytes, f) != num_bytes)
    {
        perror("Error reading BigInt data from file");
        free(buffer);
        return -1;
    }

    // Importa buffer-ul in numarul GMP
    mpz_import(num, num_bytes, 1, 1, 0, 0, buffer);

    free(buffer);
    return 0;
}

// Functie ajutatoare pentru a genera un numar prim probabil de o anumita dimensiune (biti)
// Utilizeaza gmp_randstate_t pentru randomness
static int generate_probable_prime(mpz_t prime, gmp_randstate_t rstate, size_t bits)
{
    if (bits < 8)
    { // E greu sa generezi primi foarte mici in interval random, dar si inutil pentru RSA
        fprintf(stderr, "Prime size too small (%zu bits).\n", bits);
        return -1;
    }

    // Generam un numar aleator de 'bits' biti
    // mpz_rrandomb(prime, rstate, bits); // Genereaza un numar uniform aleator de 'bits' biti
    // Sau, o abordare mai comuna pentru primii RSA:
    // Generam un numar de 'bits' biti, setam bitul cel mai semnificativ si cel mai putin semnificativ (sa fie impar)
    mpz_urandomb(prime, rstate, bits); // Genereaza un numar random pana la 2^bits - 1
    mpz_setbit(prime, bits - 1);       // Setam cel mai semnificativ bit (pentru a asigura dimensiunea)
    mpz_setbit(prime, 0);              // Setam cel mai putin semnificativ bit (sa fie impar)

    // Cautam urmatorul numar prim probabil incepand de la numarul generat
    // Testul probabilistic Miller-Rabin (ex: 25 iteratii e suficient pentru securitate)
    // 0 = compozit, 1 = probabil prim, 2 = prim sigur (pentru numere mici)
    while (mpz_probab_prime_p(prime, 25) == 0)
    {
        mpz_add_ui(prime, prime, 2); // Mergem la urmatorul numar impar
        // Sau, o abordare mai rapida e mpz_nextprime, dar mpz_probab_prime_p in bucla e OK.
        // mpz_nextprime(prime, prime);
    }

    return 0; // Succes
}

// --- Implementari Functii rsa_gmp ---

// Calculeaza dimensiunea maxima a plaintext-ului cu padding PKCS#1 v1.5
size_t rsa_pkcs1_v15_max_plaintext_size(size_t bits)
{
    if (bits / 8 < RSA_PKCS1_V15_ENCRYPT_OVERHEAD)
        return 0;
    return bits / 8 - RSA_PKCS1_V15_ENCRYPT_OVERHEAD;
}

// Calculeaza dimensiunea modulului N in bytes
size_t rsa_modulus_size_bytes(size_t bits)
{
    return (bits + 7) / 8; // Ar trebui sa fie exact bits/8 daca bits e multiplu de 8
}

// Generează cheile RSA utilizand GMP
int rsa_generate_keys_gmp(int bits, const char *public_key_file, const char *private_key_file)
{
    if (bits < 1024 || bits % 8 != 0)
    {
        fprintf(stderr, "RSA Key size must be at least 1024 bits and a multiple of 8.\n");
        return -1;
    }

    mpz_t p, q, n, phi, e, d, gcd_val;
    gmp_randstate_t rstate;
    int ret = -1;
    FILE *pub_fp = NULL;
    FILE *priv_fp = NULL;

    // 1. Initializare numere GMP
    mpz_init(p);
    mpz_init(q);
    mpz_init(n);
    mpz_init(phi);
    mpz_init(e);
    mpz_init(d);
    mpz_init(gcd_val);

    // Initializare stare generator numere aleatoare GMP (seed cu timpul curent)
    gmp_randinit_default(rstate);
    gmp_randseed_ui(rstate, time(NULL)); // Seed cu o valoare simpla

    // 2. Genereaza p si q (numere prime distincte, aproximativ bits/2)
    size_t half_bits = bits / 2;
    do
    {
        // Generam p
        if (generate_probable_prime(p, rstate, half_bits) != 0)
        {
            fprintf(stderr, "Failed to generate probable prime p.\n");
            goto cleanup;
        }

        // Generam q pana e diferit de p
        do
        {
            if (generate_probable_prime(q, rstate, half_bits) != 0)
            {
                fprintf(stderr, "Failed to generate probable prime q.\n");
                goto cleanup;
            }
        } while (mpz_cmp(p, q) == 0); // Asiguram ca p != q

        // Verificam ca p si q sunt de dimensiunea corecta (pentru a evita n sa fie mai mic)
        // Cel mai semnificativ bit trebuie sa fie setat in p si q
        if (!mpz_tstbit(p, half_bits - 1) || !mpz_tstbit(q, half_bits - 1))
        {
            fprintf(stderr, "Generated primes are not of correct bit length. Retrying...\n");
            continue; // Regeneram ambele numere
        }

        // Verificam ca p si q nu sunt egale (deja facut), si ca n=p*q are exact 'bits' biti
        mpz_mul(n, p, q);
        if (mpz_sizeinbase(n, 2) != bits)
        {
            fprintf(stderr, "Generated n has incorrect bit length (%zu vs %d). Retrying...\n", mpz_sizeinbase(n, 2), bits);
            continue; // Regeneram p si q
        }

        // Iesim din bucla daca p si q sunt generate corect si distincte si n are dimensiunea potrivita
        break;
    } while (1);

    // 3. Calculeaza n = p * q (deja calculat mai sus pentru verificare dimensiune)

    // 4. Calculeaza phi(n) = (p-1) * (q-1)
    mpz_t p_minus_1, q_minus_1;
    mpz_init(p_minus_1);
    mpz_init(q_minus_1);

    mpz_sub_ui(p_minus_1, p, 1); // p-1
    mpz_sub_ui(q_minus_1, q, 1); // q-1

    mpz_mul(phi, p_minus_1, q_minus_1); // phi = (p-1)*(q-1)

    mpz_clear(p_minus_1); // Eliberam memorie intermediara
    mpz_clear(q_minus_1); // Eliberam memorie intermediara

    // 5. Alege e (exponent public)
    // E = 65537 (0x10001) este o alegere comuna si sigura.
    // Trebuie sa fie 1 < e < phi(n) si gcd(e, phi) = 1.
    mpz_set_ui(e, 65537); // Setam e = 65537

    // Verificam gcd(e, phi) = 1 (Ar trebui sa fie 1 pentru e=65537 si phi de la prime mari)
    mpz_gcd(gcd_val, e, phi);
    if (mpz_cmp_ui(gcd_val, 1) != 0)
    {
        fprintf(stderr, "GCD(e, phi) is not 1. This should not happen with typical e and large random primes. Error in logic or prime generation.\n");
        goto cleanup; // Eroare critica
    }

    // 6. Calculeaza d (exponent privat) = e^(-1) mod phi(n)
    // Foloseste algoritmul lui Euclid extins implementat in GMP (mpz_invert)
    // mpz_invert returneaza 0 daca inversa nu exista (gcd != 1)
    if (mpz_invert(d, e, phi) == 0)
    {
        fprintf(stderr, "Failed to calculate modular inverse (d). Inverse does not exist.\n");
        goto cleanup; // Eroare
    }

    // 7. Salveaza cheile in fisiere
    pub_fp = fopen(public_key_file, "wb");
    if (!pub_fp)
    {
        perror("Error opening public key file for writing");
        goto cleanup;
    }
    // Salveaza N si E in fisierul public (format binar simplu)
    if (write_bigint_to_file(pub_fp, n) != 0)
        goto cleanup;
    if (write_bigint_to_file(pub_fp, e) != 0)
        goto cleanup;
    fclose(pub_fp);
    pub_fp = NULL; // Evita dubla închidere

    priv_fp = fopen(private_key_file, "wb");
    if (!priv_fp)
    {
        perror("Error opening private key file for writing");
        goto cleanup;
    }
    // Salveaza N si D in fisierul privat (format binar simplu)
    if (write_bigint_to_file(priv_fp, n) != 0)
        goto cleanup;
    if (write_bigint_to_file(priv_fp, d) != 0)
        goto cleanup;
    fclose(priv_fp);
    priv_fp = NULL; // Evita dubla închidere

    ret = 0; // Succes

cleanup:
    // Eliberare memorie GMP
    mpz_clear(p);
    mpz_clear(q);
    mpz_clear(n);
    mpz_clear(phi);
    mpz_clear(e);
    mpz_clear(d);
    mpz_clear(gcd_val);
    gmp_randclear(rstate); // Eliberare stare generator random

    if (pub_fp)
        fclose(pub_fp);
    if (priv_fp)
        fclose(priv_fp);

    return ret;
}

// Cripteaza un bloc mic de date cu cheia publică RSA (GMP)
int rsa_public_encrypt_block_gmp(const uint8_t *plaintext, size_t plaintext_len, uint8_t *ciphertext, size_t *ciphertext_len, const char *public_key_file, int bits)
{

    size_t modulus_bytes = rsa_modulus_size_bytes(bits);
    size_t max_pt_size = rsa_pkcs1_v15_max_plaintext_size(bits);
    int ret = -1;
    FILE *pub_fp = NULL;

    mpz_t n, e, m, c; // N, E (cheie publica), M (mesaj/plaintext), C (ciphertext)

    // 1. Validare dimensiuni
    if (plaintext_len > max_pt_size)
    {
        fprintf(stderr, "Plaintext block is too large (%zu bytes) for RSA key size %d bits with PKCS#1 v1.5 padding. Max %zu bytes.\n", plaintext_len, bits, max_pt_size);
        return -1;
    }
    if (!ciphertext || !ciphertext_len || *ciphertext_len < modulus_bytes)
    {
        fprintf(stderr, "Output ciphertext buffer too small. Needs %zu bytes.\n", modulus_bytes);
        return -1;
    }

    // 2. Initializare numere GMP
    mpz_init(n);
    mpz_init(e);
    mpz_init(m); // M va tine plaintext-ul cu padding (dimensiune modulus_bytes)
    mpz_init(c); // C va tine ciphertext-ul (dimensiune modulus_bytes)

    // 3. Citeste cheia publica (N, E) din fisier
    pub_fp = fopen(public_key_file, "rb");
    if (!pub_fp)
    {
        perror("Error opening public key file for reading");
        goto cleanup;
    }
    if (read_bigint_from_file(pub_fp, n) != 0)
        goto cleanup;
    if (read_bigint_from_file(pub_fp, e) != 0)
        goto cleanup;
    fclose(pub_fp);
    pub_fp = NULL; // Evita dubla închidere

    // Verificam ca N are dimensiunea corecta
    if (mpz_sizeinbase(n, 2) != bits)
    {
        fprintf(stderr, "Public key N has incorrect bit length (%zu vs %d). Check key file.\n", mpz_sizeinbase(n, 2), bits);
        goto cleanup;
    }

    // 4. Aplica Padding PKCS#1 v1.5 pe plaintext
    // Buffer pentru textul clar cu padding. Va avea exact dimensiunea modulului.
    size_t padded_len = modulus_bytes; // Dimensiunea buffer-ului cu padding
    uint8_t padded_buffer[padded_len];

    // Format PKCS#1 v1.5 Encryption Padding: 00 || 02 || PS || 00 || Message
    // PS = Random Non-Zero Bytes, lungime PS = padded_len - 3 - plaintext_len
    size_t ps_len = padded_len - 3 - plaintext_len;

    padded_buffer[0] = 0x00; // Primul octet
    padded_buffer[1] = 0x02; // Bloc Type 02 (pentru criptare)

    // Genereaza PS (random non-zero bytes)
    gmp_randstate_t rstate; // Generator random pentru PS
    gmp_randinit_default(rstate);
    gmp_randseed_ui(rstate, time(NULL) + plaintext_len); // Seed simplu (ar trebui mai robust)

    for (size_t i = 0; i < ps_len; ++i)
    {
        do
        {
            padded_buffer[2 + i] = mpz_urandomb_ui(e, rstate, 8); // Genereaza un byte random
        } while (padded_buffer[2 + i] == 0x00); // PS nu trebuie sa contina zero-uri
    }
    gmp_randclear(rstate); // Elibereaza stare generator random

    padded_buffer[2 + ps_len] = 0x00; // Separator 00

    // Copiaza plaintext-ul la sfarsitul buffer-ului cu padding
    memcpy(padded_buffer + 3 + ps_len, plaintext, plaintext_len);

    // 5. Convertește buffer-ul cu padding la numarul mare 'm'
    // Importa buffer-ul padded in numarul GMP 'm' (MSB first)
    mpz_import(m, padded_len, 1, 1, 0, 0, padded_buffer);

    // Verificam ca m < n (ar trebui sa fie mereu adevarat daca padding-ul e corect si plaintext_len <= max)
    if (mpz_cmp(m, n) >= 0)
    {
        fprintf(stderr, "Padded message m is not less than modulus N. Padding error or incorrect key/input size.\n");
        goto cleanup; // Eroare critica
    }

    // 6. Cripteaza: c = m^e mod n
    mpz_powm(c, m, e, n); // Foloseste algoritmul square-and-multiply implementat in GMP

    // 7. Convertește numarul mare 'c' la buffer de ciphertext
    // Exporta numarul GMP 'c' in buffer-ul 'ciphertext' (MSB first)
    // ciphertext_len la iesire va fi exact modulus_bytes
    mpz_export(ciphertext, ciphertext_len, 1, 1, 0, 0, c);

    ret = 0; // Succes

cleanup:
    // Eliberare memorie GMP
    mpz_clear(n);
    mpz_clear(e);
    mpz_clear(m);
    mpz_clear(c);
    // Nu eliberam rstate, e local la functie

    if (pub_fp)
        fclose(pub_fp);

    return ret;
}

// Decripteaza un bloc de text cifrat cu cheia privată RSA (GMP)
int rsa_private_decrypt_block_gmp(const uint8_t *ciphertext, size_t ciphertext_len, uint8_t *plaintext, size_t *plaintext_len, const char *private_key_file, int bits)
{

    size_t modulus_bytes = rsa_modulus_size_bytes(bits);
    size_t max_pt_size = rsa_pkcs1_v15_max_plaintext_size(bits);
    int ret = -1;
    FILE *priv_fp = NULL;

    mpz_t n, d, c, m_prime; // N, D (cheie privata), C (ciphertext), M' (rezultat decriptare/unpadded)

    // 1. Validare dimensiuni
    if (ciphertext_len != modulus_bytes)
    {
        fprintf(stderr, "Ciphertext block has incorrect size (%zu bytes) for RSA key size %d bits. Expected %zu bytes.\n", ciphertext_len, bits, modulus_bytes);
        return -1;
    }
    if (!plaintext || !plaintext_len || *plaintext_len < max_pt_size)
    {
        // Buffer-ul de plaintext trebuie sa fie suficient de mare pentru maximul posibil (dupa unpadding)
        fprintf(stderr, "Output plaintext buffer too small. Needs at least %zu bytes.\n", max_pt_size);
        return -1;
    }

    // 2. Initializare numere GMP
    mpz_init(n);
    mpz_init(d);
    mpz_init(c);       // C va tine ciphertext-ul (dimensiune modulus_bytes)
    mpz_init(m_prime); // M' va tine rezultatul decriptarii (dimensiune modulus_bytes)

    // 3. Citeste cheia privată (N, D) din fisier
    priv_fp = fopen(private_key_file, "rb");
    if (!priv_fp)
    {
        perror("Error opening private key file for reading");
        goto cleanup;
    }
    if (read_bigint_from_file(priv_fp, n) != 0)
        goto cleanup;
    if (read_bigint_from_file(priv_fp, d) != 0)
        goto cleanup;
    fclose(priv_fp);
    priv_fp = NULL; // Evita dubla închidere

    // Verificam ca N are dimensiunea corecta
    if (mpz_sizeinbase(n, 2) != bits)
    {
        fprintf(stderr, "Private key N has incorrect bit length (%zu vs %d). Check key file.\n", mpz_sizeinbase(n, 2), bits);
        goto cleanup;
    }

    // 4. Convertește ciphertext buffer la numarul mare 'c'
    // Importa buffer-ul ciphertext in numarul GMP 'c' (MSB first)
    mpz_import(c, ciphertext_len, 1, 1, 0, 0, ciphertext);

    // Verificam ca c < n (ar trebui sa fie adevarat pentru ciphertext valid)
    if (mpz_cmp(c, n) >= 0)
    {
        fprintf(stderr, "Ciphertext value is not less than modulus N. Corrupted ciphertext or wrong key.\n");
        // O implementare reala ar putea returna eroare de padding aici, dar verificarea asta e mai devreme.
        goto cleanup;
    }

    // 5. Decripteaza: m' = c^d mod n
    mpz_powm(m_prime, c, d, n); // Foloseste algoritmul square-and-multiply implementat in GMP

    // 6. Convertește numarul mare 'm_prime' la buffer (care ar trebui sa contina textul cu padding)
    // Exporta numarul GMP 'm_prime' in buffer-ul 'padded_buffer' (MSB first)
    // Acest buffer ar trebui sa aiba dimensiunea modulus_bytes si sa contina textul cu padding PKCS#1 v1.5
    uint8_t padded_buffer[modulus_bytes];
    size_t actual_padded_len = 0; // Va fi setata de mpz_export

    mpz_export(padded_buffer, &actual_padded_len, 1, 1, 0, 0, m_prime);

    // In teorie, actual_padded_len ar trebui sa fie egala cu modulus_bytes pentru inputuri valide.
    // Daca e mai mica, buffer-ul padded_buffer va contine zero-uri la inceput.
    // Ex: daca m_prime e mic, exportul va produce putini bytes semnificativi.
    // Trebuie sa ne asiguram ca avem exact modulus_bytes in padded_buffer pentru unpadding.
    // Daca actual_padded_len < modulus_bytes, octetii lipsa de la inceput sunt zero (padding implicitly).
    // Dar e mai sigur sa cream bufferul de marimea corecta si sa facem exportul in el.
    // Buffer-ul padded_buffer are deja marimea corecta (modulus_bytes), dar mpz_export scrie doar byte-ii semnificativi.
    // Trebuie sa punem zero-uri la inceputul padded_buffer DACA actual_padded_len < modulus_bytes
    // sau sa copiem datele exportate intr-un buffer temporar si apoi in padded_buffer cu offset.
    // O solutie mai simpla pentru export: aloca buffer temporar de actual_padded_len, exporta, apoi copiaza in padded_buffer cu offset.
    // Sau, exporta direct intr-un buffer temporar de marimea modulus_bytes si vezi cati bytes a scris real.
    // GMP exporta cel mai mic numar de bytes necesar. Deci padded_buffer ar putea sa nu fie umplut complet.

    // Solutie: Exportam intr-un buffer temporar si apoi copiem in padded_buffer cu offset
    size_t temp_export_len;
    uint8_t *temp_export_buffer = malloc(modulus_bytes); // Buffer temporar
    if (!temp_export_buffer)
    {
        perror("Error allocating temp export buffer");
        goto cleanup;
    }
    mpz_export(temp_export_buffer, &temp_export_len, 1, 1, 0, 0, m_prime);

    // Copiem datele exportate in padded_buffer, asigurandu-ne ca sunt aliniate corect (MSB first)
    memset(padded_buffer, 0, modulus_bytes);                                                        // Incepe cu zero-uri
    memcpy(padded_buffer + (modulus_bytes - temp_export_len), temp_export_buffer, temp_export_len); // Copiem datele exportate la sfarsit
    free(temp_export_buffer);                                                                       // Eliberam bufferul temporar

    // 7. Elimina Padding (Unpadding) PKCS#1 v1.5
    // Verificam formatul: 00 || 02 || PS || 00 || Message
    if (padded_buffer[0] != 0x00 || padded_buffer[1] != 0x02)
    {
        fprintf(stderr, "PKCS#1 v1.5 unpadding failed: Invalid block type prefix.\n");
        *plaintext_len = 0; // Nu am obtinut plaintext valid
        ret = -2;           // Indica eroare de padding
        goto cleanup;
    }

    // Cautam separatorul 00 dupa PS
    size_t ps_end_offset = 2; // Incepe cautarea dupa 00 02
    while (ps_end_offset < modulus_bytes && padded_buffer[ps_end_offset] != 0x00)
    {
        // Optional: In PKCS#1 v1.5, byte-ii din PS ar trebui sa fie non-zero.
        // O implementare stricta ar verifica asta: if (padded_buffer[ps_end_offset] == 0x00) { /* invalid PS */ goto error; }
        ps_end_offset++;
    }

    // Daca am ajuns la sfarsitul buffer-ului fara sa gasim 00
    if (ps_end_offset == modulus_bytes)
    {
        fprintf(stderr, "PKCS#1 v1.5 unpadding failed: Separator 00 not found.\n");
        *plaintext_len = 0;
        ret = -2; // Indica eroare de padding
        goto cleanup;
    }

    // Position of the actual message 'M' starts after the first 00 byte
    size_t message_start_offset = ps_end_offset + 1;

    // Lungimea plaintext-ului original este restul buffer-ului dupa separator
    size_t decrypted_message_len = modulus_bytes - message_start_offset;

    // Verificam daca buffer-ul de iesire 'plaintext' este suficient de mare
    if (*plaintext_len < decrypted_message_len)
    { // Remember plaintext_len points to the max size on input
        fprintf(stderr, "Output plaintext buffer too small (%zu bytes) for decrypted message (%zu bytes).\n", *plaintext_len, decrypted_message_len);
        *plaintext_len = 0;
        ret = -1; // Indica eroare de buffer
        goto cleanup;
    }

    // Copiem textul clar original in buffer-ul de iesire
    memcpy(plaintext, padded_buffer + message_start_offset, decrypted_message_len);

    // Setam lungimea reala a textului clar decriptat la iesire
    *plaintext_len = decrypted_message_len;

    ret = 0; // Succes

cleanup:
    // Eliberare memorie GMP
    mpz_clear(n);
    mpz_clear(d);
    mpz_clear(c);
    mpz_clear(m_prime);

    if (priv_fp)
        fclose(priv_fp);

    return ret;
}