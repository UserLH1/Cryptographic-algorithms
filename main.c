#include <stdio.h>
#include <string.h>
#include "include/aes_gcm.h"
#include "include/des_cfb.h" // Header pentru DES-CFB

int main(int argc, char *argv[])
{
    if (argc < 11)
    {
        fprintf(stderr, "Usage: %s -a <alg> -mode <mode> -e/-d -i input.bin -k key.bin -o output.bin -iv iv.bin\n", argv[0]);
        return 1;
    }

    char *algorithm = NULL;
    char *mode = NULL;
    char *operation = NULL;
    char *input_file = NULL;
    char *key_file = NULL;
    char *output_file = NULL;
    char *iv_file = NULL;

    // Parsăm argumentele
    for (int i = 1; i < argc;)
    {
        if (strcmp(argv[i], "-a") == 0)
        {
            algorithm = argv[i + 1];
            i += 2;
        }
        else if (strcmp(argv[i], "-mode") == 0)
        {
            mode = argv[i + 1];
            i += 2;
        }
        else if (strcmp(argv[i], "-e") == 0)
        {
            operation = "-e";
            i += 1;
        }
        else if (strcmp(argv[i], "-d") == 0)
        {
            operation = "-d";
            i += 1;
        }
        else if (strcmp(argv[i], "-i") == 0)
        {
            input_file = argv[i + 1];
            i += 2;
        }
        else if (strcmp(argv[i], "-k") == 0)
        {
            key_file = argv[i + 1];
            i += 2;
        }
        else if (strcmp(argv[i], "-o") == 0)
        {
            output_file = argv[i + 1];
            i += 2;
        }
        else if (strcmp(argv[i], "-iv") == 0)
        {
            iv_file = argv[i + 1];
            i += 2;
        }
        else
        {
            fprintf(stderr, "Unknown argument: %s\n", argv[i]);
            return 1;
        }
    }

    // Verificăm argumentele obligatorii
    if (!algorithm || !mode || !operation || !input_file || !key_file || !output_file || !iv_file)
    {
        fprintf(stderr, "Missing required arguments.\n");
        return 1;
    }

    // Suport pentru AES-GCM
    if (strcmp(algorithm, "aes") == 0 && strcmp(mode, "gcm") == 0)
    {
        const size_t KEY_SIZE = 32; // AES-256
        const size_t IV_SIZE = 12;  // GCM IV

        uint8_t key[KEY_SIZE];
        uint8_t iv[IV_SIZE];

        FILE *key_fp = fopen(key_file, "rb");
        if (!key_fp)
        {
            perror("Error opening key file");
            return 1;
        }
        if (fread(key, 1, KEY_SIZE, key_fp) != KEY_SIZE)
        {
            fprintf(stderr, "Key must be exactly 32 bytes for AES.\n");
            fclose(key_fp);
            return 1;
        }
        fclose(key_fp);

        FILE *iv_fp = fopen(iv_file, "rb");
        if (!iv_fp)
        {
            perror("Error opening IV file");
            return 1;
        }
        if (fread(iv, 1, IV_SIZE, iv_fp) != IV_SIZE)
        {
            fprintf(stderr, "IV must be exactly 12 bytes for AES-GCM.\n");
            fclose(iv_fp);
            return 1;
        }
        fclose(iv_fp);

        const uint8_t *aad = NULL;
        size_t aad_len = 0;

        if (strcmp(operation, "-e") == 0)
        {
            int result = aes_gcm_encrypt_file(input_file, output_file, key, iv, aad, aad_len);
            if (result != 0)
            {
                fprintf(stderr, "Encryption failed with code %d\n", result);
                return 1;
            }
            printf("Encryption successful. Output written to %s\n", output_file);
        }
        else if (strcmp(operation, "-d") == 0)
        {
            int result = aes_gcm_decrypt_file(input_file, output_file, key, iv, aad, aad_len);
            if (result != 0)
            {
                fprintf(stderr, "Decryption failed with code %d\n", result);
                return 1;
            }
            printf("Decryption successful. Output written to %s\n", output_file);
        }
    }
    // Suport pentru DES-CFB
    else if (strcmp(algorithm, "des") == 0 && strcmp(mode, "cfb") == 0)
    {
        const size_t KEY_SIZE = 8; // DES key size
        const size_t IV_SIZE = 8;  // DES block size for IV

        uint8_t key[KEY_SIZE];
        uint8_t iv[IV_SIZE];

        FILE *key_fp = fopen(key_file, "rb");
        if (!key_fp)
        {
            perror("Error opening key file");
            return 1;
        }
        if (fread(key, 1, KEY_SIZE, key_fp) != KEY_SIZE)
        {
            fprintf(stderr, "Key must be exactly 8 bytes for DES.\n");
            fclose(key_fp);
            return 1;
        }
        fclose(key_fp);

        FILE *iv_fp = fopen(iv_file, "rb");
        if (!iv_fp)
        {
            perror("Error opening IV file");
            return 1;
        }
        if (fread(iv, 1, IV_SIZE, iv_fp) != IV_SIZE)
        {
            fprintf(stderr, "IV must be exactly 8 bytes for DES-CFB.\n");
            fclose(iv_fp);
            return 1;
        }
        fclose(iv_fp);

        if (strcmp(operation, "-e") == 0)
        {
            int result = des_cfb_encrypt_file(input_file, output_file, key, iv);
            if (result != 0)
            {
                fprintf(stderr, "Encryption failed with code %d\n", result);
                return 1;
            }
            printf("Encryption successful. Output written to %s\n", output_file);
        }
        else if (strcmp(operation, "-d") == 0)
        {
            int result = des_cfb_decrypt_file(input_file, output_file, key, iv);
            if (result != 0)
            {
                fprintf(stderr, "Decryption failed with code %d\n", result);
                return 1;
            }
            printf("Decryption successful. Output written to %s\n", output_file);
        }
    }
    else
    {
        fprintf(stderr, "Unsupported algorithm and mode combination: %s-%s\n", algorithm, mode);
        return 1;
    }

    return 0;
}