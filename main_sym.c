#include <stdio.h>
#include <string.h>
#include "include/symmetric/core/aes.h"
#include "include/symmetric/modes/gcm.h"
#include "include/symmetric/core/des.h"
#include "include/symmetric/modes/cfb.h"

// Wrapper function to match the block_cipher_func interface for AES
static void aes_encrypt_block_wrapper(const void *ctx, const uint8_t in[16], uint8_t out[16])
{
    aes_encrypt_block((const aes_context_t *)ctx, in, out);
}

// Wrapper function to match the block_cipher_func interface for DES
static void des_encrypt_block_wrapper(const void *ctx, const uint8_t in[8], uint8_t out[8])
{
    des_encrypt_block((const des_context_t *)ctx, in, out);
}

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

    // Parse arguments
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

    // Verify required arguments
    if (!algorithm || !mode || !operation || !input_file || !key_file || !output_file || !iv_file)
    {
        fprintf(stderr, "Missing required arguments.\n");
        return 1;
    }

    // Support for AES-GCM
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

        // Initialize AES context
        aes_context_t aes_ctx;
        aes_init(&aes_ctx, key, KEY_SIZE);

        // Open files
        FILE *in_file = fopen(input_file, "rb");
        if (!in_file)
        {
            perror("Error opening input file");
            return 1;
        }

        FILE *out_file = fopen(output_file, "wb");
        if (!out_file)
        {
            perror("Error opening output file");
            fclose(in_file);
            return 1;
        }

        const uint8_t *aad = NULL;
        size_t aad_len = 0;

        int result;
        if (strcmp(operation, "-e") == 0)
        {
            // Use GCM encrypt directly with AES context
            result = gcm_encrypt_file(&aes_ctx, aes_encrypt_block_wrapper,
                                      AES_BLOCK_SIZE, in_file, out_file,
                                      iv, IV_SIZE, aad, aad_len);

            if (result != 0)
            {
                fprintf(stderr, "Encryption failed with code %d\n", result);
                fclose(in_file);
                fclose(out_file);
                return 1;
            }
            printf("Encryption successful. Output written to %s\n", output_file);
        }
        else if (strcmp(operation, "-d") == 0)
        {
            // Use GCM decrypt directly with AES context
            result = gcm_decrypt_file(&aes_ctx, aes_encrypt_block_wrapper,
                                      AES_BLOCK_SIZE, in_file, out_file,
                                      iv, IV_SIZE, aad, aad_len);

            if (result != 0)
            {
                fprintf(stderr, "Decryption failed with code %d\n", result);
                fclose(in_file);
                fclose(out_file);
                return 1;
            }
            printf("Decryption successful. Output written to %s\n", output_file);
        }

        fclose(in_file);
        fclose(out_file);
    }
    // Support for DES-CFB
    else if (strcmp(algorithm, "des") == 0 && strcmp(mode, "cfb") == 0)
    {
        const size_t KEY_SIZE = DES_KEY_SIZE;
        const size_t IV_SIZE = DES_BLOCK_SIZE;

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

        // Initialize DES context
        des_context_t des_ctx;
        des_init(&des_ctx, key);

        // Open files
        FILE *in_file = fopen(input_file, "rb");
        if (!in_file)
        {
            perror("Error opening input file");
            return 1;
        }

        FILE *out_file = fopen(output_file, "wb");
        if (!out_file)
        {
            perror("Error opening output file");
            fclose(in_file);
            return 1;
        }

        int result;
        if (strcmp(operation, "-e") == 0)
        {
            // Use CFB encrypt with DES context
            result = cfb_encrypt_file(&des_ctx, des_encrypt_block_wrapper,
                                      DES_BLOCK_SIZE, in_file, out_file,
                                      iv, IV_SIZE);

            if (result != 0)
            {
                fprintf(stderr, "Encryption failed with code %d\n", result);
                fclose(in_file);
                fclose(out_file);
                return 1;
            }
            printf("Encryption successful. Output written to %s\n", output_file);
        }
        else if (strcmp(operation, "-d") == 0)
        {
            // Use CFB decrypt with DES context
            result = cfb_decrypt_file(&des_ctx, des_encrypt_block_wrapper,
                                      DES_BLOCK_SIZE, in_file, out_file,
                                      iv, IV_SIZE);

            if (result != 0)
            {
                fprintf(stderr, "Decryption failed with code %d\n", result);
                fclose(in_file);
                fclose(out_file);
                return 1;
            }
            printf("Decryption successful. Output written to %s\n", output_file);
        }

        fclose(in_file);
        fclose(out_file);
    }
    else
    {
        fprintf(stderr, "Unsupported algorithm and mode combination: %s-%s\n", algorithm, mode);
        return 1;
    }

    return 0;
}