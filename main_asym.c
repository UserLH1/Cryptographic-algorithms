#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "include/asymmetric/rsa.h" // Include header-ul pentru functiile RSA cu GMP

int main(int argc, char *argv[])
{
    // --- Mesajul de utilizare specific RSA ---
    if (argc < 2)
    {
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "  %s -a rsa -g -bits <keysize_bits> -pubout public.key -privout private.key\n", argv[0]);
        fprintf(stderr, "  %s -a rsa -e/-d -i input.bin -k <public/private.key> -o output.bin -bits <keysize_bits>\n", argv[0]);
        fprintf(stderr, "\n");
        return 1;
    }

    char *algorithm = NULL;
    char *operation = NULL; // "-e", "-d", "-g"
    char *input_file = NULL;
    char *key_file = NULL; // Calea catre fisierul cu cheia RSA (publica sau privata)
    char *output_file = NULL;
    char *public_key_file_gen = NULL;  // Calea catre fisierul public la generare
    char *private_key_file_gen = NULL; // Calea catre fisierul privat la generare
    int key_bits = 0;                  // Lungimea cheii in biti

    // --- Parsarea argumentelor ---
    int i = 1;
    while (i < argc)
    {
        if (strcmp(argv[i], "-a") == 0)
        {
            if (i + 1 < argc)
                algorithm = argv[i + 1];
            else
                goto missing_arg;
            i += 2;
        }
        else if (strcmp(argv[i], "-g") == 0)
        {
            operation = "-g";
            i += 1;
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
            if (i + 1 < argc)
                input_file = argv[i + 1];
            else
                goto missing_arg;
            i += 2;
        }
        else if (strcmp(argv[i], "-k") == 0)
        {
            if (i + 1 < argc)
                key_file = argv[i + 1];
            else
                goto missing_arg;
            i += 2;
        }
        else if (strcmp(argv[i], "-o") == 0)
        {
            if (i + 1 < argc)
                output_file = argv[i + 1];
            else
                goto missing_arg;
            i += 2;
        }
        else if (strcmp(argv[i], "-pubout") == 0)
        { // Pentru generare RSA
            if (i + 1 < argc)
                public_key_file_gen = argv[i + 1];
            else
                goto missing_arg;
            i += 2;
        }
        else if (strcmp(argv[i], "-privout") == 0)
        { // Pentru generare RSA
            if (i + 1 < argc)
                private_key_file_gen = argv[i + 1];
            else
                goto missing_arg;
            i += 2;
        }
        else if (strcmp(argv[i], "-bits") == 0)
        { // Pentru RSA -g si -e/-d
            if (i + 1 < argc)
                key_bits = atoi(argv[i + 1]);
            else
                goto missing_arg;
            i += 2;
        }
        else
        {
            fprintf(stderr, "Unknown argument: %s\n", argv[i]);
            return 1;
        }
    }

    // Verificăm argumentele obligatorii GENERALE
    if (!algorithm || !operation)
    {
        fprintf(stderr, "Missing algorithm (-a) or operation (-e, -d, -g).\n");
        goto print_usage_and_exit;
    }

    // --- Gestionare doar RSA (simplificata fata de main-ul anterior) ---
    if (strcmp(algorithm, "rsa") != 0)
    {
        fprintf(stderr, "This executable only supports the 'rsa' algorithm (-a rsa).\n");
        goto print_usage_and_exit;
    }

    if (strcmp(operation, "-g") == 0)
    {
        // Cazul Generare Chei RSA
        if (!public_key_file_gen || !private_key_file_gen || key_bits < 1024)
        {
            fprintf(stderr, "Missing required arguments for RSA key generation (-pubout, -privout, -bits) or key size too small.\n");
            goto print_usage_and_exit;
        }
        printf("Generating RSA key pair (%d bits)...\n", key_bits);
        int result = rsa_generate_keys_gmp(key_bits, public_key_file_gen, private_key_file_gen);
        if (result == 0)
        {
            printf("RSA key pair generated successfully.\nPublic key: %s\nPrivate key: %s\n", public_key_file_gen, private_key_file_gen);
        }
        else
        {
            fprintf(stderr, "Failed to generate RSA key pair (returned %d).\n", result);
            return 1;
        }
    }
    else if (strcmp(operation, "-e") == 0 || strcmp(operation, "-d") == 0)
    {
        // Cazul Criptare/Decriptare Fisier cu RSA (prin chunking)
        // Aceasta logica utilizeaza rsa_encrypt_file_gmp / rsa_decrypt_file_gmp
        // care deja implementeaza chunking-ul intern
        if (!input_file || !key_file || !output_file || key_bits < 1024)
        {
            fprintf(stderr, "Missing required arguments for RSA encrypt/decrypt (-i, -k, -o, -bits) or key size too small.\n");
            goto print_usage_and_exit;
        }

        printf("%s file '%s' using RSA-%d...\n", (strcmp(operation, "-e") == 0) ? "Encrypting" : "Decrypting", input_file, key_bits);

        int result;
        if (strcmp(operation, "-e") == 0)
        {
            result = rsa_encrypt_file_gmp(input_file, output_file, key_file, key_bits);
        }
        else
        { // -d
            result = rsa_decrypt_file_gmp(input_file, output_file, key_file, key_bits);
        }

        if (result == 0)
        {
            printf("%s successful. Output written to %s.\n",
                   (strcmp(operation, "-e") == 0) ? "Encryption" : "Decryption",
                   output_file);
        }
        else
        {
            fprintf(stderr, "%s failed (returned %d).\n", (strcmp(operation, "-e") == 0) ? "Encryption" : "Decryption", result);
            return 1; // Ieși în caz de eroare
        }
    }
    else
    {
        fprintf(stderr, "Unsupported RSA operation: %s\n", operation);
        goto print_usage_and_exit;
    }

    return 0;

missing_arg:
    fprintf(stderr, "Missing value for argument %s.\n", argv[i]);
    // Fall through to print usage and exit

print_usage_and_exit:
    // Usage message already printed at the beginning
    return 1;
}