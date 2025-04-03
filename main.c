// crypto -a aes -mode gcm -e plaintext.bin -k key.bin -o output.bin
// crypto -a serpent -mode cfb -d cipher.bin -k key.bin -o decrypted.bin
// crypto -a rsa -genkey -k rsa_key -bits 2048

#include <stdio.h>
#include <string.h>
#include "include/aes_gcm.h"
#include "include/serpent_cfb.h"
#include "include/rsa.h"

int main(int argc, char *argv[]) {
    // parse arguments
    // ex: crypto -a aes -mode gcm -e -i input.bin -k key.bin -o output.bin -iv iv.bin
    //     crypto -a serpent -mode cfb -d ...
    //     crypto -a rsa -genkey ...
    //     etc.

    if (/* user wants AES GCM encrypt */) {
        // citește fișiere: plaintext, key, iv, AAD, output
        // apelez aes_gcm_encrypt_file()
    }
    else if (/* user wants AES GCM decrypt */) {
        // apelez aes_gcm_decrypt_file()
    }
    else if (/* user wants Serpent CFB encrypt */) {
        // apelez serpent_cfb_encrypt_file()
    }
    else if (/* user wants Serpent CFB decrypt */) {
        // apelez serpent_cfb_decrypt_file()
    }
    else if (/* user wants RSA keygen */) {
        // apelez rsa_keygen()
    }
    else if (/* user wants RSA encrypt */) {
        // apelez rsa_encrypt_file()
    }
    else if (/* user wants RSA decrypt */) {
        // apelez rsa_decrypt_file()
    }

    return 0;
}
