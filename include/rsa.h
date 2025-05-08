// rsa.h
#ifndef RSA_H
#define RSA_H

int rsa_keygen(const char* public_key_file,
               const char* private_key_file,
               int bits);

int rsa_encrypt_file(const char* in_filename,
                     const char* out_filename,
                     const char* public_key_file);

int rsa_decrypt_file(const char* in_filename,
                     const char* out_filename,
                     const char* private_key_file);

#endif
