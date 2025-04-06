#ifndef ENCRYPT_UTILITY_H
#define ENCRYPT_UTILITY_H


#include <openssl/aes.h>  // OpenSSL for AES encryption

// AES encryption using OpenSSL
void aes_encrypt(const unsigned char *plaintext, size_t plaintext_len, const unsigned char *key, unsigned char *ciphertext);
// AES decryption using OpenSSL
void aes_decrypt(const unsigned char *ciphertext, size_t ciphertext_len, const unsigned char *key, unsigned char *plaintext);

#endif 