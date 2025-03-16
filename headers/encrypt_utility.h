#ifndef ENCRYPT_UTILITY_H
#define ENCRYPT_UTILITY_H

#include <stdio.h>
#include <gmp.h>
#include <string.h>
#include <openssl/sha.h>  // OpenSSL for SHA-256
#include <openssl/aes.h>  // OpenSSL for AES encryption
#include <openssl/hmac.h> //OpenSSL for HMAC

// AES encryption using OpenSSL
void aes_encrypt(const unsigned char *plaintext, size_t plaintext_len, const unsigned char *key, unsigned char *ciphertext);

#endif 