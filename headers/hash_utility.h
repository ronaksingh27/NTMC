#ifndef HASH_UTILITY_H
#define HASH_UTILITY_H

#include <openssl/sha.h>  // OpenSSL for SHA-256
#include <openssl/hmac.h> //OpenSSL for HMAC


// Hash function using OpenSSL's SHA-256
void hash_sha256(const char *input, size_t input_len, unsigned char *output);

// HMAC using OpenSSL's HMAC-SHA256
void hmac_sha256(const unsigned char *key, size_t key_len, const unsigned char *data, size_t data_len, unsigned char *output);

#endif