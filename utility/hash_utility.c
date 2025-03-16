#include "../headers/hash_utility.h"

// Hash function using OpenSSL's SHA-256
void hash_sha256(const char *input, size_t input_len, unsigned char *output) {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input, input_len);
    SHA256_Final(output, &sha256);
}

// HMAC using OpenSSL's HMAC-SHA256
void hmac_sha256(const unsigned char *key, size_t key_len, const unsigned char *data, size_t data_len, unsigned char *output) {
    HMAC_CTX *ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, key, key_len, EVP_sha256(), NULL);
    HMAC_Update(ctx, data, data_len);
    HMAC_Final(ctx, output, NULL);
    HMAC_CTX_free(ctx);
}
