#include "../headers/encrypt_utility.h"

// AES encryption using OpenSSL
void aes_encrypt(const unsigned char *plaintext, size_t plaintext_len, const unsigned char *key, unsigned char *ciphertext) {
    AES_KEY aes_key;
    AES_set_encrypt_key(key, 128, &aes_key);  // 128-bit key
    AES_encrypt(plaintext, ciphertext, &aes_key);
}

// AES decryption using OpenSSL
void aes_decrypt(const unsigned char *ciphertext, size_t ciphertext_len, const unsigned char *key, unsigned char *plaintext) {
    AES_KEY aes_key;
    AES_set_decrypt_key(key, 128, &aes_key);  // 128-bit key
    AES_decrypt(ciphertext, plaintext, &aes_key);
}