#ifndef DECRYPTION_H
#define DECRYPTION_H
#include <stdint.h>

int aes_ctr_decrypt(const uint8_t *ciphertext, int ciphertext_len,
                    const uint8_t *key, const uint8_t *iv,
                    uint8_t *plaintext);

int sm4_decrypt(const uint8_t *ciphertext, int ciphertext_len,
    const uint8_t *key, const uint8_t *iv,
    uint8_t *plaintext);
    
int chacha_decrypt(const uint8_t *ciphertext, int ciphertext_len,
    const uint8_t *key, const uint8_t *nonce,
    uint8_t *plaintext);

int aria_decrypt(const uint8_t *ciphertext, int ciphertext_len,
    const uint8_t *key, const uint8_t *iv,
    uint8_t *plaintext);

int camellia_decrypt(const uint8_t *ciphertext, int ciphertext_len,
    const uint8_t *key, const uint8_t *iv,        uint8_t *plaintext);

int salsa20_decrypt(const uint8_t *ciphertext, int ciphertext_len,
    const uint8_t *key, const uint8_t *nonce,
    uint8_t *plaintext);

int chacha_decrypt_ls(const uint8_t *ciphertext, int ciphertext_len,
    const uint8_t *key, const uint8_t *nonce,
    uint8_t *plaintext);

int ascon_decrypt(const uint8_t *ciphertext, int ciphertext_len,
                        const uint8_t *key, const uint8_t *nonce,
                        uint8_t *plaintext);

#endif