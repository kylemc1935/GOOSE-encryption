#ifndef ENCRYPTION_H
#define ENCRYPTION_H
#include <stdint.h>
#define EVP_CTRL_CHACHA20_SET_COUNTER 4

int aes_ctr_encrypt(const uint8_t *plaintext, int plaintext_len,
                    const uint8_t *key, const uint8_t *iv,
                    uint8_t *ciphertext);

int chacha_encrypt(const uint8_t *plaintext, int plaintext_len,
                   const uint8_t *key, const uint8_t *nonce,
                   uint8_t *ciphertext);

int aria_encrypt(const uint8_t *plaintext, int plaintext_len,
                 const uint8_t *key, const uint8_t *iv,
                 uint8_t *ciphertext);

int sm4_encrypt(const uint8_t *plaintext, int plaintext_len,
                const uint8_t *key, const uint8_t *iv,
                uint8_t *ciphertext);

int camellia_encrypt(const uint8_t *plaintext, int plaintext_len,
                const uint8_t *key, const uint8_t *iv,
                uint8_t *ciphertext);

int salsa20_encrypt(const uint8_t *plaintext, int plaintext_len,
                const uint8_t *key, const uint8_t *iv,
                uint8_t *ciphertext);

int chacha_encrypt_ls(const uint8_t *plaintext, int plaintext_len,
                const uint8_t *key, const uint8_t *nonce,
                uint8_t *ciphertext);

int ascon_encrypt(const uint8_t *plaintext, int plaintext_len,
                        const uint8_t *key, const uint8_t *nonce, uint8_t *ciphertext);


#endif 