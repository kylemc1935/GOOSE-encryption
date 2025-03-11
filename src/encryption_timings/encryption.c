#include "encryption.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdio.h>
#include <sodium.h>

int aes_ctr_encrypt(const uint8_t *plaintext, int plaintext_len,
                    const uint8_t *key, const uint8_t *iv,
                    uint8_t *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    // initialize context for encrypting
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int len = 0, ciphertext_len = 0; // upadate encryption, encrypt plaintext etc
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len; //finalise encryption
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int chacha_encrypt(const uint8_t *plaintext, int plaintext_len,
                              const uint8_t *key, const uint8_t *nonce,
                              uint8_t *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int len = 0, ciphertext_len = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, key, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len;
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}


int aria_encrypt(const uint8_t *plaintext, int plaintext_len,
    const uint8_t *key, const uint8_t *iv,
    uint8_t *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    if (EVP_EncryptInit_ex(ctx, EVP_aria_128_ctr(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int len, ciphertext_len;
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len;
    
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int sm4_encrypt(const uint8_t *plaintext, int plaintext_len,
    const uint8_t *key, const uint8_t *iv,
    uint8_t *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    if (1 != EVP_EncryptInit_ex(ctx, EVP_sm4_ctr(), NULL, key, iv)){
        EVP_CIPHER_CTX_free(ctx);
    }

    int len = 0, ciphertext_len = 0;
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;
        EVP_CIPHER_CTX_free(ctx);
        return ciphertext_len;
}


int camellia_encrypt(const uint8_t *plaintext, int plaintext_len,
    const uint8_t *key, const uint8_t *iv, uint8_t *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    if (EVP_EncryptInit_ex(ctx, EVP_camellia_128_ctr(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int len, ciphertext_len;
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    ciphertext_len = len;
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int salsa20_encrypt(const uint8_t *plaintext, int plaintext_len,
    const uint8_t *key, const uint8_t *nonce,
    uint8_t *ciphertext) {
    //similar to the encrypt function this only requires this function call
    crypto_stream_salsa20_xor(ciphertext, plaintext, plaintext_len, nonce, key);
    return plaintext_len;
}

int chacha_encrypt_ls(const uint8_t *plaintext, int plaintext_len,
    const uint8_t *key, const uint8_t *nonce,
    uint8_t *ciphertext) {

    crypto_stream_chacha20_xor(ciphertext, plaintext, plaintext_len, nonce, key);
    return plaintext_len;
    }
    


