#include "decryption.h"
#include <openssl/evp.h>
#include <stdio.h>
#include <stdint.h>
#include <sodium.h>
#include <string.h>

#define EVP_CTRL_CHACHA20_SET_COUNTER 4
#define ASCON_TAG_SIZE 16

int aes_ctr_decrypt(const uint8_t *ciphertext, int ciphertext_len,
                    const uint8_t *key, const uint8_t *iv,
                    uint8_t *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); //create cipher context
    if (!ctx)return -1;

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv)) { //initalize context for given alg
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    //call decrypt update, processes the ciphertext
    int len = 0, plaintext_len = 0;
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;
    // this finalised decryption, not as appropriate in ctr mode but still essential
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

int sm4_decrypt(const uint8_t *ciphertext, int ciphertext_len,
                const uint8_t *key, const uint8_t *iv,
                uint8_t *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); //same context as above..
    if (!ctx) return -1;

    if (EVP_DecryptInit_ex(ctx, EVP_sm4_ctr(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int len = 0, plaintext_len = 0;
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

int chacha_decrypt(const uint8_t *ciphertext, int ciphertext_len,
                              const uint8_t *key, const uint8_t *nonce,
                              uint8_t *plaintext) {

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    if (EVP_DecryptInit_ex(ctx, EVP_chacha20(), NULL, key, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int len = 0, plaintext_len = 0;
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

int aria_decrypt(const uint8_t *ciphertext, int ciphertext_len,
    const uint8_t *key, const uint8_t *iv,
    uint8_t *plaintext) {

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    const EVP_CIPHER *cipher = EVP_aria_128_ctr();
    if (!cipher) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int len = 0, plaintext_len = 0;
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

int camellia_decrypt(const uint8_t *ciphertext, int ciphertext_len,
    const uint8_t *key, const uint8_t *iv, uint8_t *plaintext) {

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    if (1 != EVP_DecryptInit_ex(ctx, EVP_camellia_128_ctr(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int len = 0, plaintext_len = 0;
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

int salsa20_decrypt(const uint8_t *ciphertext, int ciphertext_len,
    const uint8_t *key, const uint8_t *nonce,
    uint8_t *plaintext) {
    //libsodiums implementation only requires this,
    crypto_stream_salsa20_xor(plaintext, ciphertext, ciphertext_len, nonce, key);
    return ciphertext_len;
}

int chacha_decrypt_ls(const uint8_t *ciphertext, int ciphertext_len,
    const uint8_t *key, const uint8_t *nonce,
    uint8_t *plaintext) {
    crypto_stream_chacha20_xor(plaintext, ciphertext, ciphertext_len, nonce, key);
    return ciphertext_len;
}

