#pragma once
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

int encrypt(const EVP_CIPHER *cipherType, unsigned char *plaintext,
            int plaintext_len, unsigned char *key, unsigned char *iv,
            unsigned char *ciphertext);

int decrypt(const EVP_CIPHER *cipherType, unsigned char *ciphertext,
            int ciphertext_len, unsigned char *key, unsigned char *iv,
            unsigned char *plaintext);

void handleErrors(void);

double benchmark(EVP_CIPHER *cipherType, unsigned char *key, unsigned char *iv,
                 long dataSize, bool doEncrypt);
