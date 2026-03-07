#include "NETWORKsec2.hpp"
#include <chrono>
#include <cstring>
#include <ctime>
#include <iostream>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
// handle errors:
void handleErrors(void) {
  ERR_print_errors_fp(stderr);
  abort();
}

// decrypt
int encrypt(const EVP_CIPHER *cipherType, unsigned char *plaintext,
            int plaintext_len, unsigned char *key, unsigned char *iv,
            unsigned char *ciphertext) {
  EVP_CIPHER_CTX *ctx;
  int len;
  int ciphertext_len;

  /* Create and initialise the context */
  if (!(ctx = EVP_CIPHER_CTX_new()))
    handleErrors();
  /*
   * Initialise the encryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits
   */
  if (1 != EVP_EncryptInit_ex(ctx, cipherType, NULL, key, iv))
    handleErrors();
  /*
   * Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors();

  ciphertext_len = len;
  /*
   * Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
    handleErrors();

  ciphertext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

// Encrypt
int decrypt(const EVP_CIPHER *cipherType, unsigned char *ciphertext,
            int ciphertext_len, unsigned char *key, unsigned char *iv,
            unsigned char *plaintext) {
  EVP_CIPHER_CTX *ctx;

  int len;

  int plaintext_len;

  /* Create and initialise the context */
  if (!(ctx = EVP_CIPHER_CTX_new()))
    handleErrors();

  /*
   * Initialise the decryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits
   */
  if (1 != EVP_DecryptInit_ex(ctx, cipherType, NULL, key, iv))
    handleErrors();

  /*
   * Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary.
   */
  if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    handleErrors();

  plaintext_len = len;

  /*
   * Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   */
  if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
    handleErrors();

  plaintext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
} // AES

// ARIA

// Camellia

int main() {

  ///////////////////////////////////////////////////////////////////////
  /* A 256 bit key */
  unsigned char key256[32];
  unsigned char key128[16];
  unsigned char iv[16];

  RAND_bytes(key256, sizeof(key256));
  RAND_bytes(key128, sizeof(key128));
  RAND_bytes(iv, sizeof(iv));

  /* A 128 bit IV */
  unsigned char *iv16[16] = {"012345678901234"};
  unsigned char *iv32[32] = {"012345678901234012345678901234"};
  /* Message to be encrypted */
  unsigned char *plaintext =
      (unsigned char *)"The quick brown fox jumps over the lazy dog";

  unsigned char ciphertext[128];

  /* Buffer for the decrypted text */
  unsigned char decryptedtext[128];
  int decryptedtext_len, ciphertext_len;

  auto start = std::chrono::system_clock::now();
  /* Encrypt the plaintext */
  ciphertext_len = encrypt(EVP_aes_256_cbc(), plaintext,
                           strlen((char *)plaintext), key, iv, ciphertext);

  auto end = std::chrono::system_clock::now();
  /* Do something useful with the ciphertext here */
  auto timeElapsed =
      std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);

  std::cout << "nanoseconds: " << timeElapsed.count() << std::endl;

  printf("Ciphertext is:\n");
  BIO_dump_fp(stdout, (const char *)ciphertext, ciphertext_len);

  /* Decrypt the ciphertext */
  decryptedtext_len = decrypt(EVP_aes_256_cbc(), ciphertext, ciphertext_len,
                              key256, iv, decryptedtext);

  /* Add a NULL terminator. We are expecting printable text */
  decryptedtext[decryptedtext_len] = '\0';

  /* Show the decrypted text */
  printf("Decrypted text is:\n");
  printf("%s\n", decryptedtext);

  // 100MB
  benchmark(EVP_aes_256_cbc(), key256, iv, 100 * 1024 * 1024, true);

  // 1000MB
  benchmark(EVP_aes_256_cbc(), key256, iv, 1000 * 1024 * 1024, true);

  return 0;
}

double benchmark(EVP_CIPHER *cipherType, unsigned char *key, unsigned char *iv,
                 long dataSize, bool doEncrypt) {

  unsigned char *plaintext = (unsigned char *)malloc(dataSize);
  unsigned char *ciphertext = (unsigned char *)malloc(dataSize + 16);
  unsigned char *decrypted = (unsigned char *)malloc(dataSize + 16);

  RAND_bytes(plaintext, dataSize);

  struct timespec start, end;
  clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);

  if (doEncrypt) {
    encrypt(cipherType, plaintext, dataSize, key, iv, ciphertext);
  } else {
    // need ciphertext first to decrypt
    int clen = encrypt(cipherType, plaintext, dataSize, key, iv, ciphertext);
    decrypt(cipherType, ciphertext, clen, key, iv, decrypted);
  }

  clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end);

  free(plaintext);
  free(ciphertext);
  free(decrypted);

  return (end.tv_sec - start.tv_sec) * 1000.0 +
         (end.tv_nsec - start.tv_nsec) / 1e6;
}
