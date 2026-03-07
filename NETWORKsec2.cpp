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
}

double benchmark(const EVP_CIPHER *cipherType, unsigned char *key,
                 unsigned char *iv, long dataSize, bool doEncrypt) {

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
  // free the memory used.
  free(plaintext);
  free(ciphertext);
  free(decrypted);

  return (end.tv_sec - start.tv_sec) * 1000.0 +
         (end.tv_nsec - start.tv_nsec) / 1e6;
}

int main() {
  // initialise keys and the initialiser vector
  unsigned char key256[32];
  unsigned char key128[16];
  unsigned char iv[16];
  // Using Rand for random initialization
  RAND_bytes(key256, sizeof(key256));
  RAND_bytes(key128, sizeof(key128));
  RAND_bytes(iv, sizeof(iv));

  // just calling the benchmark with the different parameters and ecryption
  // methods AES 256
  double result =
      benchmark(EVP_aes_256_cbc(), key256, iv, 100 * 1024 * 1024, true);
  std::cout << "AES-256-CBC   encrypt 100MB:  " << result << "ms\n";
  result = benchmark(EVP_aes_256_cbc(), key256, iv, 100 * 1024 * 1024, false);
  std::cout << "AES-256-CBC   decrypt 100MB:  " << result << "ms\n";
  result = benchmark(EVP_aes_256_cbc(), key256, iv, 1000 * 1024 * 1024, true);
  std::cout << "AES-256-CBC   encrypt 1000MB: " << result << "ms\n";
  result = benchmark(EVP_aes_256_cbc(), key256, iv, 1000 * 1024 * 1024, false);
  std::cout << "AES-256-CBC   decrypt 1000MB: " << result << "ms\n";

  result = benchmark(EVP_aes_256_ecb(), key256, iv, 100 * 1024 * 1024, true);
  std::cout << "AES-256-ECB   encrypt 100MB:  " << result << "ms\n";
  result = benchmark(EVP_aes_256_ecb(), key256, iv, 100 * 1024 * 1024, false);
  std::cout << "AES-256-ECB   decrypt 100MB:  " << result << "ms\n";
  result = benchmark(EVP_aes_256_ecb(), key256, iv, 1000 * 1024 * 1024, true);
  std::cout << "AES-256-ECB   encrypt 1000MB: " << result << "ms\n";
  result = benchmark(EVP_aes_256_ecb(), key256, iv, 1000 * 1024 * 1024, false);
  std::cout << "AES-256-ECB   decrypt 1000MB: " << result << "ms\n";

  result = benchmark(EVP_aes_256_ctr(), key256, iv, 100 * 1024 * 1024, true);
  std::cout << "AES-256-CTR   encrypt 100MB:  " << result << "ms\n";
  result = benchmark(EVP_aes_256_ctr(), key256, iv, 100 * 1024 * 1024, false);
  std::cout << "AES-256-CTR   decrypt 100MB:  " << result << "ms\n";
  result = benchmark(EVP_aes_256_ctr(), key256, iv, 1000 * 1024 * 1024, true);
  std::cout << "AES-256-CTR   encrypt 1000MB: " << result << "ms\n";
  result = benchmark(EVP_aes_256_ctr(), key256, iv, 1000 * 1024 * 1024, false);
  std::cout << "AES-256-CTR   decrypt 1000MB: " << result << "ms\n";

  // AES 128
  result = benchmark(EVP_aes_128_cbc(), key128, iv, 100 * 1024 * 1024, true);
  std::cout << "AES-128-CBC   encrypt 100MB:  " << result << "ms\n";
  result = benchmark(EVP_aes_128_cbc(), key128, iv, 100 * 1024 * 1024, false);
  std::cout << "AES-128-CBC   decrypt 100MB:  " << result << "ms\n";
  result = benchmark(EVP_aes_128_cbc(), key128, iv, 1000 * 1024 * 1024, true);
  std::cout << "AES-128-CBC   encrypt 1000MB: " << result << "ms\n";
  result = benchmark(EVP_aes_128_cbc(), key128, iv, 1000 * 1024 * 1024, false);
  std::cout << "AES-128-CBC   decrypt 1000MB: " << result << "ms\n";

  result = benchmark(EVP_aes_128_ecb(), key128, iv, 100 * 1024 * 1024, true);
  std::cout << "AES-128-ECB   encrypt 100MB:  " << result << "ms\n";
  result = benchmark(EVP_aes_128_ecb(), key128, iv, 100 * 1024 * 1024, false);
  std::cout << "AES-128-ECB   decrypt 100MB:  " << result << "ms\n";
  result = benchmark(EVP_aes_128_ecb(), key128, iv, 1000 * 1024 * 1024, true);
  std::cout << "AES-128-ECB   encrypt 1000MB: " << result << "ms\n";
  result = benchmark(EVP_aes_128_ecb(), key128, iv, 1000 * 1024 * 1024, false);
  std::cout << "AES-128-ECB   decrypt 1000MB: " << result << "ms\n";

  result = benchmark(EVP_aes_128_ctr(), key128, iv, 100 * 1024 * 1024, true);
  std::cout << "AES-128-CTR   encrypt 100MB:  " << result << "ms\n";
  result = benchmark(EVP_aes_128_ctr(), key128, iv, 100 * 1024 * 1024, false);
  std::cout << "AES-128-CTR   decrypt 100MB:  " << result << "ms\n";
  result = benchmark(EVP_aes_128_ctr(), key128, iv, 1000 * 1024 * 1024, true);
  std::cout << "AES-128-CTR   encrypt 1000MB: " << result << "ms\n";
  result = benchmark(EVP_aes_128_ctr(), key128, iv, 1000 * 1024 * 1024, false);
  std::cout << "AES-128-CTR   decrypt 1000MB: " << result << "ms\n";

  // ARIA 256
  result = benchmark(EVP_aria_256_cbc(), key256, iv, 100 * 1024 * 1024, true);
  std::cout << "ARIA-256-CBC  encrypt 100MB:  " << result << "ms\n";
  result = benchmark(EVP_aria_256_cbc(), key256, iv, 100 * 1024 * 1024, false);
  std::cout << "ARIA-256-CBC  decrypt 100MB:  " << result << "ms\n";
  result = benchmark(EVP_aria_256_cbc(), key256, iv, 1000 * 1024 * 1024, true);
  std::cout << "ARIA-256-CBC  encrypt 1000MB: " << result << "ms\n";
  result = benchmark(EVP_aria_256_cbc(), key256, iv, 1000 * 1024 * 1024, false);
  std::cout << "ARIA-256-CBC  decrypt 1000MB: " << result << "ms\n";

  result = benchmark(EVP_aria_256_ecb(), key256, iv, 100 * 1024 * 1024, true);
  std::cout << "ARIA-256-ECB  encrypt 100MB:  " << result << "ms\n";
  result = benchmark(EVP_aria_256_ecb(), key256, iv, 100 * 1024 * 1024, false);
  std::cout << "ARIA-256-ECB  decrypt 100MB:  " << result << "ms\n";
  result = benchmark(EVP_aria_256_ecb(), key256, iv, 1000 * 1024 * 1024, true);
  std::cout << "ARIA-256-ECB  encrypt 1000MB: " << result << "ms\n";
  result = benchmark(EVP_aria_256_ecb(), key256, iv, 1000 * 1024 * 1024, false);
  std::cout << "ARIA-256-ECB  decrypt 1000MB: " << result << "ms\n";

  result = benchmark(EVP_aria_256_ctr(), key256, iv, 100 * 1024 * 1024, true);
  std::cout << "ARIA-256-CTR  encrypt 100MB:  " << result << "ms\n";
  result = benchmark(EVP_aria_256_ctr(), key256, iv, 100 * 1024 * 1024, false);
  std::cout << "ARIA-256-CTR  decrypt 100MB:  " << result << "ms\n";
  result = benchmark(EVP_aria_256_ctr(), key256, iv, 1000 * 1024 * 1024, true);
  std::cout << "ARIA-256-CTR  encrypt 1000MB: " << result << "ms\n";
  result = benchmark(EVP_aria_256_ctr(), key256, iv, 1000 * 1024 * 1024, false);
  std::cout << "ARIA-256-CTR  decrypt 1000MB: " << result << "ms\n";

  // ARIA 128
  result = benchmark(EVP_aria_128_cbc(), key128, iv, 100 * 1024 * 1024, true);
  std::cout << "ARIA-128-CBC  encrypt 100MB:  " << result << "ms\n";
  result = benchmark(EVP_aria_128_cbc(), key128, iv, 100 * 1024 * 1024, false);
  std::cout << "ARIA-128-CBC  decrypt 100MB:  " << result << "ms\n";
  result = benchmark(EVP_aria_128_cbc(), key128, iv, 1000 * 1024 * 1024, true);
  std::cout << "ARIA-128-CBC  encrypt 1000MB: " << result << "ms\n";
  result = benchmark(EVP_aria_128_cbc(), key128, iv, 1000 * 1024 * 1024, false);
  std::cout << "ARIA-128-CBC  decrypt 1000MB: " << result << "ms\n";

  result = benchmark(EVP_aria_128_ecb(), key128, iv, 100 * 1024 * 1024, true);
  std::cout << "ARIA-128-ECB  encrypt 100MB:  " << result << "ms\n";
  result = benchmark(EVP_aria_128_ecb(), key128, iv, 100 * 1024 * 1024, false);
  std::cout << "ARIA-128-ECB  decrypt 100MB:  " << result << "ms\n";
  result = benchmark(EVP_aria_128_ecb(), key128, iv, 1000 * 1024 * 1024, true);
  std::cout << "ARIA-128-ECB  encrypt 1000MB: " << result << "ms\n";
  result = benchmark(EVP_aria_128_ecb(), key128, iv, 1000 * 1024 * 1024, false);
  std::cout << "ARIA-128-ECB  decrypt 1000MB: " << result << "ms\n";

  result = benchmark(EVP_aria_128_ctr(), key128, iv, 100 * 1024 * 1024, true);
  std::cout << "ARIA-128-CTR  encrypt 100MB:  " << result << "ms\n";
  result = benchmark(EVP_aria_128_ctr(), key128, iv, 100 * 1024 * 1024, false);
  std::cout << "ARIA-128-CTR  decrypt 100MB:  " << result << "ms\n";
  result = benchmark(EVP_aria_128_ctr(), key128, iv, 1000 * 1024 * 1024, true);
  std::cout << "ARIA-128-CTR  encrypt 1000MB: " << result << "ms\n";
  result = benchmark(EVP_aria_128_ctr(), key128, iv, 1000 * 1024 * 1024, false);
  std::cout << "ARIA-128-CTR  decrypt 1000MB: " << result << "ms\n";

  // Camellia 256
  result =
      benchmark(EVP_camellia_256_cbc(), key256, iv, 100 * 1024 * 1024, true);
  std::cout << "CAM-256-CBC   encrypt 100MB:  " << result << "ms\n";
  result =
      benchmark(EVP_camellia_256_cbc(), key256, iv, 100 * 1024 * 1024, false);
  std::cout << "CAM-256-CBC   decrypt 100MB:  " << result << "ms\n";
  result =
      benchmark(EVP_camellia_256_cbc(), key256, iv, 1000 * 1024 * 1024, true);
  std::cout << "CAM-256-CBC   encrypt 1000MB: " << result << "ms\n";
  result =
      benchmark(EVP_camellia_256_cbc(), key256, iv, 1000 * 1024 * 1024, false);
  std::cout << "CAM-256-CBC   decrypt 1000MB: " << result << "ms\n";

  result =
      benchmark(EVP_camellia_256_ecb(), key256, iv, 100 * 1024 * 1024, true);
  std::cout << "CAM-256-ECB   encrypt 100MB:  " << result << "ms\n";
  result =
      benchmark(EVP_camellia_256_ecb(), key256, iv, 100 * 1024 * 1024, false);
  std::cout << "CAM-256-ECB   decrypt 100MB:  " << result << "ms\n";
  result =
      benchmark(EVP_camellia_256_ecb(), key256, iv, 1000 * 1024 * 1024, true);
  std::cout << "CAM-256-ECB   encrypt 1000MB: " << result << "ms\n";
  result =
      benchmark(EVP_camellia_256_ecb(), key256, iv, 1000 * 1024 * 1024, false);
  std::cout << "CAM-256-ECB   decrypt 1000MB: " << result << "ms\n";

  result =
      benchmark(EVP_camellia_256_ctr(), key256, iv, 100 * 1024 * 1024, true);
  std::cout << "CAM-256-CTR   encrypt 100MB:  " << result << "ms\n";
  result =
      benchmark(EVP_camellia_256_ctr(), key256, iv, 100 * 1024 * 1024, false);
  std::cout << "CAM-256-CTR   decrypt 100MB:  " << result << "ms\n";
  result =
      benchmark(EVP_camellia_256_ctr(), key256, iv, 1000 * 1024 * 1024, true);
  std::cout << "CAM-256-CTR   encrypt 1000MB: " << result << "ms\n";
  result =
      benchmark(EVP_camellia_256_ctr(), key256, iv, 1000 * 1024 * 1024, false);
  std::cout << "CAM-256-CTR   decrypt 1000MB: " << result << "ms\n";

  // Camellia 128
  result =
      benchmark(EVP_camellia_128_cbc(), key128, iv, 100 * 1024 * 1024, true);
  std::cout << "CAM-128-CBC   encrypt 100MB:  " << result << "ms\n";
  result =
      benchmark(EVP_camellia_128_cbc(), key128, iv, 100 * 1024 * 1024, false);
  std::cout << "CAM-128-CBC   decrypt 100MB:  " << result << "ms\n";
  result =
      benchmark(EVP_camellia_128_cbc(), key128, iv, 1000 * 1024 * 1024, true);
  std::cout << "CAM-128-CBC   encrypt 1000MB: " << result << "ms\n";
  result =
      benchmark(EVP_camellia_128_cbc(), key128, iv, 1000 * 1024 * 1024, false);
  std::cout << "CAM-128-CBC   decrypt 1000MB: " << result << "ms\n";

  result =
      benchmark(EVP_camellia_128_ecb(), key128, iv, 100 * 1024 * 1024, true);
  std::cout << "CAM-128-ECB   encrypt 100MB:  " << result << "ms\n";
  result =
      benchmark(EVP_camellia_128_ecb(), key128, iv, 100 * 1024 * 1024, false);
  std::cout << "CAM-128-ECB   decrypt 100MB:  " << result << "ms\n";
  result =
      benchmark(EVP_camellia_128_ecb(), key128, iv, 1000 * 1024 * 1024, true);
  std::cout << "CAM-128-ECB   encrypt 1000MB: " << result << "ms\n";
  result =
      benchmark(EVP_camellia_128_ecb(), key128, iv, 1000 * 1024 * 1024, false);
  std::cout << "CAM-128-ECB   decrypt 1000MB: " << result << "ms\n";

  result =
      benchmark(EVP_camellia_128_ctr(), key128, iv, 100 * 1024 * 1024, true);
  std::cout << "CAM-128-CTR   encrypt 100MB:  " << result << "ms\n";
  result =
      benchmark(EVP_camellia_128_ctr(), key128, iv, 100 * 1024 * 1024, false);
  std::cout << "CAM-128-CTR   decrypt 100MB:  " << result << "ms\n";
  result =
      benchmark(EVP_camellia_128_ctr(), key128, iv, 1000 * 1024 * 1024, true);
  std::cout << "CAM-128-CTR   encrypt 1000MB: " << result << "ms\n";
  result =
      benchmark(EVP_camellia_128_ctr(), key128, iv, 1000 * 1024 * 1024, false);
  std::cout << "CAM-128-CTR   decrypt 1000MB: " << result << "ms\n";

  return 0;
}
