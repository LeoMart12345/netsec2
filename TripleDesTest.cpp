#include "NETWORKsec2.hpp"
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

  free(plaintext);
  free(ciphertext);
  free(decrypted);

  return (end.tv_sec - start.tv_sec) * 1000.0 +
         (end.tv_nsec - start.tv_nsec) / 1e6;
}

int main() {
  // again using rand to fill the key and the initialization vector.
  unsigned char key3des[24];
  unsigned char iv3des[8];
  RAND_bytes(key3des, sizeof(key3des));
  RAND_bytes(iv3des, sizeof(iv3des));
  // reusing result for each benchmark
  double result;
  // passing the different parameters into benchmark
  //  3DES CBC
  result =
      benchmark(EVP_des_ede3_cbc(), key3des, iv3des, 100 * 1024 * 1024, true);
  std::cout << "3DES-CBC  encrypt 100MB:  " << result << "ms\n";
  result =
      benchmark(EVP_des_ede3_cbc(), key3des, iv3des, 100 * 1024 * 1024, false);
  std::cout << "3DES-CBC  decrypt 100MB:  " << result << "ms\n";
  result =
      benchmark(EVP_des_ede3_cbc(), key3des, iv3des, 1000 * 1024 * 1024, true);
  std::cout << "3DES-CBC  encrypt 1000MB: " << result << "ms\n";
  result =
      benchmark(EVP_des_ede3_cbc(), key3des, iv3des, 1000 * 1024 * 1024, false);
  std::cout << "3DES-CBC  decrypt 1000MB: " << result << "ms\n";

  // 3DES ECB
  result =
      benchmark(EVP_des_ede3_ecb(), key3des, iv3des, 100 * 1024 * 1024, true);
  std::cout << "3DES-ECB  encrypt 100MB:  " << result << "ms\n";
  result =
      benchmark(EVP_des_ede3_ecb(), key3des, iv3des, 100 * 1024 * 1024, false);
  std::cout << "3DES-ECB  decrypt 100MB:  " << result << "ms\n";
  result =
      benchmark(EVP_des_ede3_ecb(), key3des, iv3des, 1000 * 1024 * 1024, true);
  std::cout << "3DES-ECB  encrypt 1000MB: " << result << "ms\n";
  result =
      benchmark(EVP_des_ede3_ecb(), key3des, iv3des, 1000 * 1024 * 1024, false);
  std::cout << "3DES-ECB  decrypt 1000MB: " << result << "ms\n";

  return 0;
}
