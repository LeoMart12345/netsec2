#include "NETWORKsec2.hpp"
#include <chrono>
#include <iostream>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

// AES

// ARIA

// Camellia

int main() {
  auto start = std::chrono::system_clock::now();
  // work

  auto end = std::chrono::system_clock::now();

  auto timeElapsed =
      std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);

  std::cout << "nanoseconds: " << timeElapsed.count() << std::endl;

  return 0;
}
