Block Cipher Benchmarking with OpenSSL

## Overview

This project benchmarks symmetric encryption algorithms using the OpenSSL EVP API in C++. It measures and compares CPU execution time across different algorithms, key lengths, modes of operation, and data sizes.

## Problems

### Problem 1: Block Cipher Benchmarking
Benchmarks the following configurations:

- **Algorithms:** AES, ARIA, and Camellia
- **Key lengths:** 128-bit and 256-bit
- **Modes:** ECB, CBC, and CTR
- **Data sizes:** 100 MB and 1000 MB
- **Operations:** Encryption and Decryption

Results are recorded in tabular and graph form with analysis of performance differences across all configurations.

### Problem 2: Triple-DES Benchmarking
A separate benchmarking implementation for Triple-DES (3DES) in ECB and CBC modes, compared against the results from Problem 1.

## Project Structure

```
.
├── NETWORKsec2.hpp       # Header file — function prototypes, macros, defines
├── NETWORKsec2.cpp       # Problem 1 — AES, ARIA, Camellia benchmarking
├── tripledes.cpp         # Problem 2 — Triple-DES benchmarking
└── README.md
```

## Building

```bash
g++ -o benchmark NETWORKsec2.cpp -lcrypto -lrt
g++ -o tripledes tripledes.cpp -lcrypto -lrt
```

## Running

```bash
./benchmark
./tripledes
```

## Dependencies

- OpenSSL (`libcrypto`)
- POSIX real-time library (`librt`) for CPU time measurement via `clock_gettime`

Check your OpenSSL installation:
```bash
openssl version
```

## Benchmarking Method

CPU time is measured using the POSIX API (`CLOCK_PROCESS_CPUTIME_ID`) rather than wall time, to ensure accurate and reproducible results independent of system load.
