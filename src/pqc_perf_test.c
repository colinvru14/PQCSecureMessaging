#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "ml-dsa-44.h"
#include "ml-kem-512.h"

// Default number of iterations for each test
#define DEFAULT_ITERATIONS 1000
#define TEST_MESSAGE_SIZE 1024
#define BUFFER_SIZE 4096

// Error handling for OpenSSL
void handle_errors()
{
    ERR_load_crypto_strings();
    char err[130];
    ERR_error_string(ERR_get_error(), err);
    fprintf(stderr, "Error: %s\n", err);
    exit(EXIT_FAILURE);
}

// Get current time with the most precise clock available
struct timespec get_time() {
    struct timespec time;

    // Try to use the most precise clock available
    #if defined(CLOCK_PROCESS_CPUTIME_ID)
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &time);
    #elif defined(CLOCK_MONOTONIC)
    clock_gettime(CLOCK_MONOTONIC, &time);
    #else
    clock_gettime(CLOCK_REALTIME, &time);
    #endif

    return time;
}

// Calculate duration in nanoseconds between two timespec values
unsigned long long calc_duration_ns(struct timespec start, struct timespec end) {
    unsigned long long duration_ns;

    // Use QNX-specific function if available
    #if defined(__EXT_QNX) && defined(timespec2nsec)
    unsigned long long start_ns = timespec2nsec(&start);
    unsigned long long end_ns = timespec2nsec(&end);
    duration_ns = end_ns - start_ns;
    #else
    // Standard calculation for other platforms
    duration_ns = (end.tv_sec - start.tv_sec) * 1000000000ULL +
                 (end.tv_nsec - start.tv_nsec);
    #endif

    return duration_ns;
}

// Print results in a consistent format
void print_results(const char* test_name, unsigned long long total_ns, int iterations) {
    double avg_ns = (double)total_ns / iterations;
    double avg_ms = avg_ns / 1000000.0;
    double ops_per_sec = 1000000000.0 / avg_ns;

    printf("%-40s | %10.2f ms | %10.2f ns | %10.2f ops/sec\n",
           test_name, avg_ms, avg_ns, ops_per_sec);
}

// Test ML-KEM-512 key generation performance
void test_ml_kem_keygen(int iterations) {
    struct timespec start, end;
    unsigned long long total_ns = 0;
    uint8_t kem_pk[PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t kem_sk[PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES];

    printf("Testing ML-KEM-512 keypair generation (%d iterations)...\n", iterations);

    start = get_time();

    for (int i = 0; i < iterations; i++) {
        PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(kem_pk, kem_sk);
    }

    end = get_time();
    total_ns = calc_duration_ns(start, end);

    print_results("ML-KEM-512 Keypair Generation", total_ns, iterations);
}

// Test ML-KEM-512 encapsulation performance
void test_ml_kem_encaps(int iterations) {
    struct timespec start, end;
    unsigned long long total_ns = 0;
    uint8_t kem_pk[PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t kem_sk[PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES];
    uint8_t ct[PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES];
    uint8_t ss[PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES];

    // Generate key pair first
    PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(kem_pk, kem_sk);

    printf("Testing ML-KEM-512 encapsulation (%d iterations)...\n", iterations);

    start = get_time();

    for (int i = 0; i < iterations; i++) {
        PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(ct, ss, kem_pk);
    }

    end = get_time();
    total_ns = calc_duration_ns(start, end);

    print_results("ML-KEM-512 Encapsulation", total_ns, iterations);
}

// Test ML-KEM-512 decapsulation performance
void test_ml_kem_decaps(int iterations) {
    struct timespec start, end;
    unsigned long long total_ns = 0;
    uint8_t kem_pk[PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t kem_sk[PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES];
    uint8_t ct[PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES];
    uint8_t ss1[PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES];
    uint8_t ss2[PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES];

    // Generate key pair and encapsulate first
    PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(kem_pk, kem_sk);
    PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(ct, ss1, kem_pk);

    printf("Testing ML-KEM-512 decapsulation (%d iterations)...\n", iterations);

    start = get_time();

    for (int i = 0; i < iterations; i++) {
        PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(ss2, ct, kem_sk);
    }

    end = get_time();
    total_ns = calc_duration_ns(start, end);

    print_results("ML-KEM-512 Decapsulation", total_ns, iterations);
}

// Test ML-DSA-44 key generation performance
void test_ml_dsa_keygen(int iterations) {
    struct timespec start, end;
    unsigned long long total_ns = 0;
    uint8_t dsa_pk[PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t dsa_sk[PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES];

    printf("Testing ML-DSA-44 keypair generation (%d iterations)...\n", iterations);

    start = get_time();

    for (int i = 0; i < iterations; i++) {
        PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(dsa_pk, dsa_sk);
    }

    end = get_time();
    total_ns = calc_duration_ns(start, end);

    print_results("ML-DSA-44 Keypair Generation", total_ns, iterations);
}

// Test ML-DSA-44 signature creation performance
void test_ml_dsa_sign(int iterations) {
    struct timespec start, end;
    unsigned long long total_ns = 0;
    uint8_t dsa_pk[PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t dsa_sk[PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES];
    uint8_t message[TEST_MESSAGE_SIZE];
    uint8_t signature[PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES];
    size_t signature_len;

    // Generate random message
    if (RAND_bytes(message, TEST_MESSAGE_SIZE) != 1) {
        handle_errors();
    }

    // Generate key pair first
    PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(dsa_pk, dsa_sk);

    printf("Testing ML-DSA-44 signature creation (%d iterations)...\n", iterations);

    start = get_time();

    for (int i = 0; i < iterations; i++) {
        PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(signature, &signature_len,
                                                  message, TEST_MESSAGE_SIZE, dsa_sk);
    }

    end = get_time();
    total_ns = calc_duration_ns(start, end);

    print_results("ML-DSA-44 Signature Creation", total_ns, iterations);
}

// Test ML-DSA-44 signature verification performance
void test_ml_dsa_verify(int iterations) {
    struct timespec start, end;
    unsigned long long total_ns = 0;
    uint8_t dsa_pk[PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t dsa_sk[PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES];
    uint8_t message[TEST_MESSAGE_SIZE];
    uint8_t signature[PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES];
    size_t signature_len;

    // Generate random message
    if (RAND_bytes(message, TEST_MESSAGE_SIZE) != 1) {
        handle_errors();
    }

    // Generate key pair and sign message first
    PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(dsa_pk, dsa_sk);
    PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(signature, &signature_len,
                                              message, TEST_MESSAGE_SIZE, dsa_sk);

    printf("Testing ML-DSA-44 signature verification (%d iterations)...\n", iterations);

    start = get_time();

    for (int i = 0; i < iterations; i++) {
        PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(signature, signature_len,
                                               message, TEST_MESSAGE_SIZE, dsa_pk);
    }

    end = get_time();
    total_ns = calc_duration_ns(start, end);

    print_results("ML-DSA-44 Signature Verification", total_ns, iterations);
}

// Test AES-256-CBC encryption performance
void test_aes_encrypt(int iterations) {
    struct timespec start, end;
    unsigned long long total_ns = 0;
    uint8_t key[32]; // 256-bit key
    uint8_t iv[16];  // 128-bit IV
    uint8_t plaintext[TEST_MESSAGE_SIZE];
    uint8_t ciphertext[TEST_MESSAGE_SIZE + EVP_MAX_BLOCK_LENGTH];
    int ciphertext_len;

    // Generate random key, IV, and plaintext
    if (RAND_bytes(key, sizeof(key)) != 1 ||
        RAND_bytes(iv, sizeof(iv)) != 1 ||
        RAND_bytes(plaintext, TEST_MESSAGE_SIZE) != 1) {
        handle_errors();
    }

    printf("Testing AES-256-CBC encryption (%d iterations)...\n", iterations);

    start = get_time();

    for (int i = 0; i < iterations; i++) {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) handle_errors();

        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)
            handle_errors();

        int len;
        if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, TEST_MESSAGE_SIZE) != 1)
            handle_errors();

        ciphertext_len = len;

        if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1)
            handle_errors();

        ciphertext_len += len;

        EVP_CIPHER_CTX_free(ctx);
    }

    end = get_time();
    total_ns = calc_duration_ns(start, end);

    print_results("AES-256-CBC Encryption", total_ns, iterations);
}

// Test AES-256-CBC decryption performance
void test_aes_decrypt(int iterations) {
    struct timespec start, end;
    unsigned long long total_ns = 0;
    uint8_t key[32]; // 256-bit key
    uint8_t iv[16];  // 128-bit IV
    uint8_t plaintext[TEST_MESSAGE_SIZE];
    uint8_t ciphertext[TEST_MESSAGE_SIZE + EVP_MAX_BLOCK_LENGTH];
    uint8_t decrypted[TEST_MESSAGE_SIZE + EVP_MAX_BLOCK_LENGTH];
    int ciphertext_len, decrypted_len;

    // Generate random key, IV, and plaintext
    if (RAND_bytes(key, sizeof(key)) != 1 ||
        RAND_bytes(iv, sizeof(iv)) != 1 ||
        RAND_bytes(plaintext, TEST_MESSAGE_SIZE) != 1) {
        handle_errors();
    }

    // Encrypt the data first
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handle_errors();

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)
        handle_errors();

    int len;
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, TEST_MESSAGE_SIZE) != 1)
        handle_errors();

    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1)
        handle_errors();

    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    printf("Testing AES-256-CBC decryption (%d iterations)...\n", iterations);

    start = get_time();

    for (int i = 0; i < iterations; i++) {
        ctx = EVP_CIPHER_CTX_new();
        if (!ctx) handle_errors();

        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)
            handle_errors();

        if (EVP_DecryptUpdate(ctx, decrypted, &len, ciphertext, ciphertext_len) != 1)
            handle_errors();

        decrypted_len = len;

        if (EVP_DecryptFinal_ex(ctx, decrypted + len, &len) != 1)
            handle_errors();

        decrypted_len += len;

        EVP_CIPHER_CTX_free(ctx);
    }

    end = get_time();
    total_ns = calc_duration_ns(start, end);

    print_results("AES-256-CBC Decryption", total_ns, iterations);
}

// Test full encryption process (sign + encrypt)
void test_full_encryption(int iterations) {
    struct timespec start, end;
    unsigned long long total_ns = 0;
    uint8_t dsa_pk[PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t dsa_sk[PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES];
    uint8_t key[32]; // AES key
    uint8_t iv[16];  // AES IV
    uint8_t plaintext[TEST_MESSAGE_SIZE];
    uint8_t ciphertext[TEST_MESSAGE_SIZE + EVP_MAX_BLOCK_LENGTH];
    uint8_t buffer[TEST_MESSAGE_SIZE + EVP_MAX_BLOCK_LENGTH + 16]; // IV + ciphertext
    uint8_t signature[PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES];
    size_t signature_len;
    int ciphertext_len;

    // Generate random key, IV, and plaintext
    if (RAND_bytes(key, sizeof(key)) != 1 ||
        RAND_bytes(plaintext, TEST_MESSAGE_SIZE) != 1) {
        handle_errors();
    }

    // Generate DSA key pair first
    PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(dsa_pk, dsa_sk);

    printf("Testing full encryption process (signature + encryption) (%d iterations)...\n", iterations);

    start = get_time();

    for (int i = 0; i < iterations; i++) {
        // Generate random IV for each iteration
        if (RAND_bytes(iv, sizeof(iv)) != 1) {
            handle_errors();
        }

        // 1. Encrypt with AES-256-CBC
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) handle_errors();

        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)
            handle_errors();

        int len;
        if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, TEST_MESSAGE_SIZE) != 1)
            handle_errors();

        ciphertext_len = len;

        if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1)
            handle_errors();

        ciphertext_len += len;

        EVP_CIPHER_CTX_free(ctx);

        // 2. Create buffer (IV + ciphertext)
        memcpy(buffer, iv, 16);
        memcpy(buffer + 16, ciphertext, ciphertext_len);
        int total_len = 16 + ciphertext_len;

        // 3. Sign the buffer
        PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(signature, &signature_len,
                                                  buffer, total_len, dsa_sk);
    }

    end = get_time();
    total_ns = calc_duration_ns(start, end);

    print_results("Full Encryption (Sign + Encrypt)", total_ns, iterations);
}

// Test full decryption process (verify + decrypt)
void test_full_decryption(int iterations) {
    struct timespec start, end;
    unsigned long long total_ns = 0;
    uint8_t dsa_pk[PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t dsa_sk[PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES];
    uint8_t key[32]; // AES key
    uint8_t iv[16];  // AES IV
    uint8_t plaintext[TEST_MESSAGE_SIZE];
    uint8_t ciphertext[TEST_MESSAGE_SIZE + EVP_MAX_BLOCK_LENGTH];
    uint8_t decrypted[TEST_MESSAGE_SIZE + EVP_MAX_BLOCK_LENGTH];
    uint8_t buffer[TEST_MESSAGE_SIZE + EVP_MAX_BLOCK_LENGTH + 16]; // IV + ciphertext
    uint8_t signature[PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES];
    size_t signature_len;
    int ciphertext_len, decrypted_len;

    // Generate random key, IV, and plaintext
    if (RAND_bytes(key, sizeof(key)) != 1 ||
        RAND_bytes(iv, sizeof(iv)) != 1 ||
        RAND_bytes(plaintext, TEST_MESSAGE_SIZE) != 1) {
        handle_errors();
    }

    // Generate DSA key pair
    PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(dsa_pk, dsa_sk);

    // Encrypt with AES-256-CBC
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handle_errors();

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)
        handle_errors();

    int len;
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, TEST_MESSAGE_SIZE) != 1)
        handle_errors();

    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1)
        handle_errors();

    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    // Create buffer (IV + ciphertext)
    memcpy(buffer, iv, 16);
    memcpy(buffer + 16, ciphertext, ciphertext_len);
    int total_len = 16 + ciphertext_len;

    // Sign the buffer
    PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(signature, &signature_len,
                                              buffer, total_len, dsa_sk);

    printf("Testing full decryption process (verify + decrypt) (%d iterations)...\n", iterations);

    start = get_time();

    for (int i = 0; i < iterations; i++) {
        // 1. Verify signature
        int verify_result = PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(signature, signature_len,
                                                                   buffer, total_len, dsa_pk);
        if (verify_result != 0) {
            fprintf(stderr, "Signature verification failed\n");
            exit(EXIT_FAILURE);
        }

        // 2. Decrypt
        ctx = EVP_CIPHER_CTX_new();
        if (!ctx) handle_errors();

        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)
            handle_errors();

        if (EVP_DecryptUpdate(ctx, decrypted, &len, ciphertext, ciphertext_len) != 1)
            handle_errors();

        decrypted_len = len;

        if (EVP_DecryptFinal_ex(ctx, decrypted + len, &len) != 1)
            handle_errors();

        decrypted_len += len;

        EVP_CIPHER_CTX_free(ctx);
    }

    end = get_time();
    total_ns = calc_duration_ns(start, end);

    print_results("Full Decryption (Verify + Decrypt)", total_ns, iterations);
}

int main(int argc, char *argv[]) {
    int iterations = DEFAULT_ITERATIONS;

    // Parse command line arguments
    if (argc > 1) {
        iterations = atoi(argv[1]);
        if (iterations <= 0) {
            fprintf(stderr, "Invalid number of iterations\n");
            return EXIT_FAILURE;
        }
    }

    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    printf("\nPQC Performance Test\n");
    printf("===================\n");
    printf("Testing with %d iterations per operation\n\n", iterations);

    printf("%-40s | %10s | %10s | %10s\n", "Operation", "Avg (ms)", "Avg (ns)", "Ops/sec");
    printf("------------------------------------------------------------------------------\n");

    // KEM tests
    test_ml_kem_keygen(iterations);
    test_ml_kem_encaps(iterations);
    test_ml_kem_decaps(iterations);

    // DSA tests
    test_ml_dsa_keygen(iterations);
    test_ml_dsa_sign(iterations);
    test_ml_dsa_verify(iterations);

    // Symmetric encryption tests
    test_aes_encrypt(iterations);
    test_aes_decrypt(iterations);

    // Combined operations
    test_full_encryption(iterations);
    test_full_decryption(iterations);

    printf("\nPerformance testing complete.\n");

    // Clean up
    EVP_cleanup();
    ERR_free_strings();

    return EXIT_SUCCESS;
}
