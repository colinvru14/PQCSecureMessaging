#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

// Default number of iterations for each test
#define DEFAULT_ITERATIONS 100  // Using fewer iterations as RSA is slower
#define TEST_MESSAGE_SIZE 1024
#define BUFFER_SIZE 4096
#define KEY_LENGTH 2048
#define PUB_EXP 65537

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
    #if defined(CLOCK_MONOTONIC)
    clock_gettime(CLOCK_MONOTONIC, &time);
    #elif defined(CLOCK_PROCESS_CPUTIME_ID)
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &time);
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

// Test RSA key generation performance
void test_rsa_keygen(int iterations) {
    struct timespec start, end;
    unsigned long long total_ns = 0;

    printf("Testing RSA keypair generation (%d iterations)...\n", iterations);

    start = get_time();

    for (int i = 0; i < iterations; i++) {
        RSA *keypair = RSA_new();
        BIGNUM *e = BN_new();

        // Set public exponent
        BN_set_word(e, PUB_EXP);

        // Generate key
        RSA_generate_key_ex(keypair, KEY_LENGTH, e, NULL);

        // Free resources
        RSA_free(keypair);
        BN_free(e);
    }

    end = get_time();
    total_ns = calc_duration_ns(start, end);

    print_results("RSA Keypair Generation", total_ns, iterations);
}

// Test RSA encryption performance
void test_rsa_encrypt(int iterations) {
    struct timespec start, end;
    unsigned long long total_ns = 0;

    // Generate an RSA key pair first
    RSA *keypair = RSA_new();
    BIGNUM *e = BN_new();
    BN_set_word(e, PUB_EXP);
    if (RSA_generate_key_ex(keypair, KEY_LENGTH, e, NULL) != 1) {
        handle_errors();
    }

    // Prepare a test message
    unsigned char plaintext[TEST_MESSAGE_SIZE];
    if (RAND_bytes(plaintext, TEST_MESSAGE_SIZE/8) != 1) { // RSA can only encrypt small messages
        handle_errors();
    }

    // Buffer for encrypted data
    unsigned char encrypted[KEY_LENGTH/8];

    printf("Testing RSA encryption (%d iterations)...\n", iterations);

    start = get_time();

    for (int i = 0; i < iterations; i++) {
        // Encrypt with public key (OAEP padding)
        RSA_public_encrypt(TEST_MESSAGE_SIZE/8, plaintext, encrypted,
                           keypair, RSA_PKCS1_OAEP_PADDING);
    }

    end = get_time();
    total_ns = calc_duration_ns(start, end);

    print_results("RSA Encryption", total_ns, iterations);

    // Clean up
    RSA_free(keypair);
    BN_free(e);
}

// Test RSA decryption performance
void test_rsa_decrypt(int iterations) {
    struct timespec start, end;
    unsigned long long total_ns = 0;

    // Generate an RSA key pair first
    RSA *keypair = RSA_new();
    BIGNUM *e = BN_new();
    BN_set_word(e, PUB_EXP);
    if (RSA_generate_key_ex(keypair, KEY_LENGTH, e, NULL) != 1) {
        handle_errors();
    }

    // Prepare a test message
    unsigned char plaintext[TEST_MESSAGE_SIZE/8]; // RSA can only encrypt small messages
    unsigned char decrypted[TEST_MESSAGE_SIZE/8];
    if (RAND_bytes(plaintext, TEST_MESSAGE_SIZE/8) != 1) {
        handle_errors();
    }

    // Encrypt the message
    unsigned char encrypted[KEY_LENGTH/8];
    int encrypt_len = RSA_public_encrypt(TEST_MESSAGE_SIZE/8, plaintext, encrypted,
                                        keypair, RSA_PKCS1_OAEP_PADDING);
    if (encrypt_len == -1) {
        handle_errors();
    }

    printf("Testing RSA decryption (%d iterations)...\n", iterations);

    start = get_time();

    for (int i = 0; i < iterations; i++) {
        // Decrypt with private key
        RSA_private_decrypt(encrypt_len, encrypted, decrypted,
                           keypair, RSA_PKCS1_OAEP_PADDING);
    }

    end = get_time();
    total_ns = calc_duration_ns(start, end);

    print_results("RSA Decryption", total_ns, iterations);

    // Clean up
    RSA_free(keypair);
    BN_free(e);
}

// Test RSA signature generation performance
void test_rsa_sign(int iterations) {
    struct timespec start, end;
    unsigned long long total_ns = 0;

    // Generate an RSA key pair first
    RSA *keypair = RSA_new();
    BIGNUM *e = BN_new();
    BN_set_word(e, PUB_EXP);
    if (RSA_generate_key_ex(keypair, KEY_LENGTH, e, NULL) != 1) {
        handle_errors();
    }

    // Prepare a test message
    unsigned char message[TEST_MESSAGE_SIZE];
    if (RAND_bytes(message, TEST_MESSAGE_SIZE) != 1) {
        handle_errors();
    }

    // Create a message digest
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len;
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    EVP_DigestInit(md_ctx, EVP_sha256());
    EVP_DigestUpdate(md_ctx, message, TEST_MESSAGE_SIZE);
    EVP_DigestFinal(md_ctx, digest, &digest_len);
    EVP_MD_CTX_free(md_ctx);

    // Buffer for signature
    unsigned char signature[KEY_LENGTH/8];
    unsigned int signature_len;

    printf("Testing RSA signature generation (%d iterations)...\n", iterations);

    start = get_time();

    for (int i = 0; i < iterations; i++) {
        // Sign the digest
        RSA_sign(NID_sha256, digest, digest_len, signature, &signature_len, keypair);
    }

    end = get_time();
    total_ns = calc_duration_ns(start, end);

    print_results("RSA Signature Generation", total_ns, iterations);

    // Clean up
    RSA_free(keypair);
    BN_free(e);
}

// Test RSA signature verification performance
void test_rsa_verify(int iterations) {
    struct timespec start, end;
    unsigned long long total_ns = 0;

    // Generate an RSA key pair first
    RSA *keypair = RSA_new();
    BIGNUM *e = BN_new();
    BN_set_word(e, PUB_EXP);
    if (RSA_generate_key_ex(keypair, KEY_LENGTH, e, NULL) != 1) {
        handle_errors();
    }

    // Prepare a test message
    unsigned char message[TEST_MESSAGE_SIZE];
    if (RAND_bytes(message, TEST_MESSAGE_SIZE) != 1) {
        handle_errors();
    }

    // Create a message digest
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len;
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    EVP_DigestInit(md_ctx, EVP_sha256());
    EVP_DigestUpdate(md_ctx, message, TEST_MESSAGE_SIZE);
    EVP_DigestFinal(md_ctx, digest, &digest_len);
    EVP_MD_CTX_free(md_ctx);

    // Generate a signature
    unsigned char signature[KEY_LENGTH/8];
    unsigned int signature_len;
    RSA_sign(NID_sha256, digest, digest_len, signature, &signature_len, keypair);

    printf("Testing RSA signature verification (%d iterations)...\n", iterations);

    start = get_time();

    for (int i = 0; i < iterations; i++) {
        // Verify the signature
        RSA_verify(NID_sha256, digest, digest_len, signature, signature_len, keypair);
    }

    end = get_time();
    total_ns = calc_duration_ns(start, end);

    print_results("RSA Signature Verification", total_ns, iterations);

    // Clean up
    RSA_free(keypair);
    BN_free(e);
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

// Test full encryption process (RSA sign + AES encrypt)
void test_full_encryption(int iterations) {
    struct timespec start, end;
    unsigned long long total_ns = 0;

    // Generate RSA key pair
    RSA *keypair = RSA_new();
    BIGNUM *e = BN_new();
    BN_set_word(e, PUB_EXP);
    if (RSA_generate_key_ex(keypair, KEY_LENGTH, e, NULL) != 1) {
        handle_errors();
    }

    // Generate AES key and IV
    uint8_t aes_key[32]; // 256-bit key
    uint8_t iv[16];      // 128-bit IV
    uint8_t plaintext[TEST_MESSAGE_SIZE];
    uint8_t ciphertext[TEST_MESSAGE_SIZE + EVP_MAX_BLOCK_LENGTH];
    int ciphertext_len;

    // Generate random AES key, IV, and plaintext
    if (RAND_bytes(aes_key, sizeof(aes_key)) != 1 ||
        RAND_bytes(plaintext, TEST_MESSAGE_SIZE) != 1) {
        handle_errors();
    }

    // Prepare buffers
    uint8_t buffer[TEST_MESSAGE_SIZE + EVP_MAX_BLOCK_LENGTH + 16]; // IV + ciphertext
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len;
    unsigned char signature[KEY_LENGTH/8];
    unsigned int signature_len;

    printf("Testing full encryption process (RSA sign + AES encrypt) (%d iterations)...\n", iterations);

    start = get_time();

    for (int i = 0; i < iterations; i++) {
        // Generate random IV for each iteration
        if (RAND_bytes(iv, sizeof(iv)) != 1) {
            handle_errors();
        }

        // 1. Encrypt with AES-256-CBC
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) handle_errors();

        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, iv) != 1)
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

        // 3. Create a digest of the buffer
        EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
        EVP_DigestInit(md_ctx, EVP_sha256());
        EVP_DigestUpdate(md_ctx, buffer, total_len);
        EVP_DigestFinal(md_ctx, digest, &digest_len);
        EVP_MD_CTX_free(md_ctx);

        // 4. Sign the digest
        RSA_sign(NID_sha256, digest, digest_len, signature, &signature_len, keypair);
    }

    end = get_time();
    total_ns = calc_duration_ns(start, end);

    print_results("Full Encryption (RSA Sign + AES Encrypt)", total_ns, iterations);

    // Clean up
    RSA_free(keypair);
    BN_free(e);
}

// Test full decryption process (RSA verify + AES decrypt)
void test_full_decryption(int iterations) {
    struct timespec start, end;
    unsigned long long total_ns = 0;

    // Generate RSA key pair
    RSA *keypair = RSA_new();
    BIGNUM *e = BN_new();
    BN_set_word(e, PUB_EXP);
    if (RSA_generate_key_ex(keypair, KEY_LENGTH, e, NULL) != 1) {
        handle_errors();
    }

    // Generate AES key and IV
    uint8_t aes_key[32]; // 256-bit key
    uint8_t iv[16];      // 128-bit IV
    uint8_t plaintext[TEST_MESSAGE_SIZE];
    uint8_t ciphertext[TEST_MESSAGE_SIZE + EVP_MAX_BLOCK_LENGTH];
    uint8_t decrypted[TEST_MESSAGE_SIZE + EVP_MAX_BLOCK_LENGTH];
    int ciphertext_len, decrypted_len;

    // Generate random AES key, IV, and plaintext
    if (RAND_bytes(aes_key, sizeof(aes_key)) != 1 ||
        RAND_bytes(iv, sizeof(iv)) != 1 ||
        RAND_bytes(plaintext, TEST_MESSAGE_SIZE) != 1) {
        handle_errors();
    }

    // Encrypt with AES-256-CBC
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handle_errors();

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, iv) != 1)
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
    uint8_t buffer[TEST_MESSAGE_SIZE + EVP_MAX_BLOCK_LENGTH + 16]; // IV + ciphertext
    memcpy(buffer, iv, 16);
    memcpy(buffer + 16, ciphertext, ciphertext_len);
    int total_len = 16 + ciphertext_len;

    // Create a digest of the buffer
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len;
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    EVP_DigestInit(md_ctx, EVP_sha256());
    EVP_DigestUpdate(md_ctx, buffer, total_len);
    EVP_DigestFinal(md_ctx, digest, &digest_len);
    EVP_MD_CTX_free(md_ctx);

    // Sign the digest
    unsigned char signature[KEY_LENGTH/8];
    unsigned int signature_len;
    RSA_sign(NID_sha256, digest, digest_len, signature, &signature_len, keypair);

    printf("Testing full decryption process (RSA verify + AES decrypt) (%d iterations)...\n", iterations);

    start = get_time();

    for (int i = 0; i < iterations; i++) {
        // 1. Verify the signature
        int verify_result = RSA_verify(NID_sha256, digest, digest_len,
                                      signature, signature_len, keypair);
        if (verify_result != 1) {
            fprintf(stderr, "Signature verification failed\n");
            exit(EXIT_FAILURE);
        }

        // 2. Decrypt the ciphertext
        ctx = EVP_CIPHER_CTX_new();
        if (!ctx) handle_errors();

        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, iv) != 1)
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

    print_results("Full Decryption (RSA Verify + AES Decrypt)", total_ns, iterations);

    // Clean up
    RSA_free(keypair);
    BN_free(e);
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

    printf("\nTraditional Cryptography Performance Test\n");
    printf("=======================================\n");
    printf("Testing with %d iterations per operation\n\n", iterations);

    printf("%-40s | %10s | %10s | %10s\n", "Operation", "Avg (ms)", "Avg (ns)", "Ops/sec");
    printf("------------------------------------------------------------------------------\n");

    // RSA tests
    test_rsa_keygen(iterations);
    test_rsa_encrypt(iterations);
    test_rsa_decrypt(iterations);
    test_rsa_sign(iterations);
    test_rsa_verify(iterations);

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
