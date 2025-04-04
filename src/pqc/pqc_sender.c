#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "ml-dsa-44.h"
#include "ml-kem-512.h"
#include "perf_metrics.h"

#define PORT 9090
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

void sender_process(const char *input_file)
{
    int sockfd;
    struct sockaddr_in server_addr;
    struct timespec operation_start_time, encryption_start_time, encryption_end_time;
    FILE *msg_file = NULL;

    if (input_file)
    {
        msg_file = fopen(input_file, "r");
        if (!msg_file)
        {
            perror("[SENDER] Failed to open input file");
            exit(EXIT_FAILURE);
        }
        printf("[SENDER] Reading messages from file: %s\n", input_file);
    }

    // Initialize performance logging
    init_perf_logging("sender_perf.csv");

    // ML-KEM-512 key pair generation
    uint8_t kem_pk[PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t kem_sk[PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES];

    operation_start_time = start_timing();
    if (PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(kem_pk, kem_sk) != 0)
    {
        fprintf(stderr, "[SENDER] ML-KEM keypair generation failed\n");
        exit(EXIT_FAILURE);
    }
    end_timing(operation_start_time, "[SENDER] ML-KEM-512 Keypair Generation", PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES + PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES, "Sender");
    printf("[SENDER] ML-KEM public key generated.\n");

    // ML-DSA-44 key pair generation
    uint8_t dsa_pk[PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t dsa_sk[PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES];

    operation_start_time = start_timing();
    if (PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(dsa_pk, dsa_sk) != 0)
    {
        fprintf(stderr, "[SENDER] ML-DSA keypair generation failed\n");
        exit(EXIT_FAILURE);
    }
    end_timing(operation_start_time, "[SENDER] ML-DSA-44 Keypair Generation", PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES + PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES, "Sender");
    printf("[SENDER] ML-DSA public key generated.\n");

    // Socket setup
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("[SENDER] Socket creation failed");
        exit(EXIT_FAILURE);
    }
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("[SENDER] Connection failed");
        exit(EXIT_FAILURE);
    }
    printf("[SENDER] Connected to receiver.\n");

    // Receive receiver's ML-KEM public key and ML-DSA signature
    uint8_t receiver_kem_pk[PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t receiver_dsa_pk[PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES];
    size_t receiver_siglen;
    uint8_t receiver_sig[PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES];
    recv(sockfd, receiver_kem_pk, PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES, 0);
    recv(sockfd, receiver_dsa_pk, PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES, 0);
    recv(sockfd, &receiver_siglen, sizeof(size_t), 0);
    recv(sockfd, receiver_sig, receiver_siglen, 0);

    // Verify receiver's ML-KEM public key
    operation_start_time = start_timing();
    if (PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(receiver_sig, receiver_siglen,
                                                 receiver_kem_pk,
                                                 PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES,
                                                 receiver_dsa_pk) != 0)
    {
        fprintf(stderr, "[SENDER] ML-DSA signature verification failed\n");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    end_timing(operation_start_time, "[SENDER] ML-DSA-44 Signature Verification", receiver_siglen, "Verifying receiver's ML-KEM public key");
    printf("[SENDER] Receiver's ML-KEM public key verified.\n");

    // Encapsulate shared secret with receiver's public key
    uint8_t ct[PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES];
    uint8_t ss[PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES];

    operation_start_time = start_timing();
    if (PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(ct, ss, receiver_kem_pk) != 0)
    {
        fprintf(stderr, "[SENDER] ML-KEM encapsulation failed\n");
        exit(EXIT_FAILURE);
    }
    end_timing(operation_start_time, "[SENDER] ML-KEM-512 Encapsulation", PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES, "Generating shared secret");
    send(sockfd, ct, PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES, 0);
    printf("[SENDER] Shared secret encapsulated and sent.\n");

    // Send ML-DSA pk
    send(sockfd, dsa_pk, PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES, 0);

    // Send encrypted messages
    int message_count = 0;
    double total_time_ms = 0;
    size_t total_bytes = 0;
    char msg[BUFFER_SIZE];

    while (1)
    {
        if (msg_file)
        {
            // Read messages from file
            if (fgets(msg, BUFFER_SIZE - 1, msg_file) == NULL)
            {
                // End of file
                printf("[SENDER] End of message file reached. Sending termination message.\n");
                strcpy(msg, "quit");
            }
            else
            {
                // Remove newline character if present
                size_t len = strlen(msg);
                if (len > 0 && msg[len - 1] == '\n')
                {
                    msg[len - 1] = '\0';
                }
                printf("[SENDER] Sending message: %s\n", msg);
            }
        }
        else
        {
            // Interactive mode - read from stdin
            printf("[SENDER] Enter message (or 'quit' to exit): ");
            fgets(msg, BUFFER_SIZE - 1, stdin);
            msg[strlen(msg) - 1] = '\0'; // Remove newline
        }

        if (strcmp(msg, "quit") == 0)
        {
            printf("[SENDER] Exiting...\n");
            break;
        }

        // Start encryption timing
        encryption_start_time = start_timing();

        // Generate random IV
        uint8_t iv[EVP_MAX_IV_LENGTH];
        if (RAND_bytes(iv, EVP_MAX_IV_LENGTH) != 1)
        {
            handle_errors();
        }

        // Set up encryption context
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx)
            handle_errors();

        // Start timing encryption
        operation_start_time = start_timing();

        // Initialize encryption operation with AES-256-CBC
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, ss, iv) != 1)
            handle_errors();

        // Encrypt message - the EVP interface handles padding automatically
        int len, ciphertext_len;
        uint8_t encrypted[BUFFER_SIZE + EVP_MAX_IV_LENGTH]; // Allow space for padding
        if (EVP_EncryptUpdate(ctx, encrypted, &len, (uint8_t *)msg, strlen(msg)) != 1)
            handle_errors();
        ciphertext_len = len;

        // Finalize encryption (adds padding)
        if (EVP_EncryptFinal_ex(ctx, encrypted + len, &len) != 1)
            handle_errors();
        ciphertext_len += len;

        end_timing(operation_start_time, "[SENDER] AES-256-CBC Encryption", ciphertext_len, "Message encryption");

        EVP_CIPHER_CTX_free(ctx);

        // Create buffer (iv + ciphertext)
        uint8_t buffer[BUFFER_SIZE];
        memcpy(buffer, iv, EVP_MAX_IV_LENGTH);
        memcpy(buffer + EVP_MAX_IV_LENGTH, encrypted, ciphertext_len);
        int total_len = EVP_MAX_IV_LENGTH + ciphertext_len;

        // Create signature of buffer
        size_t siglen;
        uint8_t sig[PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES];

        operation_start_time = start_timing();
        if (PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(sig, &siglen, buffer, total_len, dsa_sk) != 0)
        {
            fprintf(stderr, "[SENDER] ML-DSA signing of message buffer failed\n");
            exit(EXIT_FAILURE);
        }
        end_timing(operation_start_time, "[SENDER] ML-DSA-44 Signature Creation", siglen, "Signing encrypted message");

        // End encryption timing
        end_timing(encryption_start_time, "[SENDER] Encryption and Signature Creation", total_len + siglen, "Encrypting and signing message");

        // Send buffer, siglen and sig
        send(sockfd, buffer, total_len, 0);
        send(sockfd, &siglen, sizeof(size_t), 0);
        send(sockfd, sig, siglen, 0);

        // Track for throughput calculation
        message_count++;
        total_bytes += total_len + sizeof(size_t) + siglen;

        encryption_end_time = start_timing();

        double duration_ms = (encryption_end_time.tv_sec - encryption_start_time.tv_sec) * 1000.0 +
                             (encryption_end_time.tv_nsec - encryption_start_time.tv_nsec) / 1000000.0;
        total_time_ms += duration_ms;

        printf("[SENDER] Encrypted message (%d bytes) and signature (%ld bytes) sent.\n", total_len, siglen);
    }

    // Log throughput metrics at the end if messages were sent
    if (message_count > 0)
    {
        log_throughput("Message Processing Throughput", message_count, total_time_ms, total_bytes);
    }

    if (msg_file)
    {
        fclose(msg_file);
    }

    close(sockfd);
    close_perf_logging();
}

int main(int argc, char *argv[])
{
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    const char *input_file = NULL;

    // Check for input file argument
    if (argc > 1)
    {
        input_file = argv[1];
    }

    sender_process(input_file);

    EVP_cleanup();
    ERR_free_strings();
    return EXIT_SUCCESS;
}
