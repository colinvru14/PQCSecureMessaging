#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/err.h>
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

void receiver_process()
{
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    struct timespec operation_start_time, decryption_start_time, decryption_end_time;

    // Initialize performance logging
    init_perf_logging("receiver_perf.csv");

    // ML-KEM-512 key pair generation
    uint8_t kem_pk[PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t kem_sk[PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES];

    operation_start_time = start_timing();
    if (PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(kem_pk, kem_sk) != 0)
    {
        fprintf(stderr, "[RECEIVER] ML-KEM keypair generation failed\n");
        exit(EXIT_FAILURE);
    }
    end_timing(operation_start_time, "[RECEIVER] ML-KEM-512 Keypair Generation", PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES + PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES, "Receiver");
    printf("[RECEIVER] ML-KEM public key generated.\n");

    // ML-DSA-44 key pair generation
    uint8_t dsa_pk[PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t dsa_sk[PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES];

    operation_start_time = start_timing();
    if (PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(dsa_pk, dsa_sk) != 0)
    {
        fprintf(stderr, "[RECEIVER] ML-DSA keypair generation failed\n");
        exit(EXIT_FAILURE);
    }
    end_timing(operation_start_time, "[RECEIVER] ML-DSA-44 Keypair Generation", PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES + PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES, "Receiver");
    printf("[RECEIVER] ML-DSA public key generated.\n");

    // Socket setup
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        perror("[RECEIVER] Socket creation failed");
        exit(EXIT_FAILURE);
    }
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)))
    {
        perror("[RECEIVER] Setsockopt failed");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0)
    {
        perror("[RECEIVER] Bind failed");
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd, 1) < 0)
    {
        perror("[RECEIVER] Listen failed");
        exit(EXIT_FAILURE);
    }
    printf("[RECEIVER] Waiting for sender on port %d...\n", PORT);

    // Accept connection
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0)
    {
        perror("[RECEIVER] Accept failed");
        exit(EXIT_FAILURE);
    }
    printf("[RECEIVER] Sender connected.\n");

    // Send ML-KEM & ML-DSA pk, siglen and sig of ML-KEM pk
    size_t dsa_siglen;
    uint8_t dsa_sig[PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES];

    operation_start_time = start_timing();
    if (PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(dsa_sig, &dsa_siglen, kem_pk,
                                                    PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES,
                                                    dsa_sk) != 0)
    {
        fprintf(stderr, "[RECEIVER] ML-DSA signing failed\n");
        exit(EXIT_FAILURE);
    }
    end_timing(operation_start_time, "[RECEIVER] ML-DSA-44 Signature Creation", dsa_siglen, "Signing ML-KEM public key");
    send(new_socket, kem_pk, PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES, 0);
    send(new_socket, dsa_pk, PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES, 0);
    send(new_socket, &dsa_siglen, sizeof(size_t), 0);
    send(new_socket, dsa_sig, dsa_siglen, 0);
    printf("[RECEIVER] Sent ML-KEM public key and ML-DSA signature.\n");

    // Decapsulate shared secret from sender's ciphertext
    uint8_t ct[PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES];
    uint8_t ss[PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES];
    recv(new_socket, ct, PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES, 0);

    operation_start_time = start_timing();
    if (PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(ss, ct, kem_sk) != 0)
    {
        fprintf(stderr, "[RECEIVER] ML-KEM decapsulation failed\n");
        exit(EXIT_FAILURE);
    }
    end_timing(operation_start_time, "[RECEIVER] ML-KEM-512 Decapsulation", PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES, "Deriving shared secret");
    printf("[RECEIVER] Shared secret derived.\n");

    // Receive sender's ML-DSA pk
    uint8_t sender_dsa_pk[PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES];
    recv(new_socket, sender_dsa_pk, PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES, 0);

    // Receive and decrypt messages
    uint8_t buffer[BUFFER_SIZE];
    int message_count = 0;
    double total_time_ms = 0;
    size_t total_bytes = 0;

    while (1)
    {
        int bytes_received = recv(new_socket, buffer, BUFFER_SIZE, 0);
        if (bytes_received <= 0)
        {
            if (bytes_received == 0)
                printf("[RECEIVER] Sender disconnected.\n");
            else
                perror("[RECEIVER] Receive failed");
            break;
        }

        // Receive the siglen and sig of buffer
        uint8_t sig[PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES];
        size_t siglen;
        recv(new_socket, &siglen, sizeof(size_t), 0);
        recv(new_socket, sig, siglen, 0);

        // Decryption start time
        decryption_start_time = start_timing();

        // Verify buffer signature
        operation_start_time = start_timing();
        if (PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(sig, siglen, buffer, bytes_received, sender_dsa_pk) != 0)
        {
            fprintf(stderr, "[RECEIVER] ML-DSA signature verification of message buffer failed\n");
            close(new_socket);
            close(server_fd);
            exit(EXIT_FAILURE);
        }
        end_timing(operation_start_time, "[RECEIVER] ML-DSA-44 Signature Verification", siglen, "Verifying message signature");

        printf("[RECEIVER] Received ciphertext (%d bytes) and signature (%ld bytes).\n", bytes_received, siglen);
        printf("[RECEIVER] Successfully verified ciphertext signature.\n");

        // Extract IV and ciphertext
        uint8_t iv[EVP_MAX_IV_LENGTH];
        memcpy(iv, buffer, EVP_MAX_IV_LENGTH);
        int ct_len = bytes_received - EVP_MAX_IV_LENGTH;
        uint8_t *ciphertext = buffer + EVP_MAX_IV_LENGTH;

        // Set up decryption context
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx)
            handle_errors();

        // Decrypt message with timing
        operation_start_time = start_timing();

        // Initialize decryption operation
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, ss, iv) != 1)
            handle_errors();

        // Decrypt message
        int len, plaintext_len;
        uint8_t decrypted[BUFFER_SIZE];
        if (EVP_DecryptUpdate(ctx, decrypted, &len, ciphertext, ct_len) != 1)
            handle_errors();
        plaintext_len = len;

        // Finalize decryption (removes padding)
        int ret = EVP_DecryptFinal_ex(ctx, decrypted + len, &len);
        if (ret > 0)
        {
            plaintext_len += len;
            decrypted[plaintext_len] = '\0'; // Null-terminate
            end_timing(operation_start_time, "[RECEIVER] AES-256-CBC Decryption", ct_len, "Message decryption");
            end_timing(decryption_start_time, "[RECEIVER] Decryption and Signature Verification", bytes_received + siglen + sizeof(size_t), "Decrypting and verifying.");

            printf("[RECEIVER] Decrypted message: %s\n", decrypted);

            // Decryption end time
            decryption_end_time = start_timing();

            // Track for throughput calculation
            message_count++;
            total_bytes += bytes_received + siglen + sizeof(size_t);

            double duration_ms = (decryption_end_time.tv_sec - decryption_start_time.tv_sec) * 1000.0 +
                                 (decryption_end_time.tv_nsec - decryption_start_time.tv_nsec) / 1000000.0;
            total_time_ms += duration_ms;
        }
        else
        {
            printf("[RECEIVER] Decryption failed - invalid padding or corrupted data\n");
            printf("Raw ciphertext (hex): ");
            for (int i = 0; i < ct_len; i++)
            {
                printf("%02x ", ciphertext[i]);
            }
            printf("\n");
        }

        EVP_CIPHER_CTX_free(ctx);
    }

    // Log throughput metrics at the end if messages were received
    if (message_count > 0)
    {
        log_throughput("Message Processing Throughput", message_count, total_time_ms, total_bytes);
    }

    close(new_socket);
    close(server_fd);
    close_perf_logging();
}

int main()
{
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    receiver_process();
    EVP_cleanup();
    ERR_free_strings();
    return EXIT_SUCCESS;
}
