#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include "x86_64/ml-kem-512/api.h"
#include "x86_64/ml-dsa-44/api.h"

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT        9090
#define BUFFER_SIZE 4096

// Error handling for OpenSSL
void handle_errors() {
    ERR_load_crypto_strings();
    char err[130];
    ERR_error_string(ERR_get_error(), err);
    fprintf(stderr, "Error: %s\n", err);
    exit(EXIT_FAILURE);
}

void receiver_process() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    // ML-KEM-512 key pair generation
    uint8_t kem_pk[PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t kem_sk[PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES];
    if (PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(kem_pk, kem_sk) != 0) {
        fprintf(stderr, "[RECEIVER] ML-KEM keypair generation failed\n");
        exit(EXIT_FAILURE);
    }
    printf("[RECEIVER] ML-KEM public key generated.\n");

    // ML-DSA-44 key pair generation
    uint8_t dsa_pk[PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t dsa_sk[PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES];
    if (PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(dsa_pk, dsa_sk) != 0) {
        fprintf(stderr, "[RECEIVER] ML-DSA keypair generation failed\n");
        exit(EXIT_FAILURE);
    }
    printf("[RECEIVER] ML-DSA public key generated.\n");

    // Socket setup
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("[RECEIVER] Socket creation failed");
        exit(EXIT_FAILURE);
    }
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("[RECEIVER] Setsockopt failed");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("[RECEIVER] Bind failed");
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd, 1) < 0) {
        perror("[RECEIVER] Listen failed");
        exit(EXIT_FAILURE);
    }
    printf("[RECEIVER] Waiting for sender on port %d...\n", PORT);

    // Accept connection
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
        perror("[RECEIVER] Accept failed");
        exit(EXIT_FAILURE);
    }
    printf("[RECEIVER] Sender connected.\n");

    // Receive sender's ML-KEM public key and ML-DSA signature
    uint8_t sender_kem_pk[PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t sender_dsa_pk[PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t sig[PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES];
    size_t siglen;
    recv(new_socket, sender_kem_pk, PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES, 0);
    recv(new_socket, sender_dsa_pk, PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES, 0);
    recv(new_socket, &siglen, sizeof(size_t), 0);
    recv(new_socket, sig, siglen, 0);

    // Verify sender's ML-KEM public key with ML-DSA signature
    if (PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(sig, siglen, sender_kem_pk,
                                                 PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES,
                                                 sender_dsa_pk) != 0) {
        fprintf(stderr, "[RECEIVER] ML-DSA signature verification failed\n");
        close(new_socket);
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    printf("[RECEIVER] Sender's ML-KEM public key verified.\n");

    // Send receiver's ML-KEM public key and ML-DSA signature
    size_t dsa_siglen;
    uint8_t dsa_sig[PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES];
    if (PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(dsa_sig, &dsa_siglen, kem_pk,
                                                    PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES,
                                                    dsa_sk) != 0) {
        fprintf(stderr, "[RECEIVER] ML-DSA signing failed\n");
        exit(EXIT_FAILURE);
    }
    send(new_socket, kem_pk, PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES, 0);
    send(new_socket, dsa_pk, PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES, 0);
    send(new_socket, &dsa_siglen, sizeof(size_t), 0);
    send(new_socket, dsa_sig, dsa_siglen, 0);
    printf("[RECEIVER] Sent ML-KEM public key and ML-DSA signature.\n");

    // Decapsulate shared secret from sender's ciphertext
    uint8_t ct[PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES];
    uint8_t ss[PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES];
    recv(new_socket, ct, PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES, 0);
    if (PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(ss, ct, kem_sk) != 0) {
        fprintf(stderr, "[RECEIVER] ML-KEM decapsulation failed\n");
        exit(EXIT_FAILURE);
    }
    printf("[RECEIVER] Shared secret derived.\n");

    // Set up AES key
    AES_KEY aes_key;
    if (AES_set_decrypt_key(ss, 256, &aes_key) != 0) {
        handle_errors();
    }

    // Receive and decrypt messages
    uint8_t buffer[BUFFER_SIZE];
    while (1) {
        int bytes_received = recv(new_socket, buffer, BUFFER_SIZE, 0);
        if (bytes_received <= 0) {
            if (bytes_received == 0) printf("[RECEIVER] Sender disconnected.\n");
            else perror("[RECEIVER] Receive failed");
            break;
        }

        // Extract IV (16 bytes) and ciphertext
        uint8_t iv[AES_BLOCK_SIZE];
        memcpy(iv, buffer, AES_BLOCK_SIZE);
        int ct_len = bytes_received - AES_BLOCK_SIZE;
        uint8_t *ciphertext = buffer + AES_BLOCK_SIZE;
        uint8_t decrypted[BUFFER_SIZE];

        // Decrypt with AES-CBC
        AES_cbc_encrypt(ciphertext, decrypted, ct_len, &aes_key, iv, AES_DECRYPT);
        decrypted[ct_len] = '\0'; // Null-terminate (assuming text)
        printf("[RECEIVER] Decrypted message: %s\n", decrypted);
    }

    close(new_socket);
    close(server_fd);
}

int main() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    receiver_process();
    EVP_cleanup();
    ERR_free_strings();
    return EXIT_SUCCESS;
}
