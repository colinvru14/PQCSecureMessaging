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

void sender_process() {
    int sockfd;
    struct sockaddr_in server_addr;

    // ML-KEM-512 key pair generation
    uint8_t kem_pk[PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t kem_sk[PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES];
    if (PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(kem_pk, kem_sk) != 0) {
        fprintf(stderr, "[SENDER] ML-KEM keypair generation failed\n");
        exit(EXIT_FAILURE);
    }
    printf("[SENDER] ML-KEM public key generated.\n");

    // ML-DSA-44 key pair generation
    uint8_t dsa_pk[PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t dsa_sk[PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES];
    if (PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(dsa_pk, dsa_sk) != 0) {
        fprintf(stderr, "[SENDER] ML-DSA keypair generation failed\n");
        exit(EXIT_FAILURE);
    }
    printf("[SENDER] ML-DSA public key generated.\n");

    // Socket setup
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("[SENDER] Socket creation failed");
        exit(EXIT_FAILURE);
    }
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;
    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
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
    if (PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(receiver_sig, receiver_siglen,
                                                 receiver_kem_pk,
                                                 PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES,
                                                 receiver_dsa_pk) != 0) {
        fprintf(stderr, "[SENDER] ML-DSA signature verification failed\n");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    printf("[SENDER] Receiver's ML-KEM public key verified.\n");

    // Encapsulate shared secret with receiver's public key
    uint8_t ct[PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES];
    uint8_t ss[PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES];
    if (PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(ct, ss, receiver_kem_pk) != 0) {
        fprintf(stderr, "[SENDER] ML-KEM encapsulation failed\n");
        exit(EXIT_FAILURE);
    }
    send(sockfd, ct, PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES, 0);
    printf("[SENDER] Shared secret encapsulated and sent.\n");

    // Send ML-DSA pk
    send(sockfd, dsa_pk, PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES, 0);

    // Send encrypted messages
    while (1) {
    	// In the message sending loop:
    	char msg[BUFFER_SIZE];
    	printf("[SENDER] Enter message (or 'quit' to exit): ");
    	fgets(msg, BUFFER_SIZE - 1, stdin);
    	msg[strlen(msg) - 1] = '\0'; // Remove newline

    	if (strcmp(msg, "quit") == 0) {
    	    printf("[SENDER] Exiting...\n");
    	    break;
    	}

    	// Generate random IV
    	uint8_t iv[EVP_MAX_IV_LENGTH];
    	if (RAND_bytes(iv, EVP_MAX_IV_LENGTH) != 1) {
    	    handle_errors();
    	}

    	// Set up encryption context
    	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    	if (!ctx) handle_errors();

    	// Initialize encryption operation with AES-256-CBC
    	if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, ss, iv) != 1)
    	    handle_errors();

    	// Encrypt message - the EVP interface handles padding automatically
    	int len, ciphertext_len;
    	uint8_t encrypted[BUFFER_SIZE + EVP_MAX_IV_LENGTH]; // Allow space for padding
    	if (EVP_EncryptUpdate(ctx, encrypted, &len, (uint8_t*)msg, strlen(msg)) != 1)
    	    handle_errors();
    	ciphertext_len = len;

    	// Finalize encryption (adds padding)
    	if (EVP_EncryptFinal_ex(ctx, encrypted + len, &len) != 1)
    	    handle_errors();
    	ciphertext_len += len;

    	EVP_CIPHER_CTX_free(ctx);

    	// Create buffer (iv + ciphertext)
    	uint8_t buffer[BUFFER_SIZE];
    	memcpy(buffer, iv, EVP_MAX_IV_LENGTH);
    	memcpy(buffer + EVP_MAX_IV_LENGTH, encrypted, ciphertext_len);
    	int total_len = EVP_MAX_IV_LENGTH + ciphertext_len;

    	// Create signature of buffer
		size_t siglen;
		uint8_t sig[PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES];
		if (PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(sig, &siglen, buffer, total_len, dsa_sk) != 0) {
			fprintf(stderr, "[SENDER] ML-DSA signing of message buffer failed\n");
			exit(EXIT_FAILURE);
		}

		// Send buffer, siglen and sig
    	send(sockfd, buffer, total_len, 0);
    	send(sockfd, &siglen, sizeof(size_t), 0);
    	send(sockfd, sig, siglen, 0);

    	printf("[SENDER] Encrypted message (%d bytes) and signature (%ld bytes) sent.\n", total_len, siglen);
    }

    close(sockfd);
}

int main() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    sender_process();
    EVP_cleanup();
    ERR_free_strings();
    return EXIT_SUCCESS;
}
