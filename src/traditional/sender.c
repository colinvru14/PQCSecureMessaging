#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#define KEY_LENGTH  2048
#define PUB_EXP     3
#define PORT        9090
#define BUFFER_SIZE 4096
#define LOG_FILE    "sender_timing.log"

// Error handling function
void handle_errors() {
    ERR_load_crypto_strings();
    char err[130];
    ERR_error_string(ERR_get_error(), err);
    fprintf(stderr, "Error: %s\n", err);
}

// Generate RSA key pair and return it
RSA* generate_key_pair() {
    printf("Generating RSA (%d bits) keypair...\n", KEY_LENGTH);
    RSA *keypair = RSA_generate_key(KEY_LENGTH, PUB_EXP, NULL, NULL);
    if (keypair == NULL) {
        handle_errors();
        exit(EXIT_FAILURE);
    }
    printf("Key pair generated successfully.\n");
    return keypair;
}

// Convert RSA public key to PEM format string
char* get_public_key_PEM(RSA *keypair, size_t *len) {
    BIO *pub = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPublicKey(pub, keypair);

    *len = BIO_pending(pub);
    char *pub_key = malloc(*len + 1);
    BIO_read(pub, pub_key, *len);
    pub_key[*len] = '\0';

    BIO_free(pub);
    return pub_key;
}

int sign_message(RSA *keypair, const unsigned char *msg, unsigned int msg_len, unsigned char **signature, size_t *sig_len) {
    *sig_len = RSA_size(keypair);
    *signature = malloc(*sig_len);

    if (*signature == NULL) {
        perror("Memory allocation failed");
        return 0;
    }

    if (RSA_sign(NID_sha256, msg, msg_len, *signature, (unsigned int *)sig_len, keypair) != 1) {
        handle_errors();
        free(*signature);
        return 0;
    }

    return 1;
}

// Function to log timing information
void log_timing(long long time_taken_ns) {
    FILE *log_file = fopen(LOG_FILE, "a");
    if (log_file == NULL) {
        perror("Failed to open log file");
        return;
    }

    time_t now;
    time(&now);
    char timestamp[30];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));

    fprintf(log_file, "%lld\n",time_taken_ns);
    fclose(log_file);
}

// Sender process function
void sender_process() {
    int sockfd;
    struct sockaddr_in server_addr;

    // Generate RSA key pair
    RSA *keypair = generate_key_pair();

    // Get public key in PEM format
    size_t pub_len;
    char *pub_key = get_public_key_PEM(keypair, &pub_len);
    printf("[SENDER] Sender's public key:\n%s\n", pub_key);

    // Create socket
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("[SENDER] Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Set up server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    // Connect to receiver
    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("[SENDER] Connection failed");
        exit(EXIT_FAILURE);
    }
    printf("[SENDER] Connected to receiver.\n");

    // Send public key to receiver
    send(sockfd, pub_key, pub_len, 0);
    printf("[SENDER] Public key sent to receiver.\n");

    // Receive receiver's public key
    char receiver_pub_key[BUFFER_SIZE];
    int bytes_received = recv(sockfd, receiver_pub_key, BUFFER_SIZE, 0);
    receiver_pub_key[bytes_received] = '\0';
    printf("[SENDER] Received receiver's public key:\n%s\n", receiver_pub_key);

    // Convert PEM string to RSA public key
    BIO *bio = BIO_new(BIO_s_mem());
    BIO_puts(bio, receiver_pub_key);
    RSA *receiver_key = PEM_read_bio_RSAPublicKey(bio, NULL, NULL, NULL);
    if (receiver_key == NULL) {
        handle_errors();
        exit(EXIT_FAILURE);
    }

    // Loop to keep sending messages
    while (1) {
        // Get message to encrypt
        char msg[KEY_LENGTH/8];
        printf("[SENDER] Enter message to encrypt and send (or 'quit' to exit): ");

        // Start timing
        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);

        fgets(msg, KEY_LENGTH/8 - 1, stdin);
        msg[strlen(msg)-1] = '\0';
        
        if (strcmp(msg, "quit") == 0) {
            printf("[SENDER] Exiting...\n");
            break;
        }

        // Sign the message
        unsigned char *signature;
        unsigned int sig_len;
        if (!sign_message(keypair, (unsigned char*)msg, strlen(msg), &signature, &sig_len)) {
            printf("[SENDER] Message signing failed.\n");
            continue;
        }
        printf("[SENDER] Message signed successfully.\n");

        // Encrypt message with receiver's public key
        char *encrypted = malloc(RSA_size(receiver_key));
        int encrypt_len = RSA_public_encrypt(strlen(msg)+1, (unsigned char*)msg,
                                            (unsigned char*)encrypted,
                                            receiver_key, RSA_PKCS1_OAEP_PADDING);
        if (encrypt_len == -1) {
            handle_errors();
            free(encrypted);
            continue;
        }

        // End timing
        clock_gettime(CLOCK_MONOTONIC, &end);
        long long time_taken_ns = (end.tv_sec - start.tv_sec) * 1000000000LL +
                                (end.tv_nsec - start.tv_nsec);
        // Log timing information
        log_timing(time_taken_ns);

        // Send encrypted message
        send(sockfd, encrypted, encrypt_len, 0);
        printf("[SENDER] Encrypted message sent.\n");

        // Send signature size
        send(sockfd, &sig_len, sizeof(unsigned int), 0);

        // Send signature
        send(sockfd, signature, sig_len, 0);
        printf("[SENDER] Signature sent (%d bytes).\n", sig_len);

        // Wait for acknowledgment from receiver
        char ack[4] = {0};
        int ack_bytes = recv(sockfd, ack, 3, 0);
        if (ack_bytes > 0) {
            ack[ack_bytes] = '\0';
        }

        if (ack_bytes > 0 && strcmp(ack, "ACK") == 0) {
            printf("[SENDER] Received acknowledgment from receiver.\n");
        } else {
            printf("[SENDER] Error: Did not receive acknowledgment from receiver.\n");
            break;
        }

        for(int i = 0; i < 0; i++) {}
        printf("\n");

        free(encrypted);
        free(signature);
    }

    // Clean up
    free(pub_key);
    RSA_free(keypair);
    RSA_free(receiver_key);
    BIO_free(bio);
    close(sockfd);
}

int main() {
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    sender_process();

    // Clean up OpenSSL
    EVP_cleanup();
    ERR_free_strings();

    return EXIT_SUCCESS;
}
