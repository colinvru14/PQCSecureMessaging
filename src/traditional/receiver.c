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

#define KEY_LENGTH  2048
#define PUB_EXP     3
#define PORT        9090
#define BUFFER_SIZE 4096

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

// Receiver process function
void receiver_process() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    
    // Generate RSA key pair
    RSA *keypair = generate_key_pair();
    
    // Get public key in PEM format
    size_t pub_len;
    char *pub_key = get_public_key_PEM(keypair, &pub_len);
    printf("[RECEIVER] Receiver's public key:\n%s\n", pub_key);
    
    // Create socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("[RECEIVER] Socket creation failed");
        exit(EXIT_FAILURE);
    }
    
    // Set socket options
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("[RECEIVER] Setsockopt failed");
        exit(EXIT_FAILURE);
    }
    
    // Set up address
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);
    
    // Bind socket
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("[RECEIVER] Bind failed");
        exit(EXIT_FAILURE);
    }
    
    // Listen for connections
    if (listen(server_fd, 1) < 0) {
        perror("[RECEIVER] Listen failed");
        exit(EXIT_FAILURE);
    }
    printf("[RECEIVER] Receiver waiting for sender connection on port %d...\n", PORT);
    
    // Accept connection
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
        perror("[RECEIVER] Accept failed");
        exit(EXIT_FAILURE);
    }
    printf("[RECEIVER] Sender connected.\n");
    
    // Receive sender's public key
    char sender_pub_key[BUFFER_SIZE];
    int bytes_received = recv(new_socket, sender_pub_key, BUFFER_SIZE, 0);
    sender_pub_key[bytes_received] = '\0';
    printf("[RECEIVER] Received sender's public key:\n%s\n", sender_pub_key);
    
    // Send public key to sender
    send(new_socket, pub_key, pub_len, 0);
    printf("[RECEIVER] Public key sent to sender.\n");
    
    // Convert PEM string to RSA public key
    BIO *bio = BIO_new(BIO_s_mem());
    BIO_puts(bio, sender_pub_key);
    RSA *sender_key = PEM_read_bio_RSAPublicKey(bio, NULL, NULL, NULL);
    if (sender_key == NULL) {
        handle_errors();
        exit(EXIT_FAILURE);
    }
    
    // Loop to keep receiving messages
    char encrypted[BUFFER_SIZE];
    while (1) {
        printf("\n[RECEIVER] Waiting for new message from sender...\n");
        // Receive encrypted message
        bytes_received = recv(new_socket, encrypted, BUFFER_SIZE, 0);
        if (bytes_received <= 0) {
            if (bytes_received == 0) {
                printf("[RECEIVER] Sender disconnected.\n");
            } else {
                perror("[RECEIVER] Receive failed");
            }
            break;
        }
        
        printf("[RECEIVER] Received encrypted message (%d bytes).\n", bytes_received);
        
        // Decrypt message
        char *decrypted = malloc(bytes_received);
        int decrypt_len = RSA_private_decrypt(bytes_received, (unsigned char*)encrypted, 
                                             (unsigned char*)decrypted,
                                             keypair, RSA_PKCS1_OAEP_PADDING);
        if (decrypt_len == -1) {
            handle_errors();
            free(decrypted);
            continue;
        }
        
        printf("[RECEIVER] Decrypted message: %s\n", decrypted);
        free(decrypted);
    }
    
    // Clean up
    free(pub_key);
    RSA_free(keypair);
    RSA_free(sender_key);
    BIO_free(bio);
    close(new_socket);
    close(server_fd);
}

int main() {
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    
    receiver_process();
    
    // Clean up OpenSSL
    EVP_cleanup();
    ERR_free_strings();
    
    return EXIT_SUCCESS;
}
