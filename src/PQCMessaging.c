#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "x86_64/ml-kem-512/api.h"
#include "x86_64/ml-dsa-44/api.h"

// Error handling macro
#define CHECK(x) if ((x) != 0) { printf("Error at %s:%d\n", __FILE__, __LINE__); exit(1); }

int main() {
    // Buffers for Kyber (ML-KEM-512)
    uint8_t pk_kyber[PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES];      // Public key
    uint8_t sk_kyber[PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES];      // Secret key
    uint8_t ct[PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES];           // Ciphertext
    uint8_t ss_a[PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES];                   // Shared secret (Alice)
    uint8_t ss_b[PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES];                   // Shared secret (Bob)

    // Buffers for Dilithium (ML-DSA-44)
    uint8_t pk_dil[PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES];         // Public key
    uint8_t sk_dil[PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES];         // Secret key
    uint8_t sig[PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES];                     // Signature
    size_t siglen;

    // Simulate Alice: Generate Kyber keypair
    CHECK(PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(pk_kyber, sk_kyber));

    // Simulate Alice: Encapsulate a shared secret
    CHECK(PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(ct, ss_a, pk_kyber));

    // Simulate Alice: Generate Dilithium keypair and sign the ciphertext
    CHECK(PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk_dil, sk_dil));
    CHECK(PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(sig, &siglen, ct,
            PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES, sk_dil));

    // Simulate Bob: Verify the signature
    if (PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(sig, siglen, ct,
            PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES, pk_dil) != 0) {
        printf("Signature verification failed!\n");
        return 1;
    }

    // Simulate Bob: Decapsulate the shared secret
    CHECK(PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(ss_b, ct, sk_kyber));

    // Verify shared secrets match
    if (memcmp(ss_a, ss_b, PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES) != 0) {
        printf("Shared secrets do not match!\n");
        return 1;
    }
    printf("Shared secret established: ");
    for (int i = 0; i < PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES; i++) printf("%02x", ss_a[i]);
    printf("\n");

    return 0;
}
