#include <oqs/oqs.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

double time_diff_ms(struct timespec start, struct timespec end) {
    return (end.tv_sec - start.tv_sec) * 1000.0 +
           (end.tv_nsec - start.tv_nsec) / 1000000.0;
}

void kemtls_handshake_timed(
    const char *alg_name,
    uint8_t *public_key,
    uint8_t *ciphertext,
    uint8_t *shared_secret,
    double *keygen_time,
    double *encap_time,
    double *decap_time
) {
    OQS_KEM *kem = NULL;

    // 🔥 SAFE SELECTION (NO STRING BUG)
    if (strcmp(alg_name, "Kyber512") == 0) {
        kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    } 
    else if (strcmp(alg_name, "Kyber768") == 0) {
        kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
    } 
    else if (strcmp(alg_name, "Kyber1024") == 0) {
        kem = OQS_KEM_new(OQS_KEM_alg_kyber_1024);
    }

    if (kem == NULL) {
        return; // prevents crash
    }

    uint8_t *secret_key = malloc(kem->length_secret_key);

    struct timespec start, end;

    // KeyGen
    clock_gettime(CLOCK_MONOTONIC, &start);
    OQS_KEM_keypair(kem, public_key, secret_key);
    clock_gettime(CLOCK_MONOTONIC, &end);
    *keygen_time = time_diff_ms(start, end);

    // Encapsulation
    clock_gettime(CLOCK_MONOTONIC, &start);
    OQS_KEM_encaps(kem, ciphertext, shared_secret, public_key);
    clock_gettime(CLOCK_MONOTONIC, &end);
    *encap_time = time_diff_ms(start, end);

    // Decapsulation
    clock_gettime(CLOCK_MONOTONIC, &start);
    OQS_KEM_decaps(kem, shared_secret, ciphertext, secret_key);
    clock_gettime(CLOCK_MONOTONIC, &end);
    *decap_time = time_diff_ms(start, end);

    OQS_KEM_free(kem);
    free(secret_key);
}