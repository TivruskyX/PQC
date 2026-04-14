#include <oqs/oqs.h>
#include <string.h>
#include <stdlib.h>

void signature_test(
    uint8_t *message,
    size_t message_len,
    uint8_t *public_key,
    uint8_t *signature,
    uint8_t *result
) {
    OQS_SIG *sig = OQS_SIG_new("ML-DSA-44");

    uint8_t *secret_key = malloc(sig->length_secret_key);

    // Key generation
    OQS_SIG_keypair(sig, public_key, secret_key);

    // Sign
    size_t sig_len;
    OQS_SIG_sign(sig, signature, &sig_len, message, message_len, secret_key);

    // Verify
    int is_valid = OQS_SIG_verify(sig, message, message_len, signature, sig_len, public_key);

    result[0] = (is_valid == OQS_SUCCESS);

    OQS_SIG_free(sig);
    free(secret_key);
}
