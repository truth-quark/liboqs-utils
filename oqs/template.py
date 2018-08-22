API_HEADER_SEGMENT_TEMPLATE = """#ifdef OQS_ENABLE_KEM_{CRYPTO_ALGNAME}

#define OQS_KEM_{CRYPTO_ALGNAME}_length_public_key {CRYPTO_PUBLICKEYBYTES}
#define OQS_KEM_{CRYPTO_ALGNAME}_length_secret_key {CRYPTO_SECRETKEYBYTES}
#define OQS_KEM_{CRYPTO_ALGNAME}_length_ciphertext {CRYPTO_CIPHERTEXTBYTES}
#define OQS_KEM_{CRYPTO_ALGNAME}_length_shared_secret {CRYPTO_BYTES}

OQS_KEM *OQS_KEM_{CRYPTO_ALGNAME}_new();

extern OQS_STATUS OQS_KEM_{CRYPTO_ALGNAME}_keypair(uint8_t *public_key, uint8_t *secret_key);
extern OQS_STATUS OQS_KEM_{CRYPTO_ALGNAME}_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
extern OQS_STATUS OQS_KEM_{CRYPTO_ALGNAME}_decaps(uint8_t *shared_secret, const unsigned char *ciphertext, const uint8_t *secret_key);

#endif
"""

API_HEADER_TEMPLATE = """#ifndef __OQS_KEM_{BASENAME}_H
#define __OQS_KEM_{BASENAME}_H

#include <oqs/oqs.h>

{segments}
#endif /* __OQS_KEM_{BASENAME}_H */
"""
