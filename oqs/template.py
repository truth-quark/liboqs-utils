# FIXME: API to WRAPPER

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


API_SRC_SEGMENT_TEMPLATE = """#ifdef OQS_ENABLE_KEM_{CRYPTO_ALGNAME}

OQS_KEM *OQS_KEM_{CRYPTO_ALGNAME}_new() {{

    OQS_KEM *kem = malloc(sizeof(OQS_KEM));
    if (kem == NULL) {{
        return NULL;
    }}
    kem->method_name = OQS_KEM_alg_{CRYPTO_ALGNAME};

    kem->claimed_nist_level = {nist-level};
    kem->ind_cca = {ind-cca};

    kem->length_public_key = OQS_KEM_{CRYPTO_ALGNAME}_length_public_key;
    kem->length_secret_key = OQS_KEM_{CRYPTO_ALGNAME}_length_secret_key;
    kem->length_ciphertext = OQS_KEM_{CRYPTO_ALGNAME}_length_ciphertext;
    kem->length_shared_secret = OQS_KEM_{CRYPTO_ALGNAME}_length_shared_secret;

    kem->keypair = OQS_KEM_{CRYPTO_ALGNAME}_keypair;
    kem->encaps = OQS_KEM_{CRYPTO_ALGNAME}_encaps;
    kem->decaps = OQS_KEM_{CRYPTO_ALGNAME}_decaps;

    return kem;
}}

#endif
"""


API_SRC_TEMPLATE = """#include <stdlib.h>

#include <oqs/kem_{basename}.h>

{segments}"""


# TODO: fix naming
OQS_ALGORITHM_H_TEMPLATE = '''/** Algorithm identifier for {0}. */
#define OQS_KEM_alg_{0} "{0}"'''

# TODO: fix naming
OQS_ALGORITHM_C_TEMPLATE = '''\t}} else if (0 == strcasecmp(method_name, OQS_KEM_alg_{0}) {{
#ifdef OQS_ENABLE_KEM_{0}
\t\treturn OQS_KEM_{0}_new();
#else
\t\treturn NULL;
#endif'''


GLOBAL_SYMBOL_RENAMING_SEGMENT = """crypto_kem_keypair OQS_KEM_{0}_keypair
crypto_kem_enc OQS_KEM_{0}_encaps
crypto_kem_dec OQS_KEM_{0}_decaps"""
