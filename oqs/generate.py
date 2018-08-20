import string

CRYPTO_SECRETKEYBYTES = 'CRYPTO_SECRETKEYBYTES'
CRYPTO_PUBLICKEYBYTES = 'CRYPTO_PUBLICKEYBYTES'
CRYPTO_BYTES = 'CRYPTO_BYTES'
CRYPTO_CIPHERTEXTBYTES = 'CRYPTO_CIPHERTEXTBYTES'
CRYPTO_ALGNAME = 'CRYPTO_ALGNAME'

KEYWORDS = [CRYPTO_SECRETKEYBYTES, CRYPTO_PUBLICKEYBYTES,
            CRYPTO_BYTES, CRYPTO_CIPHERTEXTBYTES, CRYPTO_ALGNAME]


def parse_api_header(content):
    """
    Extract defined vars from NIST api.h
    :content string of the entire header file
    """
    result = {}
    for line in content.split('\n'):
        for kw in KEYWORDS:
            if kw in line:
                _, _, value = line.strip().split()
                value = value.strip()

                if kw == CRYPTO_ALGNAME:
                    assert value[0] == value[-1] == '"'
                    value = value[1:-1]

                result[kw] = value
                break

    return result


# TODO: move to template file
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


def has_whitespace(s):
    """Returns True if string contains whitespace."""
    for c in string.whitespace:
        if c in s:
            return True
    return False


def kem_header_segment(params):
    """Returns algorithm header segment text for specific algorithm strength."""
    if has_whitespace(params[CRYPTO_ALGNAME]):
        sanitised = params[CRYPTO_ALGNAME].replace(' ', '_')
        params[CRYPTO_ALGNAME] = sanitised

    return API_HEADER_SEGMENT_TEMPLATE.format_map(params)
