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
                result[kw] = value.strip()
                break

    return result

