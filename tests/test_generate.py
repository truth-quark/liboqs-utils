from oqs import generate


FAKE_API_HEADER = """
#ifndef api_h
#define api_h
#define CRYPTO_SECRETKEYBYTES 1
#define CRYPTO_PUBLICKEYBYTES 2
#define CRYPTO_BYTES 3
#define CRYPTO_CIPHERTEXTBYTES 4
#define CRYPTO_ALGNAME "NAME"

int crypto_kem_keypair(unsigned char *pk, unsigned char *sk);
int crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
int crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);
#endif
"""


def test_parse_api_header():
    res = generate.parse_api_header(FAKE_API_HEADER)
    assert len(res) == 5
    assert res['CRYPTO_SECRETKEYBYTES'] == '1'
    assert res['CRYPTO_PUBLICKEYBYTES'] == '2'
    assert res['CRYPTO_BYTES'] == '3'
    assert res['CRYPTO_CIPHERTEXTBYTES'] == '4'
    assert res['CRYPTO_ALGNAME'] == '"NAME"'
