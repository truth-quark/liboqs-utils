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


EXP_KEM_HEADER_SEGMENT = """
#ifdef OQS_ENABLE_KEM_Fake_Alg_1

#define OQS_KEM_Fake_Alg_1_length_public_key 10
#define OQS_KEM_Fake_Alg_1_length_secret_key 15
#define OQS_KEM_Fake_Alg_1_length_ciphertext 20
#define OQS_KEM_Fake_Alg_1_length_shared_secret 25

OQS_KEM *OQS_KEM_Fake_Alg_1_new();

extern OQS_STATUS OQS_KEM_Fake_Alg_1_keypair(uint8_t *public_key, uint8_t *secret_key);
extern OQS_STATUS OQS_KEM_Fake_Alg_1_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
extern OQS_STATUS OQS_KEM_Fake_Alg_1_decaps(uint8_t *shared_secret, const unsigned char *ciphertext, const uint8_t *secret_key);

#endif
"""


def test_parse_api_header():
    res = generate.parse_api_header(FAKE_API_HEADER)
    assert len(res) == 5
    assert res['CRYPTO_SECRETKEYBYTES'] == '1'
    assert res['CRYPTO_PUBLICKEYBYTES'] == '2'
    assert res['CRYPTO_BYTES'] == '3'
    assert res['CRYPTO_CIPHERTEXTBYTES'] == '4'
    assert res['CRYPTO_ALGNAME'] == 'NAME'


def get_fake_api_params(pk='10', sk='15', ct='20', ss='25', name='FakeAlg1'):
    params = {'CRYPTO_PUBLICKEYBYTES': pk,
              'CRYPTO_SECRETKEYBYTES': sk,
              'CRYPTO_CIPHERTEXTBYTES': ct,
              'CRYPTO_BYTES': ss,  # shared secret
              'CRYPTO_ALGNAME': name}

    return params


# TODO: handle spaces in names
def test_kem_header_segment():
    api_params = get_fake_api_params(name='Fake Alg 1')
    header = generate.kem_header_segment(api_params)
    assert header in EXP_KEM_HEADER_SEGMENT  # allow some whitespace leeway
