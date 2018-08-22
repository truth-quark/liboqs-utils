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


EXP_KEM_HEADER = """#ifndef __OQS_KEM_FAKE_ALG_H
#define __OQS_KEM_FAKE_ALG_H

#include <oqs/oqs.h>

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

#ifdef OQS_ENABLE_KEM_Fake_Alg_2

#define OQS_KEM_Fake_Alg_2_length_public_key 50
#define OQS_KEM_Fake_Alg_2_length_secret_key 55
#define OQS_KEM_Fake_Alg_2_length_ciphertext 60
#define OQS_KEM_Fake_Alg_2_length_shared_secret 65

OQS_KEM *OQS_KEM_Fake_Alg_2_new();

extern OQS_STATUS OQS_KEM_Fake_Alg_2_keypair(uint8_t *public_key, uint8_t *secret_key);
extern OQS_STATUS OQS_KEM_Fake_Alg_2_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
extern OQS_STATUS OQS_KEM_Fake_Alg_2_decaps(uint8_t *shared_secret, const unsigned char *ciphertext, const uint8_t *secret_key);

#endif

#endif /* __OQS_KEM_FAKE_ALG_H */
"""


EXP_KEM_SRC_SEGMENT = """#ifdef OQS_ENABLE_KEM_Fake_Alg_1

OQS_KEM *OQS_KEM_Fake_Alg_1_new() {

    OQS_KEM *kem = malloc(sizeof(OQS_KEM));
    if (kem == NULL) {
        return NULL;
    }
    kem->method_name = OQS_KEM_alg_Fake_Alg_1;

    kem->claimed_nist_level = TODO;
    kem->ind_cca = TODO;

    kem->length_public_key = OQS_KEM_Fake_Alg_1_length_public_key;
    kem->length_secret_key = OQS_KEM_Fake_Alg_1_length_secret_key;
    kem->length_ciphertext = OQS_KEM_Fake_Alg_1_length_ciphertext;
    kem->length_shared_secret = OQS_KEM_Fake_Alg_1_length_shared_secret;

    kem->keypair = OQS_KEM_Fake_Alg_1_keypair;
    kem->encaps = OQS_KEM_Fake_Alg_1_encaps;
    kem->decaps = OQS_KEM_Fake_Alg_1_decaps;

    return kem;
}

#endif
"""


EXP_KEM_SRC = """#include <stdlib.h>

#include <oqs/kem_fake.h>

#ifdef OQS_ENABLE_KEM_Fake_Alg_1

OQS_KEM *OQS_KEM_Fake_Alg_1_new() {

    OQS_KEM *kem = malloc(sizeof(OQS_KEM));
    if (kem == NULL) {
        return NULL;
    }
    kem->method_name = OQS_KEM_alg_Fake_Alg_1;

    kem->claimed_nist_level = TODO;
    kem->ind_cca = TODO;

    kem->length_public_key = OQS_KEM_Fake_Alg_1_length_public_key;
    kem->length_secret_key = OQS_KEM_Fake_Alg_1_length_secret_key;
    kem->length_ciphertext = OQS_KEM_Fake_Alg_1_length_ciphertext;
    kem->length_shared_secret = OQS_KEM_Fake_Alg_1_length_shared_secret;

    kem->keypair = OQS_KEM_Fake_Alg_1_keypair;
    kem->encaps = OQS_KEM_Fake_Alg_1_encaps;
    kem->decaps = OQS_KEM_Fake_Alg_1_decaps;

    return kem;
}

#endif

#ifdef OQS_ENABLE_KEM_Fake_Alg_2

OQS_KEM *OQS_KEM_Fake_Alg_2_new() {

    OQS_KEM *kem = malloc(sizeof(OQS_KEM));
    if (kem == NULL) {
        return NULL;
    }
    kem->method_name = OQS_KEM_alg_Fake_Alg_2;

    kem->claimed_nist_level = TODO;
    kem->ind_cca = TODO;

    kem->length_public_key = OQS_KEM_Fake_Alg_2_length_public_key;
    kem->length_secret_key = OQS_KEM_Fake_Alg_2_length_secret_key;
    kem->length_ciphertext = OQS_KEM_Fake_Alg_2_length_ciphertext;
    kem->length_shared_secret = OQS_KEM_Fake_Alg_2_length_shared_secret;

    kem->keypair = OQS_KEM_Fake_Alg_2_keypair;
    kem->encaps = OQS_KEM_Fake_Alg_2_encaps;
    kem->decaps = OQS_KEM_Fake_Alg_2_decaps;

    return kem;
}

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


def get_fake_api_params(pk=10, sk=15, ct=20, ss=25, name='FakeAlg1'):
    params = {'CRYPTO_PUBLICKEYBYTES': pk,
              'CRYPTO_SECRETKEYBYTES': sk,
              'CRYPTO_CIPHERTEXTBYTES': ct,
              'CRYPTO_BYTES': ss,  # shared secret
              'CRYPTO_ALGNAME': name}

    return params


def test_kem_header_segment():
    api_params = get_fake_api_params(name='Fake Alg 1')
    seg = generate.kem_header_segment(api_params)
    assert seg in EXP_KEM_HEADER_SEGMENT  # allow some whitespace leeway


def test_kem_header_file():
    params0 = get_fake_api_params(name='Fake Alg 1')
    params1 = get_fake_api_params(pk=50, sk=55, ct=60, ss=65, name='Fake Alg 2')
    header = generate.kem_header_file('Fake Alg', [params0, params1])
    assert header in EXP_KEM_HEADER


def test_kem_src_segment():
    params0 = get_fake_api_params(name='Fake Alg 1')
    src = generate.kem_src_segment(params0)
    assert src in EXP_KEM_SRC_SEGMENT


def test_kem_src_file():
    params0 = get_fake_api_params(name='Fake Alg 1')
    params1 = get_fake_api_params(name='Fake Alg 2')
    src = generate.kem_src_file('Fake', [params0, params1])
    assert src in EXP_KEM_SRC
