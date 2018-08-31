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


EXP_KEM_H = """/** Algorithm identifier for default KEM algorithm. */
#define OQS_KEM_alg_default "DEFAULT"
/** Algorithm identifier for Lima-sp-2062 CCA KEM. */
#define OQS_KEM_alg_lima_sp_2062_cca_kem "Lima-sp-2062-CCA-KEM"
/** Algorithm identifier for Fake_Alg_1. */
#define OQS_KEM_alg_Fake_Alg_1 "Fake_Alg_1"
/** Algorithm identifier for Fake_Alg_2. */
#define OQS_KEM_alg_Fake_Alg_2 "Fake_Alg_2"
// EDIT-WHEN-ADDING-KEM
/** Number of algorithm identifiers above. */
#define OQS_KEM_algs_length 4

#include <oqs/kem_lima.h>
#include <oqs/kem_fake.h>
// EDIT-WHEN-ADDING-KEM
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


def test_kem_header_add_new_algorithm():
    cont = '/** Algorithm identifier for default KEM algorithm. */\n' \
           '#define OQS_KEM_alg_default "DEFAULT"\n' \
           '/** Algorithm identifier for Lima-sp-2062 CCA KEM. */\n' \
           '#define OQS_KEM_alg_lima_sp_2062_cca_kem "Lima-sp-2062-CCA-KEM"\n' \
           '// EDIT-WHEN-ADDING-KEM\n' \
           '/** Number of algorithm identifiers above. */\n' \
           '#define OQS_KEM_algs_length 2\n\n' \
           '#include <oqs/kem_lima.h>\n' \
           '// EDIT-WHEN-ADDING-KEM\n'

    params0 = get_fake_api_params(name='Fake Alg 1')
    params1 = get_fake_api_params(name='Fake Alg 2')
    result = generate.kem_header_add_new_algorithm('fake', cont, [params0, params1])
    assert result == EXP_KEM_H


ORIG_KEM_C_SEGMENT = '''char *OQS_KEM_alg_identifier(size_t i) {
\t// EDIT-WHEN-ADDING-KEM
\tchar *a[OQS_KEM_algs_length] = {
\t    OQS_KEM_alg_default,
\t    OQS_KEM_alg_frodokem_640_aes, OQS_KEM_alg_frodokem_976_aes};
\tif (i >= OQS_KEM_algs_length) {
\t\treturn NULL;
\t} else {
\t\treturn a[i];
\t}
}

OQS_KEM *OQS_KEM_new(const char *method_name) {
\tif (0 == strcasecmp(method_name, OQS_KEM_alg_default)) {
\t\treturn OQS_KEM_new(OQS_KEM_DEFAULT);
\t} else if (0 == strcasecmp(method_name, OQS_KEM_alg_lima_sp_2062_cca_kem)) {
#ifdef OQS_ENABLE_KEM_lima_sp_2062_cca_kem
\t\treturn OQS_KEM_lima_sp_2062_cca_kem_new();
#else
\t\treturn NULL;
#endif
\t\t// EDIT-WHEN-ADDING-KEM
\t} else {
\t\treturn NULL;
\t}
}
'''

EXP_KEM_C_SEGMENT = '''char *OQS_KEM_alg_identifier(size_t i) {
\t// EDIT-WHEN-ADDING-KEM
\tchar *a[OQS_KEM_algs_length] = {
\t    OQS_KEM_alg_default,
\t    OQS_KEM_alg_Fake_Alg_1, OQS_KEM_alg_Fake_Alg_2,
\t    OQS_KEM_alg_frodokem_640_aes, OQS_KEM_alg_frodokem_976_aes};
\tif (i >= OQS_KEM_algs_length) {
\t\treturn NULL;
\t} else {
\t\treturn a[i];
\t}
}

OQS_KEM *OQS_KEM_new(const char *method_name) {
\tif (0 == strcasecmp(method_name, OQS_KEM_alg_default)) {
\t\treturn OQS_KEM_new(OQS_KEM_DEFAULT);
\t} else if (0 == strcasecmp(method_name, OQS_KEM_alg_lima_sp_2062_cca_kem)) {
#ifdef OQS_ENABLE_KEM_lima_sp_2062_cca_kem
\t\treturn OQS_KEM_lima_sp_2062_cca_kem_new();
#else
\t\treturn NULL;
#endif
\t} else if (0 == strcasecmp(method_name, OQS_KEM_alg_Fake_Alg_1) {
#ifdef OQS_ENABLE_KEM_Fake_Alg_1
\t\treturn OQS_KEM_Fake_Alg_1_new();
#else
\t\treturn NULL;
#endif
\t} else if (0 == strcasecmp(method_name, OQS_KEM_alg_Fake_Alg_2) {
#ifdef OQS_ENABLE_KEM_Fake_Alg_2
\t\treturn OQS_KEM_Fake_Alg_2_new();
#else
\t\treturn NULL;
#endif
\t\t// EDIT-WHEN-ADDING-KEM
\t} else {
\t\treturn NULL;
\t}
}
'''


def test_kem_src_add_new_algorithm():
    params0 = get_fake_api_params(name='Fake Alg 1')
    params1 = get_fake_api_params(name='Fake Alg 2')
    result = generate.kem_src_add_new_algorithm(ORIG_KEM_C_SEGMENT, [params0, params1])
    assert result == EXP_KEM_C_SEGMENT


def test_kem_src_add_new_algorithm_already_done():
    params0 = get_fake_api_params(name='Fake Alg 1')
    params1 = get_fake_api_params(name='Fake Alg 2')
    result = generate.kem_src_add_new_algorithm(EXP_KEM_C_SEGMENT, [params0, params1])
    assert result == EXP_KEM_C_SEGMENT


EXP_GLOBAL_SYMBOL_RENAME_SEGMENT = """crypto_kem_keypair OQS_KEM_Fake_Alg_1_keypair
crypto_kem_enc OQS_KEM_Fake_Alg_1_encaps
crypto_kem_dec OQS_KEM_Fake_Alg_1_decaps"""


def test_global_symbol_renaming_content():
    res = generate.global_symbol_renaming_content('Fake Alg 1')
    assert res == EXP_GLOBAL_SYMBOL_RENAME_SEGMENT


def test_local_symbol_renaming_content():
    symbols = {'func_C', 'func_B', 'func_A'}
    res = generate.local_symbol_renaming_content(symbols)
    assert res == 'func_A\nfunc_B\nfunc_C\n'


# TODO: name???
KEM_MAKEFILE_ORIG = """example_kem: headers src/kem/example_kem.c liboqs
$(CC) src/kem/example_kem.c liboqs.a -o example_kem $(CFLAGS) $(LDFLAGS)

include src/kem/frodokem/Makefile
# EDIT-WHEN-ADDING-KEM
"""

KEM_MAKEFILE_WITH_HEADER = """example_kem: headers src/kem/example_kem.c liboqs
$(CC) src/kem/example_kem.c liboqs.a -o example_kem $(CFLAGS) $(LDFLAGS)

include src/kem/frodokem/Makefile
include src/kem/fake/Makefile
# EDIT-WHEN-ADDING-KEM
"""


def test_kem_makefile_add_header():
    # TODO: convert to working with list of strings?
    res = generate.kem_makefile_add_header(KEM_MAKEFILE_ORIG, basename='fake')
    assert res == KEM_MAKEFILE_WITH_HEADER


def test_kem_makefile_add_header_already_done():
    res = generate.kem_makefile_add_header(KEM_MAKEFILE_WITH_HEADER, 'fake')
    assert res == KEM_MAKEFILE_WITH_HEADER
