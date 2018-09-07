import oqs
from oqs import generate, ALG_VARS

FAKE1 = 'Fake Alg 1'
FAKE2 = 'Fake Alg 2'
FAKE1_SAFE = 'Fake_Alg_1'
FAKE2_SAFE = 'Fake_Alg_2'


EXP_KEM_HEADER_SEGMENT = """
#ifdef OQS_ENABLE_KEM_Fake_Alg_1

#define OQS_KEM_Fake_Alg_1_length_public_key 10
#define OQS_KEM_Fake_Alg_1_length_secret_key 15
#define OQS_KEM_Fake_Alg_1_length_ciphertext 20
#define OQS_KEM_Fake_Alg_1_length_shared_secret 25

OQS_KEM *OQS_KEM_Fake_Alg_1_new();

OQS_STATUS OQS_KEM_Fake_Alg_1_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_STATUS OQS_KEM_Fake_Alg_1_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
OQS_STATUS OQS_KEM_Fake_Alg_1_decaps(uint8_t *shared_secret, const unsigned char *ciphertext, const uint8_t *secret_key);

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

OQS_STATUS OQS_KEM_Fake_Alg_1_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_STATUS OQS_KEM_Fake_Alg_1_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
OQS_STATUS OQS_KEM_Fake_Alg_1_decaps(uint8_t *shared_secret, const unsigned char *ciphertext, const uint8_t *secret_key);

#endif

#ifdef OQS_ENABLE_KEM_Fake_Alg_2

#define OQS_KEM_Fake_Alg_2_length_public_key 50
#define OQS_KEM_Fake_Alg_2_length_secret_key 55
#define OQS_KEM_Fake_Alg_2_length_ciphertext 60
#define OQS_KEM_Fake_Alg_2_length_shared_secret 65

OQS_KEM *OQS_KEM_Fake_Alg_2_new();

OQS_STATUS OQS_KEM_Fake_Alg_2_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_STATUS OQS_KEM_Fake_Alg_2_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
OQS_STATUS OQS_KEM_Fake_Alg_2_decaps(uint8_t *shared_secret, const unsigned char *ciphertext, const uint8_t *secret_key);

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


def get_fake_api_params(pk=10, sk=15, ct=20, ss=25, name='FakeAlg1', **kwargs):
    params = {'CRYPTO_PUBLICKEYBYTES': pk,
              'CRYPTO_SECRETKEYBYTES': sk,
              'CRYPTO_CIPHERTEXTBYTES': ct,
              'CRYPTO_BYTES': ss,  # shared secret
              'CRYPTO_ALGNAME': name,
              'sanitised_name': name.replace(' ', '_'),
              'nist-level': 'TODO',
              'ind-cca': 'TODO',
              }

    if kwargs:
        params.update(kwargs)

    return params


def test_kem_header_segment():
    api_params = get_fake_api_params(name=FAKE1_SAFE)
    seg = generate.kem_header_segment(api_params)
    assert seg in EXP_KEM_HEADER_SEGMENT  # allow some whitespace leeway


def test_kem_header_file():
    params0 = get_fake_api_params(name=FAKE1)
    params1 = get_fake_api_params(pk=50, sk=55, ct=60, ss=65, name='Fake Alg 2')
    header = generate.kem_header_file('FAKE_ALG', [params0, params1])
    assert header in EXP_KEM_HEADER


def test_kem_src_segment():
    params0 = get_fake_api_params(name=FAKE1)
    src = generate.kem_src_segment(params0)
    assert src in EXP_KEM_SRC_SEGMENT


def test_kem_src_file():
    params0 = get_fake_api_params(name=FAKE1_SAFE)
    params1 = get_fake_api_params(name=FAKE2_SAFE)
    src = generate.kem_src_file('fake', [params0, params1])
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

    params0 = get_fake_api_params(name=FAKE1)
    params1 = get_fake_api_params(name=FAKE2)
    res = generate.kem_header_add_new_algorithm('fake', cont, [params0, params1])
    assert res == EXP_KEM_H


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
\t} else if (0 == strcasecmp(method_name, OQS_KEM_alg_Fake_Alg_1)) {
#ifdef OQS_ENABLE_KEM_Fake_Alg_1
\t\treturn OQS_KEM_Fake_Alg_1_new();
#else
\t\treturn NULL;
#endif
\t} else if (0 == strcasecmp(method_name, OQS_KEM_alg_Fake_Alg_2)) {
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
    res = generate.global_symbol_renaming_content('Fake_Alg_1')
    assert res == EXP_GLOBAL_SYMBOL_RENAME_SEGMENT


def test_local_symbol_renaming_content():
    symbols = {'func_C', 'func_B', 'func_A'}
    res = generate.local_symbol_renaming_content(symbols)
    assert res == 'func_A\nfunc_B\nfunc_C\n'


SRC_KEM_MAKEFILE = """example_kem: headers src/kem/example_kem.c liboqs
$(CC) src/kem/example_kem.c liboqs.a -o example_kem $(CFLAGS) $(LDFLAGS)

include src/kem/frodokem/Makefile
# EDIT-WHEN-ADDING-KEM
"""

SRC_KEM_MAKEFILE_WITH_HEADER = """example_kem: headers src/kem/example_kem.c liboqs
$(CC) src/kem/example_kem.c liboqs.a -o example_kem $(CFLAGS) $(LDFLAGS)

include src/kem/frodokem/Makefile
include src/kem/fake/Makefile
# EDIT-WHEN-ADDING-KEM
"""


def test_kem_makefile_add_header():
    # TODO: convert to working with list of strings?
    res = generate.kem_makefile_add_header(SRC_KEM_MAKEFILE, basename='fake')
    assert res == SRC_KEM_MAKEFILE_WITH_HEADER


def test_kem_makefile_add_header_already_done():
    res = generate.kem_makefile_add_header(SRC_KEM_MAKEFILE_WITH_HEADER, 'fake')
    assert res == SRC_KEM_MAKEFILE_WITH_HEADER


EXP_SRCS_BLOCK = """$(TITANIUM_CCA_STD_DIR)/file0.c \\
                          $(TITANIUM_CCA_STD_DIR)/file1.c
"""


def test_srcs_block():
    params = get_fake_api_params(src_files=['file0.c', 'file1.c'],
                                 SANITISED_NAME='TITANIUM_CCA_STD')
    res = generate.srcs_block(params)
    assert res == EXP_SRCS_BLOCK


EXP_ALG_MAKEFILE_SEGMENT = """ifneq (,$(findstring titanium_cca_std, $(ENABLE_KEMS)))
UPSTREAMS+=titanium_cca_std_upstream
endif

TITANIUM_CCA_STD_DIR=src/kem/titanium/upstream/Titanium_CCA_std

SRCS_KEM_TITANIUM_CCA_STD=$(TITANIUM_CCA_STD_DIR)/encrypt.c \\
                          $(TITANIUM_CCA_STD_DIR)/kem.c \\
                          $(TITANIUM_CCA_STD_DIR)/ntt.c

OBJS_KEM_TITANIUM_CCA_STD=$(SRCS_KEM_TITANIUM_CCA_STD:.c=.o)

TO_CLEAN+=$(OBJS_KEM_TITANIUM_CCA_STD)

src/kem/titanium/upstream/Titanium_CCA_std/%.o: src/kem/titanium/upstream/Titanium_CCA_std/%.c
\t$(CC) -O2 -fPIC -c -o $@ $<

MODULE_TITANIUM_CCA_STD=kem_titanium_cca_std

titanium_cca_std_upstream: $(OBJS_KEM_TITANIUM_CCA_STD)
\tbash scripts/collect_objects.sh $(MODULE_TITANIUM_CCA_STD) $(OBJS_KEM_TITANIUM_CCA_STD)
\tbash scripts/symbols_global_rename.sh $(MODULE_TITANIUM_CCA_STD) src/kem/titanium/symbols_global_rename_titanium_cca_std.txt
\tbash scripts/symbols_local.sh $(MODULE_TITANIUM_CCA_STD) src/kem/titanium/symbols_local.txt
"""


def test_algorithm_makefile_segment():
    name = 'titanium_cca_std'
    src_files = ['encrypt.c', 'kem.c', 'ntt.c']
    kem_dir = 'src/kem/titanium/upstream/Titanium_CCA_std'
    params = get_fake_api_params(name=name, SANITISED_NAME=name.upper(),
                                 src_files=src_files)

    res = generate.algorithm_makefile_segment('titanium', kem_dir, params)
    assert res == EXP_ALG_MAKEFILE_SEGMENT


EXP_ALG_MAKEFILE_SEGMENT_HEADER = """ifeq (x64,$(ARCH))
ENABLE_KEMS+=$(findstring titanium_cca_std, $(KEMS_TO_ENABLE))
ENABLE_KEMS+=$(findstring titanium_cca_hi, $(KEMS_TO_ENABLE))
MAKE_FLAGS_KEM_TITANIUM=
else ifeq (x86,$(ARCH))
ENABLE_KEMS+=$(findstring titanium_cca_std, $(KEMS_TO_ENABLE))
ENABLE_KEMS+=$(findstring titanium_cca_hi, $(KEMS_TO_ENABLE))
MAKE_FLAGS_KEM_TITANIUM=
endif

HEADERS_KEM_TITANIUM=src/kem/titanium/kem_titanium.h
HEADERS_KEM+=$(HEADERS_KEM_TITANIUM)

OBJECT_DIRS+=.objs/kem/titanium
OBJECTS_KEM_TITANIUM=.objs/kem/titanium/kem_titanium.o
OBJECTS_KEM+=$(OBJECTS_KEM_TITANIUM)

# build liboqs interface to upstream component
.objs/kem/titanium/kem_titanium.o: headers src/kem/titanium/kem_titanium.c
\t$(CC) -c src/kem/titanium/kem_titanium.c -o .objs/kem/titanium/kem_titanium.o $(CFLAGS)
"""


def test_algorithm_makefile_header_segment():
    params = {'basename': 'titanium',
              'BASENAME': 'TITANIUM',
              ALG_VARS: {'src/kem/titanium/upstream/Titanium_CCA_std':
                          {'SANITISED_NAME': 'TITANIUM_CCA_STD',
                           'sanitised_name': 'titanium_cca_std',
                           },
                         'src/kem/emblem/upstream/Titanium_CCA_hi':
                             {'SANITISED_NAME': 'TITANIUM_CCA_HI',
                              'sanitised_name': 'titanium_cca_hi',
                              },
                         }
              }

    res = generate.algorithm_makefile_header_segment(params)
    assert res == EXP_ALG_MAKEFILE_SEGMENT_HEADER


ORIG_MAKEFILE = """THESE SHOULD BE THE ONLY OPTIONS TO BE CONFIGURED BY THE PERSON COMPILING

KEMS_TO_ENABLE?=frodokem_640_aes frodokem_640_cshake frodokem_976_aes \\
\t\t\t   newhope_512_cca_kem newhope_1024_cca_kem \\
\t\t\t   kyber512 kyber768 kyber1024
\t\t\t   # EDIT-WHEN-ADDING-KEM
"""


EXP_MAKEFILE = """THESE SHOULD BE THE ONLY OPTIONS TO BE CONFIGURED BY THE PERSON COMPILING

KEMS_TO_ENABLE?=frodokem_640_aes frodokem_640_cshake frodokem_976_aes \\
\t\t\t   titanium_cca_std titanium_cca_hi \\
\t\t\t   newhope_512_cca_kem newhope_1024_cca_kem \\
\t\t\t   kyber512 kyber768 kyber1024
\t\t\t   # EDIT-WHEN-ADDING-KEM
"""


def test_enable_algorithms_root_makefile():
    params = {'basename': 'titanium',
              ALG_VARS: {'src/kem/titanium/upstream/Titanium_CCA_std':
                             {'sanitised_name': 'titanium_cca_std'},
                         'src/kem/emblem/upstream/Titanium_CCA_hi':
                             {'sanitised_name': 'titanium_cca_hi'},
                         }
              }
    res = generate.enable_algorithms_root_makefile(ORIG_MAKEFILE, params)
    assert res == EXP_MAKEFILE


EXP_BASE_DATA_SHEET = """liboqs nist-branch algorithm datasheet: `kem_emblem`
====================================================

Summary
-------

- **Name:** emblem
- **Algorithm type:**
- **Main cryptographic assumption:**
- **NIST submission URL:** https://csrc.nist.gov/CSRC/media/Projects/Post-Quantum-Cryptography/documents/round-1/submissions
- **Submitters (to NIST competition):**
- **Submitters' website:**
- **Added to liboqs by:**

Parameter sets
--------------

| Parameter set | Security model | Claimed NIST security level | Public key size (bytes) | Secret key size (bytes) | Ciphertext size (bytes) | Shared secret size (bytes) |
|:-------------:|:--------------:|:---------------------------:|:-----------------------:|:-----------------------:|:-----------------------:|:--------------------------:|
| EMBLEM        | TODO           |                           5 |                   26912 |                   26944 |                       8 |                         32 |
| R_EMBLEM      | TODO           |                           3 |                   20512 |                   20544 |                       6 |                         16 |

Implementation
--------------

- **Source of implementation:**
- **License:**
- **Language:** C
- **Constant-time:** Unknown
- **Architectures supported in liboqs nist-branch:**

Additional comments
-------------------
"""


def test_algorithm_data_sheet():
    params = {'basename': 'emblem',
              ALG_VARS: {'src/kem/emblem/upstream/EMBLEM':
                          {oqs.CRYPTO_ALGNAME: 'EMBLEM',
                           oqs.CRYPTO_PUBLICKEYBYTES: 26912,
                           oqs.CRYPTO_SECRETKEYBYTES: 26944,
                           oqs.CRYPTO_CIPHERTEXTBYTES: 8,
                           oqs.CRYPTO_BYTES: 32,
                           'sanitised_name': 'emblem',
                           'nist-level': 5,
                           },
                         'src/kem/emblem/upstream/R_EMBLEM':
                          {oqs.CRYPTO_ALGNAME: 'R_EMBLEM',
                           oqs.CRYPTO_PUBLICKEYBYTES: 20512,
                           oqs.CRYPTO_SECRETKEYBYTES: 20544,
                           oqs.CRYPTO_CIPHERTEXTBYTES: 6,
                           oqs.CRYPTO_BYTES: 16,
                           'sanitised_name': 'r_emblem',
                           'nist-level': 3,
                           },
                         }
              }

    res = generate.algorithm_data_sheet(params)
    assert res == EXP_BASE_DATA_SHEET
