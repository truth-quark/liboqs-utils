from unittest import mock

import pytest

import oqs
from oqs import scanner


BASENAME = 'fake'

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
    res = scanner.parse_api_header(FAKE_API_HEADER)
    assert len(res) == 5
    assert res['CRYPTO_SECRETKEYBYTES'] == '1'
    assert res['CRYPTO_PUBLICKEYBYTES'] == '2'
    assert res['CRYPTO_BYTES'] == '3'
    assert res['CRYPTO_CIPHERTEXTBYTES'] == '4'
    assert res['CRYPTO_ALGNAME'] == 'NAME'


@mock.patch('os.walk')
class TestFinders:

    def test_find_kem_dirs(self, walk):
        walk.return_value = [['dirA', [], ['a', 'api.h']],
                             ['dirB', [], ['file.txt']]]

        kdirs = scanner.find_kem_dirs(BASENAME)
        assert kdirs == ['dirA']

    def test_find_kem_dirs_not_found(self, walk):
        walk.return_value = [['dirA', [], ['a', 'file.c']],
                             ['dirB', [], ['file.txt']]]

        with pytest.raises(oqs.KemException):
            scanner.find_kem_dirs(BASENAME)

    def test_find_object_files(self, walk):
        walk.return_value = [['dirA', [], ['a', 'file.o']],
                             ['dirB', [], ['file.txt']],
                             ['dirC', [], ['test.o']],
                             ['dirD', [], ['rng.o']]]

        files = list(scanner.find_object_files('fake-dir-path', skip_rng=True))
        assert files == ['dirA/file.o', 'dirC/test.o']

    def test_find_object_files_not_found(self, walk):
        walk.return_value = [['dirA', [], ['a', 'file.c']],
                             ['dirB', [], ['file.txt']]]

        assert [] == list(scanner.find_object_files('fake-dir-path-again'))

    def test_find_object_files_with_rng(self, walk):
        walk.return_value = [['dirA', [], ['a', 'file.o']],
                             ['dirB', [], ['rng.o']]]

        files = list(scanner.find_object_files('fake-dir-path-2', skip_rng=False))
        assert files == ['dirA/file.o', 'dirB/rng.o']


def test_filter_symbols():
    content = '0000000000000000 T _BINT_to_OS\n' \
              '                 U calloc\n' \
              '0000000000000000 D CDT_TABLE\n'

    exp = ['_BINT_to_OS', 'CDT_TABLE']
    assert exp == list(scanner.filter_symbols(content))
