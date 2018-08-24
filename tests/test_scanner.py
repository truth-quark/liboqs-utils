from unittest import mock

import pytest

from oqs import scanner, KemException


BASENAME = 'fake'


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

        with pytest.raises(KemException):
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
