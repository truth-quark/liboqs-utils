import os
import string
import subprocess

import oqs


KEYWORDS = [oqs.CRYPTO_SECRETKEYBYTES, oqs.CRYPTO_PUBLICKEYBYTES,
            oqs.CRYPTO_BYTES, oqs.CRYPTO_CIPHERTEXTBYTES, oqs.CRYPTO_ALGNAME]


# TODO: handle varying whitespace between defines and value
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

                if kw == oqs.CRYPTO_ALGNAME:
                    assert value[0] == value[-1] == '"'
                    value = value[1:-1]

                result[kw] = value
                break

    return result


def has_whitespace(s):
    """Returns True if string contains whitespace."""
    for c in string.whitespace:
        if c in s:
            return True
    return False


def sanitise_name(s):
    return s.replace(' ', '_')


def find_kem_dirs(basename):
    """Search KEM upstream dir, returning list of dirs containing api.h file."""
    # TODO: assume script run from project root
    upstream_dir = 'src/kem/{}/upstream'
    kem_dirs = []

    # TODO; find api.h files to enable generation of wrapper code
    for dirpath, _, filenames in os.walk(upstream_dir.format(basename)):
        if 'api.h' in filenames:
            kem_dirs.append(dirpath)

    if not kem_dirs:
        msg = 'api.h not found in subdirs of {}'.format(upstream_dir)
        raise oqs.KemException(msg)

    return kem_dirs


def find_object_files(kem_dir, skip_rng=True):
    """
    Recursively finds '.o' obj files in given dir.
    :param kem_dir: dir path to search recursively
    :param skip_rng: True
    :return: yields paths to object files
    """
    for dirpath, _, filenames in os.walk(kem_dir):
        for fn in filenames:
            if fn.endswith('.o'):
                if skip_rng and fn.endswith('rng.o'):
                    continue

                yield os.path.join(dirpath, fn)


def get_symbols(obj_path):
    """
    Extract symbols from object file using 'nm'
    :param obj_path: object file to extract symbols from
    :return: string decoded output
    """
    cmd = ['nm', obj_path]
    res = subprocess.run(cmd, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, check=True)

    return res.stdout.decode()


def filter_symbols(nm_output):
    """
    Extracts Data and Code section symbols from the output of 'nm'
    :param nm_output:
    :return: yields raw symbol names
    """
    lines = nm_output.split('\n')
    subset = [e for e in lines if (' T ' in e or ' D ' in e)]  # TODO: regex?

    for s in subset:
        _, _, symbol = s.split()
        yield symbol


def get_all_symbols(kem_dirs):
    """
    Returns unique list of symbols from object files within KEM dirs.
    :param kem_dirs: sequence of dir paths
    """
    symbols = set()

    for kd in kem_dirs:
        for obj_path in find_object_files(kd):
            for symbol in get_symbols(obj_path):
                symbols.add(symbol)

    return symbols


def scan(basename):
    data = {'basename': basename,
            'sanitised_name': sanitise_name(basename),
            }

    data['BASENAME'] = data['sanitised_name'].upper()

    # find all upstream algorithms dirs of interest
    kem_dirs = find_kem_dirs(basename)
    data['alg_variants'] = {kd: None for kd in kem_dirs}

    # scan for algorithm variant data in each of the KEM dirs
    for kd in kem_dirs:
        api_h = os.path.join(kd, 'api.h')

        # TODO: potentially refactor with named tuples
        with open(api_h) as f:
            alg = data['alg_variants']
            alg[kd] = parse_api_header(f.read())
            alg_name = alg[kd][oqs.CRYPTO_ALGNAME]
            safe = sanitise_name(alg_name)
            alg[kd]['sanitised_name'] = safe
            alg[kd]['nist-level'] = 'TODO'
            alg[kd]['ind-cca'] = 'TODO'

    return data
