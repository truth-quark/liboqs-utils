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


def find_object_files(kem_dir):
    """
    Recursively finds '.o' obj files in given dir.
    :param kem_dir: dir path to search recursively
    :return: yields paths to object files
    """
    for dirpath, _, filenames in os.walk(kem_dir):
        for fn in filenames:
            if fn.endswith('.o'):
                yield os.path.join(dirpath, fn)


def filter_object_files(objs, ignored=('rng.o', 'PQCgenKAT_kem.o')):
    for o in objs:
        if os.path.basename(o) not in ignored:
            yield o


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
        for obj_path in filter_object_files(find_object_files(kd)):
            for symbol in filter_symbols(get_symbols(obj_path)):
                symbols.add(symbol)

    if symbols:
        return symbols

    raise oqs.KemException('No symbols found')


# TODO: generalise with find_object_files
def find_src_files(kem_dir):
    for dirpath, _, filenames in os.walk(kem_dir):
        for fn in filenames:
            if fn.endswith('.c'):
                if dirpath != kem_dir:
                    msg = 'Relative sub dirs not handled yet'
                    raise NotImplementedError(msg)

                yield fn


def filter_src_files(srcs, ignored=('rng.c', 'PQCgenKAT_kem.c')):
    for c in srcs:
        if os.path.basename(c) not in ignored:
            yield c


def scan(basename):
    safe = sanitise_name(basename)
    data = {'basename': basename,
            'sanitised_name': safe,
            'BASENAME': safe.upper(),
            }

    # find all upstream algorithms dirs of interest
    kem_dirs = find_kem_dirs(basename)
    data[oqs.ALG_VARS] = {kd: None for kd in kem_dirs}

    # scan for algorithm variant data in each of the KEM dirs
    for kd in kem_dirs:
        api_h = os.path.join(kd, 'api.h')

        # TODO: potentially refactor with named tuples
        with open(api_h) as f:
            alg = data[oqs.ALG_VARS]
            alg[kd] = parse_api_header(f.read())
            alg_name = alg[kd][oqs.CRYPTO_ALGNAME]
            safe = sanitise_name(alg_name)
            alg[kd][oqs.SAFE_NAME] = safe
            alg[kd]['SANITISED_NAME'] = safe.upper()
            alg[kd]['nist-level'] = '-1'
            alg[kd]['ind-cca'] = 'TODO'
            alg[kd]['src_files'] = list(filter_src_files(find_src_files(kd)))

    # object file scan
    tmp = list(data[oqs.ALG_VARS].keys())
    data['symbols'] = get_all_symbols(tmp)
    return data
