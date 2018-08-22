import os
import string
import textwrap

from oqs import template

CRYPTO_SECRETKEYBYTES = 'CRYPTO_SECRETKEYBYTES'
CRYPTO_PUBLICKEYBYTES = 'CRYPTO_PUBLICKEYBYTES'
CRYPTO_BYTES = 'CRYPTO_BYTES'
CRYPTO_CIPHERTEXTBYTES = 'CRYPTO_CIPHERTEXTBYTES'
CRYPTO_ALGNAME = 'CRYPTO_ALGNAME'

KEYWORDS = [CRYPTO_SECRETKEYBYTES, CRYPTO_PUBLICKEYBYTES,
            CRYPTO_BYTES, CRYPTO_CIPHERTEXTBYTES, CRYPTO_ALGNAME]

EDIT = '// EDIT-WHEN-ADDING-KEM\n'


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

                if kw == CRYPTO_ALGNAME:
                    assert value[0] == value[-1] == '"'
                    value = value[1:-1]

                result[kw] = value
                break

    return result


def scan_upstream(basename):
    # TODO: assume script run from project root
    upstream_dir = 'src/kem/{}/upstream'
    kem_dirs = []

    # TODO; find api.h files to enable generation of wrapper code
    for dirpath, _, filenames in os.walk(upstream_dir.format(basename)):
        if 'api.h' in filenames:
            kem_dirs.append(dirpath)

    if not kem_dirs:
        msg = 'api.h not found in subdirs of {}'.format(upstream_dir)
        raise KemException(msg)

    return kem_dirs


def has_whitespace(s):
    """Returns True if string contains whitespace."""
    for c in string.whitespace:
        if c in s:
            return True
    return False


def sanitise_name(s):
    return s.replace(' ', '_')


def kem_header_segment(params):
    """Returns algorithm C header segment for a specific algorithm."""
    # FIXME: changes params
    if has_whitespace(params[CRYPTO_ALGNAME]):
        sanitised = sanitise_name(params[CRYPTO_ALGNAME])
        params[CRYPTO_ALGNAME] = sanitised

    return template.API_HEADER_SEGMENT_TEMPLATE.format_map(params)


def kem_header_file(basename, params):
    """Return KEM header file content for given algorithms."""
    mapping = dict(basename=basename,
                   BASENAME=sanitise_name(str.upper(basename)))

    mapping['segments'] = '\n'.join(kem_header_segment(p) for p in params)
    return template.API_HEADER_TEMPLATE.format_map(mapping)


def kem_header_add_new_algorithm(basename, content, params):
    # edit kem.h for content

    # add algorithm ID strings
    if content.count(EDIT) == 2:
        for p in params:
            safe = sanitise_name(p[CRYPTO_ALGNAME])
            tmp = template.OQS_ALGORITHM_TEMPLATE.format(safe)

            if tmp not in content:
                tmp_edit = tmp + '\n' + EDIT
                content = content.replace(EDIT, tmp_edit, 1)
    else:
        raise KemException('Too many/few "// EDIT-WHEN-ADDING-KEM" strings')

    # update count of algorithms
    lines = content.split('\n')
    count = len([e for e in lines if e.startswith('#define OQS_KEM_alg_')])
    blah = [e for e in lines if e.startswith('#define OQS_KEM_algs_length')]
    assert len(blah) == 1
    i = lines.index(blah[0])
    lines[i] = '#define OQS_KEM_algs_length {}'.format(count)

    # include new header files at bottom
    inc = '#include <oqs/kem_{}.h>'.format(basename)
    if inc not in lines:
        j = lines.index(EDIT.strip(), i)
        lines.insert(j, inc)

    content = '\n'.join(lines)
    return content


def kem_src_segment(params):
    """Returns C source segment for an algorithm """
    # FIXME: changes params
    params['nist-level'] = 'TODO'
    params['ind-cca'] = 'TODO'

    if has_whitespace(params[CRYPTO_ALGNAME]):
        sanitised = sanitise_name(params[CRYPTO_ALGNAME])
        params[CRYPTO_ALGNAME] = sanitised

    return template.API_SRC_SEGMENT_TEMPLATE.format_map(params)


def kem_src_file(basename, params):
    """Return KEM src file content for given algorithms."""
    mapping = dict(basename=basename.lower(),
                   segments='\n'.join(kem_src_segment(p) for p in params))

    return template.API_SRC_TEMPLATE.format_map(mapping)


def oqs_wrapper(basename):
    """Generate liboqs wrapper files."""
    # TODO: assume upstream dir is created
    # TODO: need a class with path attrs

    kem_dirs = scan_upstream(basename)
    params = {}

    for kd in kem_dirs:
        print(kd)
        path = os.path.join(kd, 'api.h')
        content = open(path).read()
        param = parse_api_header(content)
        params[path] = param

    header_path = 'src/kem/{}/kem_{}.h'.format(basename, basename)

    with open(header_path, 'w') as f:
        header = kem_header_file(basename, params.values())
        f.write(header)

    src_path = 'src/kem/{}/kem_{}.c'.format(basename, basename)
    with open(src_path, 'w') as f:
        src = kem_src_file(basename, params.values())
        f.write(src)

    # TODO: edit kem.h for content
    kem_h_path = 'src/kem/kem.h'
    content = open(kem_h_path).read()
    new_content = kem_header_add_new_algorithm(basename, content, params.values())

    if new_content:
        with open(kem_h_path, 'w') as f:
            f.write(new_content)

    # TODO: edit kem.c for content


class KemException(Exception):
    pass


if __name__ == '__main__':
    import sys
    oqs_wrapper(sys.argv[1])
