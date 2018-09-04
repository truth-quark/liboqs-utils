import os
import string

import oqs
from oqs import template


KEYWORDS = [oqs.CRYPTO_SECRETKEYBYTES, oqs.CRYPTO_PUBLICKEYBYTES,
            oqs.CRYPTO_BYTES, oqs.CRYPTO_CIPHERTEXTBYTES, oqs.CRYPTO_ALGNAME]

EDIT = '// EDIT-WHEN-ADDING-KEM\n'
EDIT_MAKE = '# EDIT-WHEN-ADDING-KEM\n'

# TODO: create global symbol renaming files
# TODO: create local symbol renaming file
# TODO: data structure for scanning upstream
# TODO: modify src/kem/Makefile

# TODO: generate algorithm makefile? where to get names for ENABLE_<> from???
# TODO: modify project Makefile / enable new algorithms
# TODO: KAT extraction
# TODO: Stub out algorithm data sheet


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


def kem_header_segment(params):
    """Returns algorithm C header segment for a specific algorithm."""
    # FIXME: changes params
    if has_whitespace(params[oqs.CRYPTO_ALGNAME]):
        sanitised = sanitise_name(params[oqs.CRYPTO_ALGNAME])
        params[oqs.CRYPTO_ALGNAME] = sanitised

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
            safe = sanitise_name(p[oqs.CRYPTO_ALGNAME])
            tmp = template.OQS_ALGORITHM_H_TEMPLATE.format(safe)

            if tmp not in content:
                tmp_edit = tmp + '\n' + EDIT
                content = content.replace(EDIT, tmp_edit, 1)
    else:
        raise oqs.KemException('Too many/few "// EDIT-WHEN-ADDING-KEM" strings')

    # update count of algorithms
    lines = content.split('\n')
    count = len([e for e in lines if e.startswith('#define OQS_KEM_alg_')])
    alg_len = [e for e in lines if e.startswith('#define OQS_KEM_algs_length')]
    assert len(alg_len) == 1
    i = lines.index(alg_len[0])
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

    if has_whitespace(params[oqs.CRYPTO_ALGNAME]):
        sanitised = sanitise_name(params[oqs.CRYPTO_ALGNAME])
        params[oqs.CRYPTO_ALGNAME] = sanitised

    return template.API_SRC_SEGMENT_TEMPLATE.format_map(params)


def kem_src_file(basename, params):
    """Return KEM src file content for given algorithms."""
    mapping = dict(basename=basename.lower(),
                   segments='\n'.join(kem_src_segment(p) for p in params))

    return template.API_SRC_TEMPLATE.format_map(mapping)


def kem_src_add_new_algorithm(content, params):
    """Updates src/kem/kem.c in place for adding new algorithms."""
    lines = content.split('\n')
    safe_names = [sanitise_name(p[oqs.CRYPTO_ALGNAME]) for p in params]
    tmp = [e for e in lines if 'OQS_KEM_alg_default' in e]
    assert len(tmp) == 2
    ids = tmp[0]

    # add algorithm names to identifier list
    i = lines.index(ids)
    algs = ', '.join(['OQS_KEM_alg_' + s for s in safe_names])

    if algs not in content:  # check content to make str find cleaner
        lines[i] += '\n\t    {},'.format(algs)

    # add new algorithms to bottom of if block
    tmp = [e for e in lines if EDIT.strip() in e]
    assert len(tmp) == 2
    if_block = tmp[1]
    j = lines.index(if_block)

    for s in safe_names:
        blk = template.OQS_ALGORITHM_C_TEMPLATE.format(s)

        if blk not in content:  # check content to make str find cleaner
            lines.insert(j, blk)
            j += 1  # maintain order of newly inserted blocks

    updated = '\n'.join(lines)
    return updated


def global_symbol_renaming_content(alg_name):
    """Generate content for symbols_global_rename_NAME.txt file."""
    # TODO: refactor to sanitised name
    safe = sanitise_name(alg_name)
    return template.GLOBAL_SYMBOL_RENAMING_SEGMENT.format(safe)


def local_symbol_renaming_content(symbols):
    """Generate content for symbols_local.txt file."""
    return '{}\n'.format('\n'.join(sorted(symbols)))


def kem_makefile_add_header(content, basename):
    """Include new algorithm header file in src/kem/Makefile"""
    new = 'include src/kem/{}/Makefile\n'.format(basename)

    if new not in content:
        content = content.replace(EDIT_MAKE, new + EDIT_MAKE)

    return content


def oqs_wrapper(basename, kem_dirs):
    """Generate liboqs wrapper files."""
    # NB: assumes upstream dir already exists
    # TODO: need a class with path attrs

    params = {}

    for kd in kem_dirs:
        print(kd)
        path = os.path.join(kd, 'api.h')
        content = open(path).read()
        param = parse_api_header(content)
        params[path] = param

    # generate KEM wrapper header file
    header_path = 'src/kem/{}/kem_{}.h'.format(basename, basename)

    with open(header_path, 'w') as f:
        header = kem_header_file(basename, params.values())
        f.write(header)

    # generate KEM wrapper source file
    src_path = 'src/kem/{}/kem_{}.c'.format(basename, basename)
    with open(src_path, 'w') as f:
        src = kem_src_file(basename, params.values())
        f.write(src)

    # update kem.h for wrapper content
    kem_h_path = 'src/kem/kem.h'
    content = open(kem_h_path).read()
    new_content = kem_header_add_new_algorithm(basename, content, params.values())

    if new_content:
        with open(kem_h_path, 'w') as f:
            f.write(new_content)

    # update kem.c for for wrapper content
    kem_c_path = 'src/kem/kem.c'
    content = open(kem_c_path).read()

    new_content = kem_src_add_new_algorithm(content, params.values())

    if new_content:
        with open(kem_c_path, 'w') as f:
            f.write(new_content)


if __name__ == '__main__':
    import sys
    from oqs import scanner
    base_name = sys.argv[1]
    kdirs = scanner.find_kem_dirs(base_name)
    oqs_wrapper(base_name, kdirs)
