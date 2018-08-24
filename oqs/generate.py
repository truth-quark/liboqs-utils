import os
import string
import subprocess

from oqs import template

CRYPTO_SECRETKEYBYTES = 'CRYPTO_SECRETKEYBYTES'
CRYPTO_PUBLICKEYBYTES = 'CRYPTO_PUBLICKEYBYTES'
CRYPTO_BYTES = 'CRYPTO_BYTES'
CRYPTO_CIPHERTEXTBYTES = 'CRYPTO_CIPHERTEXTBYTES'
CRYPTO_ALGNAME = 'CRYPTO_ALGNAME'

KEYWORDS = [CRYPTO_SECRETKEYBYTES, CRYPTO_PUBLICKEYBYTES,
            CRYPTO_BYTES, CRYPTO_CIPHERTEXTBYTES, CRYPTO_ALGNAME]

EDIT = '// EDIT-WHEN-ADDING-KEM\n'

# TODO: create global symbol renaming files
#
# TODO: create local symbol renaming file
# TODO: data structure for scanning upstream
# TODO: modify src/kem/Makefile
# TODO: modify Makefile / enable new algorithms
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

                if kw == CRYPTO_ALGNAME:
                    assert value[0] == value[-1] == '"'
                    value = value[1:-1]

                result[kw] = value
                break

    return result


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
        raise KemException(msg)

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
    cmd = ['nm', obj_path]
    res = subprocess.run(cmd, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, check=True)

    content = res.stdout.decode()
    return filter_symbols(content)


def filter_symbols(nm_output):
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
            tmp = template.OQS_ALGORITHM_H_TEMPLATE.format(safe)

            if tmp not in content:
                tmp_edit = tmp + '\n' + EDIT
                content = content.replace(EDIT, tmp_edit, 1)
    else:
        raise KemException('Too many/few "// EDIT-WHEN-ADDING-KEM" strings')

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

    if has_whitespace(params[CRYPTO_ALGNAME]):
        sanitised = sanitise_name(params[CRYPTO_ALGNAME])
        params[CRYPTO_ALGNAME] = sanitised

    return template.API_SRC_SEGMENT_TEMPLATE.format_map(params)


def kem_src_file(basename, params):
    """Return KEM src file content for given algorithms."""
    mapping = dict(basename=basename.lower(),
                   segments='\n'.join(kem_src_segment(p) for p in params))

    return template.API_SRC_TEMPLATE.format_map(mapping)


def kem_src_add_new_algorithm(content, params):
    """Updates src/kem/kem.c in place for adding new algorithms."""
    lines = content.split('\n')
    safe_names = [sanitise_name(p[CRYPTO_ALGNAME]) for p in params]
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


def global_symbol_renaming_content(basename):
    """Generate content for symbols_global_rename_NAME.txt file."""
    # TODO: refactor to sanitised name
    safe = sanitise_name(basename)
    return template.GLOBAL_SYMBOL_RENAMING_SEGMENT.format(safe)


def local_symbol_renaming_content(symbols):
    """Generate content for symbols_local.txt file."""
    return '{}\n'.format('\n'.join(sorted(symbols)))


def oqs_wrapper(basename):
    """Generate liboqs wrapper files."""
    # TODO: assume upstream dir is created
    # TODO: need a class with path attrs

    kem_dirs = find_kem_dirs(basename)
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
    kem_c_path = 'src/kem/kem.c'
    content = open(kem_c_path).read()

    new_content = kem_src_add_new_algorithm(content, params.values())

    if new_content:
        with open(kem_c_path, 'w') as f:
            f.write(new_content)


class KemException(Exception):
    pass


if __name__ == '__main__':
    import sys
    oqs_wrapper(sys.argv[1])
