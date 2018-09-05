import sys

import oqs
from oqs import template, scanner


EDIT = '// EDIT-WHEN-ADDING-KEM\n'
EDIT_MAKE = '# EDIT-WHEN-ADDING-KEM\n'

# TODO: modify src/kem/Makefile
# TODO: generate algorithm makefile? where to get names for ENABLE_<> from???
# TODO: modify project Makefile / enable new algorithms

# TODO: remove rng.c
# TODO: try to remove rng.h?
# TODO: KAT extraction
# TODO: Stub out algorithm data sheet


def kem_header_segment(params):
    """Returns algorithm C header segment for a specific algorithm."""
    return template.API_HEADER_SEGMENT_TEMPLATE.format_map(params)


def kem_header_file(basename_upper, params):
    """Return KEM header file content for given algorithms."""
    mapping = {'BASENAME': basename_upper,
               'segments': '\n'.join(kem_header_segment(p) for p in params),
               }

    return template.API_HEADER_TEMPLATE.format_map(mapping)


def kem_header_add_new_algorithm(basename, content, params):
    # edit kem.h for content

    # add algorithm ID strings
    if content.count(EDIT) == 2:
        for p in params:
            tmp = template.OQS_ALGORITHM_H_TEMPLATE.format(p['sanitised_name'])

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
    return template.API_SRC_SEGMENT_TEMPLATE.format_map(params)


def kem_src_file(basename, params):
    """
    Return KEM src file content for given algorithms.
    :param basename:
    :param params: list of data dicts for each algorithm variant
    :return:
    """
    mapping = dict(basename=basename,
                   segments='\n'.join(kem_src_segment(p) for p in params))

    return template.API_SRC_TEMPLATE.format_map(mapping)


def kem_src_add_new_algorithm(content, params):
    """Updates src/kem/kem.c in place for adding new algorithms."""
    lines = content.split('\n')
    safe_names = [p['sanitised_name'] for p in params]
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


def global_symbol_renaming_content(safe_alg_name):
    """Generate content for symbols_global_rename_NAME.txt file."""
    return template.GLOBAL_SYMBOL_RENAMING_SEGMENT.format(safe_alg_name)


def local_symbol_renaming_content(symbols):
    """Generate content for symbols_local.txt file."""
    return '{}\n'.format('\n'.join(sorted(symbols)))


def kem_makefile_add_header(content, basename):
    """Include new algorithm header file in src/kem/Makefile"""
    new = 'include src/kem/{}/Makefile\n'.format(basename)

    if new not in content:
        content = content.replace(EDIT_MAKE, new + EDIT_MAKE)

    return content


def generate_oqs_wrapper(basename, data):
    """Generate liboqs wrapper files."""
    # NB: assumes upstream dir already exists

    # generate KEM wrapper header file
    header_path = 'src/kem/{0}/kem_{0}.h'.format(basename)

    with open(header_path, 'w') as f:
        hdr = kem_header_file(data['BASENAME'], data['alg_variants'].values())
        f.write(hdr)

    # generate KEM wrapper source file
    src_path = 'src/kem/{0}/kem_{0}.c'.format(basename)
    with open(src_path, 'w') as f:
        src = kem_src_file(data['BASENAME'], data['alg_variants'].values())
        f.write(src)

    # update kem.h for wrapper content
    kem_h_path = 'src/kem/kem.h'
    content = open(kem_h_path).read()
    new_content = kem_header_add_new_algorithm(basename, content,
                                               data['alg_variants'].values())

    if new_content:
        with open(kem_h_path, 'w') as f:
            f.write(new_content)

    # update kem.c for for wrapper content
    kem_c_path = 'src/kem/kem.c'
    cont = open(kem_c_path).read()
    new_content = kem_src_add_new_algorithm(cont, data['alg_variants'].values())

    if new_content:
        with open(kem_c_path, 'w') as f:
            f.write(new_content)

    # symbol renaming
    for alg in data['alg_variants'].values():
        global_rename = global_symbol_renaming_content(alg['sanitised_name'])
        path_t = 'src/kem/{}/symbols_global_rename_{}.txt'
        path = path_t.format(basename, alg['sanitised_name'])

        with open(path, 'w') as f:
            f.write(global_rename)

    # local symbol rename
    local_rename = local_symbol_renaming_content(data['symbols'])
    path = 'src/kem/{}/symbols_local.txt'.format(basename)

    with open(path, 'w') as f:
        f.write(local_rename)

    # TODO: create Makefile / modify existing project ones


if __name__ == '__main__':
    base_name = sys.argv[1]
    scandata = scanner.scan(base_name)

    from pprint import pprint
    pprint(scandata)

    generate_oqs_wrapper(base_name, scandata)
