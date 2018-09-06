import os
import sys

import oqs
from oqs import template, scanner, SAFE_NAME, ALG_VARS

EDIT = '// EDIT-WHEN-ADDING-KEM\n'
EDIT_MAKE = '# EDIT-WHEN-ADDING-KEM\n'

OQS_DEF_ALG = '#define OQS_KEM_alg_'
OQS_DEF_ALG_LEN = '#define OQS_KEM_algs_length'


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
            tmp = template.OQS_SRC_KEM_KEM_H_ALG_TEMPLATE.format(p[SAFE_NAME])

            if tmp not in content:
                tmp_edit = tmp + '\n' + EDIT
                content = content.replace(EDIT, tmp_edit, 1)
    else:
        raise oqs.KemException('Too many/few "// EDIT-WHEN-ADDING-KEM" strings')

    # update count of algorithms
    lines = content.split('\n')
    count = len([e for e in lines if e.startswith(OQS_DEF_ALG)])
    alg_len = [e for e in lines if e.startswith(OQS_DEF_ALG_LEN)]
    assert len(alg_len) == 1
    i = lines.index(alg_len[0])
    lines[i] = OQS_DEF_ALG_LEN + ' {}'.format(count)

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
        blk = template.OQS_SRC_KEM_KEM_C_ALG_TEMPLATE.format(s)

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


def srcs_block(kem_params):
    """Generate list of files for SRCS_KEM_<ALG>= makefile variable."""
    sname = kem_params['SANITISED_NAME']
    indent = len(sname) + 10
    src_files = kem_params['src_files']
    lines = ['$({}_DIR)/{} \\\n'.format(sname, s) for s in src_files[:-1]]
    lines.append('$({}_DIR)/{}\n'.format(sname, src_files[-1]))

    indented = [line.replace('$', indent * ' ' + '$') for line in lines[1:]]
    indented.insert(0, lines[0])
    return ''.join(indented)


def algorithm_makefile_segment(basename, kem_dir, kem_params):
    srcs_seg = srcs_block(kem_params)

    tmp = {'basename': basename, 'kem_dir': kem_dir,
           'srcs_block': srcs_seg,
           }

    tmp.update(kem_params)
    return template.ALG_MAKEFILE_SEGMENT.format_map(tmp)


def enable_kems(alg_names):
    tmpl = 'ENABLE_KEMS+=$(findstring {}_kem, $(KEMS_TO_ENABLE))'
    lines = [tmpl.format(n) for n in alg_names]
    return '\n'.join(lines)


def algorithm_makefile_header_segment(params):
    tmp = {}
    tmp.update(params)

    alg_names = [params[ALG_VARS][p][SAFE_NAME] for p in params[ALG_VARS]]
    tmp['enable_kems_x64'] = enable_kems(alg_names)
    tmp['enable_kems_x86'] = enable_kems(alg_names)

    return template.EXP_ALG_MAKEFILE_SEGMENT_HEADER.format_map(tmp)


def generate_algorithm_makefile(params):
    segs = [algorithm_makefile_header_segment(params)]
    for kd in params[ALG_VARS]:
        s = algorithm_makefile_segment(params['basename'], kd, params[ALG_VARS][kd])
        segs.append(s)

    return '\n'.join(segs)


# TODO: cleanup hard coded paths
def generate_oqs_wrapper(basename, data):
    """Generate liboqs wrapper files."""
    # NB: assumes upstream dir already exists

    # generate KEM wrapper header file
    header_path = 'src/kem/{0}/kem_{0}.h'.format(basename)

    with open(header_path, 'w') as f:
        hdr = kem_header_file(data['BASENAME'], data[ALG_VARS].values())
        f.write(hdr)

    # generate KEM wrapper source file
    src_path = 'src/kem/{0}/kem_{0}.c'.format(basename)
    with open(src_path, 'w') as f:
        src = kem_src_file(data[SAFE_NAME], data[ALG_VARS].values())
        f.write(src)

    # update kem.h for wrapper content
    kem_h_path = 'src/kem/kem.h'
    content = open(kem_h_path).read()
    new_content = kem_header_add_new_algorithm(basename, content,
                                               data[ALG_VARS].values())
    if new_content:
        with open(kem_h_path, 'w') as f:
            f.write(new_content)

    # update kem.c for for wrapper content
    kem_c_path = 'src/kem/kem.c'
    cont = open(kem_c_path).read()
    new_content = kem_src_add_new_algorithm(cont, data[ALG_VARS].values())

    if new_content:
        with open(kem_c_path, 'w') as f:
            f.write(new_content)

    # symbol renaming
    for alg in data[ALG_VARS].values():
        global_rename = global_symbol_renaming_content(alg[SAFE_NAME])
        path_t = 'src/kem/{}/symbols_global_rename_{}.txt'
        path = path_t.format(basename, alg[SAFE_NAME])

        with open(path, 'w') as f:
            f.write(global_rename)

    # local symbol rename
    local_rename = local_symbol_renaming_content(data['symbols'])
    path = 'src/kem/{}/symbols_local.txt'.format(basename)

    with open(path, 'w') as f:
        f.write(local_rename)

    # create algorithm makefile
    path = 'src/kem/{}/Makefile'.format(basename)

    with open(path, 'w') as f:
        f.write(generate_algorithm_makefile(data))

    # include new algorithm Makefile in src/kem/Makefile
    kem_makefile_path = 'src/kem/Makefile'
    content = open(kem_makefile_path).read()

    new_content = kem_makefile_add_header(content, basename)
    with open(kem_makefile_path, 'w') as f:
        f.write(new_content)

    # TODO: update Makefile
    # update root makefile


if __name__ == '__main__':
    assert os.path.exists('.git')  # quick and dirty check for root dir

    base_name = sys.argv[1]
    scandata = scanner.scan(base_name)

    from pprint import pprint
    pprint(scandata)

    generate_oqs_wrapper(base_name, scandata)
