import sys


def extract_kat(file_like):
    """Extract first KAT from path.
    :param file_like: open file_like object to extract KAT data from
    :returns first KAT
    """
    lines = []

    for line in file_like:
        if '=' in line:
            lines.append(line)

        if line.startswith('ss = '):
            break

    return ''.join(lines)


if __name__ == '__main__':
    # TODO: handle extraction from zip files?
    if len(sys.argv) != 2:  # cmd + file
        usage = 'extract.py [file.rsp]'
        sys.exit(usage)

    path = sys.argv[1]
    assert path.endswith('.rsp')  # TODO: does this always hold true?

    kat = None
    with open(path) as f:
        kat = extract_kat(f)

    n = kat.count('\n')
    assert n == 6, 'Got {} lines'.format(n)
    print(kat)
