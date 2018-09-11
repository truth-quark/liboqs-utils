import sys


def extract_kat(path):
    """Extract first KAT from path.
    :path: path to RSP file to extract KAT from
    """
    done = False
    lines = []

    with open(path) as f:
        while not done:
            line = f.readline()
            if '=' in line:
                lines.append(line)

            if line.startswith('ss = '):
                done = True

    return ''.join(lines)


if __name__ == '__main__':
    # TODO: handle extraction from zip files??
    if len(sys.argv) != 2  # cmd + file
        usage = 'extract.py [file.rsp]'
        sys.exit(usage)

    path = sys.argv[1]
    assert path.endswith('.rsp')  # TODO: does this always hold true?
    kat = extract_kat(path)
    n = kat.count('\n')
    assert n == 6, 'Got {} lines'.format(n)
    print(kat)
