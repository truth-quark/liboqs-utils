from io import StringIO
from oqs import extract


DUMMY_RSP = """
count = 01
seed = 1
pk = 2
sk = 3
ct = 4
ss = 5

"""

EXP_KAT = """count = 01
seed = 1
pk = 2
sk = 3
ct = 4
ss = 5
"""


def test_extract_kat():
    f = StringIO(DUMMY_RSP)
    res = extract.extract_kat(f)
    assert res == EXP_KAT
