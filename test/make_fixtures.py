"""Makes the test data for compress_test.goose.

zlib in Python is the reference encoder. Each case is a source file and
its .gz, .zz (zlib) and .raw (raw DEFLATE) forms.

The small cases go to test/data. Git keeps them, because http_test needs
them too. The large cases go to test/data/gen. Git ignores that directory,
so the package that users fetch stays small. The output is the same at
each run, so the small files do not change.

    python make_fixtures.py
"""

import os
import random
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
SMALL = os.path.join(HERE, "data")
LARGE = os.path.join(HERE, "data", "gen")
ALICE = os.path.join(HERE, "..", "..", "goose-bin", "goose-v2026.3-windows-x64",
                     "samples", "data", "alice.txt")


def deflate(data, level, wbits):
    # zlib writes a gzip header with mtime 0, so the bytes are the same at each run.
    c = zlib.compressobj(level, zlib.DEFLATED, wbits)
    return c.compress(data) + c.flush()


def write(directory, name, data):
    with open(os.path.join(directory, name), "wb") as f:
        f.write(data)


def case(directory, name, data, level=9):
    write(directory, name + ".bin", data)
    write(directory, name + ".gz", deflate(data, level, 31))
    write(directory, name + ".zz", deflate(data, level, 15))
    write(directory, name + ".raw", deflate(data, level, -15))


def main():
    os.makedirs(LARGE, exist_ok=True)
    rng = random.Random(1952)

    # ---- small: git keeps these
    case(SMALL, "empty", b"")
    case(SMALL, "hello", b"hello, hello, hello goose\n")              # a fixed-code block
    # Two gzip members in one file: the result is the two parts joined.
    write(SMALL, "multi.bin", b"first member\n" + b"second member\n")
    write(SMALL, "multi.gz", deflate(b"first member\n", 9, 31) + deflate(b"second member\n", 9, 31))
    # Corrupt and truncated input must fail with an error, not crash.
    good = bytearray(deflate(b"goose " * 1000, 9, 31))
    bad_crc = bytearray(good)
    bad_crc[-6] ^= 0xFF
    write(SMALL, "bad_crc.gz", bytes(bad_crc))
    write(SMALL, "truncated.gz", bytes(good[: len(good) // 2]))
    write(SMALL, "not_gzip.gz", b"this is plain text, not gzip data")
    # A small input with a large output, for the limit test.
    write(SMALL, "bomb.gz", deflate(b"\0" * 100000, 9, 31))

    # ---- large: git ignores these
    case(LARGE, "stored", bytes(rng.getrandbits(8) for _ in range(70000)), 0)  # two stored blocks
    case(LARGE, "random", bytes(rng.getrandbits(8) for _ in range(20000)))     # incompressible
    case(LARGE, "repeat", b"ab" * 20000)                                       # long overlapping matches
    words = [b"goose", b"duck", b"swan", b"heron", b"\n", b" ", b"egg", b"feather"]
    case(LARGE, "words", b"".join(rng.choice(words) for _ in range(15000)))    # dynamic blocks
    if os.path.exists(ALICE):
        with open(ALICE, "rb") as f:
            case(LARGE, "alice", f.read())


if __name__ == "__main__":
    main()
