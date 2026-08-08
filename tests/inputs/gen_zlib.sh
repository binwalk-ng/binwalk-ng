#!/bin/bash
#
# Generates the zlib.bin fixture used by tests/zlib.rs with Python's zlib
# module (an independent implementation of the zlib format).
#
# The decompressed content is pinned here and the fixture is committed, so
# regeneration must produce byte-identical output (Python's zlib.compress is
# deterministic for a given input and compression level).

cd "$(dirname "$0")" || exit 1

python3 - <<'PY'
import zlib

# Pinned decompressed content -- keep in sync with any content assertions.
content = (
    b"Hello, binwalk-ng zlib!\n"
    + b"Some more text to make the stream longer than a single block.\n" * 4
    + b"\x00\x01\x02\x03" * 64
)

with open("zlib.bin", "wb") as f:
    f.write(zlib.compress(content, level=9))
PY

ls -la zlib.bin
