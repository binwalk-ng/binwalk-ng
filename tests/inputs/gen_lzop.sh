#!/bin/bash
#
# Generates LZOP test fixtures used by tests/lzop.rs.
# The compressed content is deterministic so the fixture is reproducible.

cd "$(dirname "$0")" || exit 1

# ── Helper: generate deterministic content ────────────────────────────

gen_content() {
  python3 -c "
import sys
for chunk in range(112):
    for i in range(50):
        print(f'Testing LZOP compression, chunk {chunk}, line {i}: ' + 'x' * 40)
"
}

# ======================================================================
# 1. Standard multi-block LZOP file (compression level 1)
#    Stored filename: lzop_std.txt
#    Reference:       lzop_std.txt
# ======================================================================

gen_content > /tmp/lzop_std.txt
lzop -1 -c /tmp/lzop_std.txt > lzop.bin
echo "Created lzop.bin ($(wc -c < lzop.bin) bytes)"
cp /tmp/lzop_std.txt lzop_std.txt

# ======================================================================
# 2. Single-block LZOP file (small input, now passes with MIN_BLOCK_COUNT=1)
#    Stored filename: lzop_single.txt
# ======================================================================

echo "This is a small file for single-block testing." > /tmp/lzop_single.txt
lzop -1 -c /tmp/lzop_single.txt > lzop_single.bin
echo "Created lzop_single.bin ($(wc -c < lzop_single.bin) bytes)"

# ======================================================================
# 3. Higher compression level (lzop -9)
#    Stored filename: lzop_highcomp.txt
# ======================================================================

gen_content > /tmp/lzop_highcomp.txt
lzop -9 -c /tmp/lzop_highcomp.txt > lzop_highcomp.bin
echo "Created lzop_highcomp.bin ($(wc -c < lzop_highcomp.bin) bytes)"

# ======================================================================
# 4. No original file name stored (lzop -n)
#    Stored filename: (empty)
# ======================================================================

gen_content | lzop -1 -n -c > lzop_noname.bin
echo "Created lzop_noname.bin ($(wc -c < lzop_noname.bin) bytes)"

# ======================================================================
# 5. Original path preserved (lzop -P)
#    Stored filename: /tmp/lzop_path_data.txt
# ======================================================================

gen_content > /tmp/lzop_path_data.txt
lzop -1 -P -c /tmp/lzop_path_data.txt > lzop_withpath.bin
echo "Created lzop_withpath.bin ($(wc -c < lzop_withpath.bin) bytes)"

# ======================================================================
# 6. Very long filename (255 char name)
# ======================================================================

python3 -c "print('a'*255)" > /tmp/lzop_longname.txt
lzop -1 -c /tmp/lzop_longname.txt > lzop_longname.bin
echo "Created lzop_longname.bin ($(wc -c < lzop_longname.bin) bytes)"

# ======================================================================
# 7. Empty content (0 bytes uncompressed)
# ======================================================================

: > /tmp/lzop_empty.txt
lzop -1 -c /tmp/lzop_empty.txt > lzop_empty.bin 2>/dev/null
echo "Created lzop_empty.bin ($(wc -c < lzop_empty.bin) bytes)"

# ======================================================================
# 8. Different suffix ('.bin' file compressed with lzop)
#    Stored filename: testdata.bin
# ======================================================================

echo "Hello from a .bin file" > /tmp/testdata.bin
lzop -1 -c /tmp/testdata.bin > lzop_dotbin.bin
echo "Created lzop_dotbin.bin ($(wc -c < lzop_dotbin.bin) bytes)"

# ======================================================================
# Clean up temp files
# ======================================================================

rm -f /tmp/lzop_std.txt /tmp/lzop_single.txt /tmp/lzop_highcomp.txt \
      /tmp/lzop_noname.txt /tmp/lzop_path_data.txt /tmp/lzop_longname.txt \
      /tmp/lzop_empty.txt /tmp/testdata.bin
