#!/bin/bash
#
# Generates LZOP test fixtures used by tests/lzop.rs.
# The compressed content is deterministic so the fixture is reproducible.
#
# Requires: lzop (the external utility) for generating the compressed test inputs.

cd "$(dirname "$0")" || exit 1

TMPDIR=$(mktemp -d) || exit 1

# ── Shared deterministic content ──────────────────────────────────────
# Repetitions of classic Lorem Ipsum so the reference file is large
# enough to produce multiple LZOP blocks at the default block size.
# extraction_reference.txt is also used by tests/lzop.rs for byte-level
# decompression verification.

if [ ! -f extraction_reference.txt ]; then
    echo "ERROR: extraction_reference.txt not found — create it first." >&2
    rm -rf "$TMPDIR"
    exit 1
fi

REF="extraction_reference.txt"

# ======================================================================
# 1. Standard multi-block LZOP file (compression level 1)
#    Stored filename: extraction_reference.txt
# ======================================================================

cp -p "$REF" "$TMPDIR"/extraction_reference.txt
lzop -1 -c "$TMPDIR"/extraction_reference.txt > lzop.bin
echo "Created lzop.bin ($(wc -c < lzop.bin) bytes)"

# ======================================================================
# 2. Single-block LZOP file (small input)
#    Stored filename: lzop_single.txt
# ======================================================================

echo "This is a small file for single-block testing." > "$TMPDIR"/lzop_single.txt
touch -r "$REF" "$TMPDIR"/lzop_single.txt
lzop -1 -c "$TMPDIR"/lzop_single.txt > lzop_single.bin
echo "Created lzop_single.bin ($(wc -c < lzop_single.bin) bytes)"

# ======================================================================
# 3. No original file name stored (lzop -n)
#    Stored filename: (empty)
# ======================================================================

cp -p "$REF" "$TMPDIR"/lzop_noname_src.txt
lzop -1 -n -c "$TMPDIR"/lzop_noname_src.txt > lzop_noname.bin
echo "Created lzop_noname.bin ($(wc -c < lzop_noname.bin) bytes)"

# ======================================================================
# 4. Original path preserved (lzop -P)
#    Stored filename: subdir/lzop_withpath_src.txt
#
#    Note: uses a fixed relative path inside the script dir so the
#    lzop header stores a deterministic path across runs.
# ======================================================================

mkdir -p ./lzop_fixed_path
cp -p "$REF" ./lzop_fixed_path/lzop_withpath_src.txt
lzop -1 -P -c ./lzop_fixed_path/lzop_withpath_src.txt > lzop_withpath.bin
rm -rf ./lzop_fixed_path
echo "Created lzop_withpath.bin ($(wc -c < lzop_withpath.bin) bytes)"

# ======================================================================
# 5. Very long filename (255 char name)
# ======================================================================

printf '%*s' 255 '' | tr ' ' 'a' > "$TMPDIR"/lzop_longname.txt
touch -r "$REF" "$TMPDIR"/lzop_longname.txt
lzop -1 -c "$TMPDIR"/lzop_longname.txt > lzop_longname.bin
echo "Created lzop_longname.bin ($(wc -c < lzop_longname.bin) bytes)"

# ======================================================================
# 6. Empty content (0 bytes uncompressed)
# ======================================================================

: > "$TMPDIR"/lzop_empty.txt
touch -r "$REF" "$TMPDIR"/lzop_empty.txt
lzop -1 -c "$TMPDIR"/lzop_empty.txt > lzop_empty.bin 2>/dev/null
echo "Created lzop_empty.bin ($(wc -c < lzop_empty.bin) bytes)"

# ======================================================================
# 7. Different suffix ('.bin' file compressed with lzop)
#    Stored filename: testdata.bin
# ======================================================================

echo "Hello from a .bin file" > "$TMPDIR"/testdata.bin
touch -r "$REF" "$TMPDIR"/testdata.bin
lzop -1 -c "$TMPDIR"/testdata.bin > lzop_dotbin.bin
echo "Created lzop_dotbin.bin ($(wc -c < lzop_dotbin.bin) bytes)"

# ======================================================================
# 8. CRC32 checksums (lzop --crc32)
#    Stored filename: extraction_reference.txt
# ======================================================================

cp -p "$REF" "$TMPDIR"/extraction_reference.txt
lzop --crc32 -1 -c "$TMPDIR"/extraction_reference.txt > lzop_crc32.bin
echo "Created lzop_crc32.bin ($(wc -c < lzop_crc32.bin) bytes)"

# ======================================================================
# 9. FLAG_FILTER set in header (lzop --filter=1)
#    Stored filename: extraction_reference.txt
# ======================================================================

cp -p "$REF" "$TMPDIR"/lzop_filter_src.txt
lzop --filter=1 -1 -c "$TMPDIR"/lzop_filter_src.txt > lzop_filter.bin
echo "Created lzop_filter.bin ($(wc -c < lzop_filter.bin) bytes)"

# ======================================================================
# 10. Method 1 compression (lzop -2, LZO1X-1, method=01)
#     Stored filename: extraction_reference.txt
# ======================================================================

cp -p "$REF" "$TMPDIR"/lzop_method1_src.txt
lzop -2 -c "$TMPDIR"/lzop_method1_src.txt > lzop_method1.bin
echo "Created lzop_method1.bin ($(wc -c < lzop_method1.bin) bytes)"

# ======================================================================
# 12. Method 3 compression (lzop -99, LZO1X-999, method=03)
#     Stored filename: extraction_reference.txt
# ======================================================================

cp -p "$REF" "$TMPDIR"/lzop_method3_src.txt
lzop -99 -c "$TMPDIR"/lzop_method3_src.txt > lzop_method3.bin
echo "Created lzop_method3.bin ($(wc -c < lzop_method3.bin) bytes)"

# ======================================================================
# Clean up temp directory
# ======================================================================

rm -rf "$TMPDIR"
