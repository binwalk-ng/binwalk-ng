#!/bin/bash
#
# Generates the cpio.bin fixture used by tests/cpio.rs with GNU cpio's
# deterministic "newc" (SVR4 ASCII) format.
#
# The file contents, ordering, and parsed size/count are pinned here and
# asserted in the test, so the parser is verified against a real archive
# produced by an independent tool rather than against the parser itself.

cd "$(dirname "$0")" || exit 1

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

mkdir -p "$tmpdir/testdir"

printf 'Hello, binwalk-ng cpio!\n' > "$tmpdir/hello.txt"
printf '\xAB\xCD\xEF' > "$tmpdir/three_bytes.bin"
printf '#!/bin/sh\necho hi\n' > "$tmpdir/testdir/run.sh"

# Pinned metadata so the fixture is reproducible.
touch -d @0 "$tmpdir/hello.txt" "$tmpdir/three_bytes.bin" "$tmpdir/testdir" "$tmpdir/testdir/run.sh"
chmod 0644 "$tmpdir/hello.txt" "$tmpdir/three_bytes.bin"
chmod 0755 "$tmpdir/testdir" "$tmpdir/testdir/run.sh"

(
    cd "$tmpdir" || exit 1
    # Deterministic entry order; GNU cpio pads the archive out to 512-byte blocks.
    find . -mindepth 1 | sort | cpio -o -H newc
) > cpio.bin || exit $?

ls -la cpio.bin
