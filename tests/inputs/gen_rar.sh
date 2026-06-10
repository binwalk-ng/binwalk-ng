#!/bin/bash
#
# Generates a minimal valid RAR5 archive used by tests/rar.rs.
#
# The archive contains:
#   - testdir/           (directory entry)
#   - testdir/hello.txt  ("Hello, RAR!\n")
#
# The file contents are pinned here and asserted in tests/rar.rs.
# Requires Python 3 (standard library only — no external RAR tools needed).

cd "$(dirname "$0")" || exit 1

python3 - << 'PY'
import struct
import zlib

def vint(n):
    """Encode n as a RAR5 variable-length integer."""
    result = []
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            b |= 0x80
        result.append(b)
        if not n:
            break
    return bytes(result)

def make_block(head_type, head_flags, type_specific, data=b""):
    """Assemble a RAR5 block with correct CRC32."""
    body = vint(head_type) + vint(head_flags)
    if head_flags & 0x0002:          # data area present flag
        body += type_specific + vint(len(data))
    else:
        body += type_specific
    head_size_encoded = vint(len(body))
    crc_data = head_size_encoded + body
    crc = zlib.crc32(crc_data) & 0xffffffff
    return struct.pack('<I', crc) + crc_data + data

# RAR5 signature
MAGIC = b"Rar!\x1a\x07\x01\x00"

# Archive header block (type=1, no flags).
# The type-specific data for ARCHIVE_HEADER is: vint(ARCHIVE_FLAGS).
archive_header = make_block(1, 0, vint(0))

# Directory entry: "testdir"
dir_name = b"testdir"
dir_specific = (
    vint(0x0001) +   # FILE_FLAGS: directory
    vint(0) +        # unpacked_size = 0
    vint(0x10) +     # attributes = directory
    vint(0x32) +     # compression_info: version=50, store
    vint(1) +        # host_os = Unix
    vint(len(dir_name)) +
    dir_name
)
# No data area for directories (HEAD_FLAGS = 0)
dir_block = make_block(2, 0x0000, dir_specific)

# File entry: "testdir/hello.txt"
file_data = b"Hello, RAR!\n"
file_crc  = zlib.crc32(file_data) & 0xffffffff
file_name = b"testdir/hello.txt"
file_specific = (
    vint(0x0004) +                  # FILE_FLAGS: CRC32 present
    vint(len(file_data)) +          # unpacked_size
    vint(0x20) +                    # attributes = regular file
    struct.pack('<I', file_crc) +   # file CRC32
    vint(0x32) +                    # compression_info: version=50, store
    vint(1) +                       # host_os = Unix
    vint(len(file_name)) +
    file_name
)
# HEAD_FLAGS = 0x0002: data area is present
file_block = make_block(2, 0x0002, file_specific, file_data)

# End-of-archive block (type=5, no flags).
# The type-specific data for END_OF_ARCHIVE is: vint(END_FLAGS).
eof_block = make_block(5, 0, vint(0))

archive = MAGIC + archive_header + dir_block + file_block + eof_block

with open("rar.bin", "wb") as f:
    f.write(archive)

print(f"Written rar.bin ({len(archive)} bytes)")
PY