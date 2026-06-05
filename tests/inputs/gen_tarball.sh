#!/bin/bash
#
# Generates a deterministic POSIX (ustar) tar archive used by tests/tarball.rs.
#
# The archive layout and file contents are pinned here and asserted in the test,
# so the extractor (currently external `tar`, soon to be replaced) can be verified
# to produce exactly these files with exactly these contents.

cd "$(dirname "$0")" || exit 1

python3 - <<'PY'
import io
import tarfile


def reset(info):
    # Fully deterministic metadata so the fixture is reproducible.
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    return info


# Pinned regular-file contents and modes -- keep in sync with tests/tarball.rs.
# (name, data, mode): run.sh is executable; the others are plain 0644 files.
files = [
    ("testdir/hello.txt",       b"Hello, binwalk-ng tarball!\n", 0o644),
    ("testdir/readme.md",       b"# Tarball test fixture\n",      0o644),
    ("testdir/nested/data.bin", b"\xAB" * 256,                    0o644),
    ("testdir/run.sh",          b"#!/bin/sh\necho hi\n",          0o755),
]

with tarfile.open("tarball.bin", "w", format=tarfile.USTAR_FORMAT) as tar:
    for name, data, mode in files:
        info = reset(tarfile.TarInfo(name))
        info.mode = mode
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))

    # An explicit directory entry with the sticky bit set (exercises the Directory
    # extraction path and directory-mode restoration).
    d = reset(tarfile.TarInfo("testdir/subdir"))
    d.type = tarfile.DIRTYPE
    d.mode = 0o1755
    tar.addfile(d)

    # A symlink entry (exercises the chroot-safe symlink extraction path);
    # points at hello.txt in the same directory.
    link = reset(tarfile.TarInfo("testdir/hello.link"))
    link.type = tarfile.SYMTYPE
    link.mode = 0o777
    link.linkname = "hello.txt"
    tar.addfile(link)
PY
