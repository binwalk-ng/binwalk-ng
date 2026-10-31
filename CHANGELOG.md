# Changelog

All notable changes to binwalk-ng are recorded here. Versions up to and including
3.1.0 were released under the `ReFirmLabs/binwalk` repository.

## Unreleased

### Breaking changes

- **QNX IFS extraction is now internal.** The external `dumpifs` utility is no
  longer used; images are parsed and extracted in-process with the
  [`qnx-ifs`](https://crates.io/crates/qnx-ifs) crate. The public
  `extractors::dumpifs` module and the
  `formats::qnx::IFSHeader`/`parse_ifs_header` helpers are removed.

### Features

- QNX IFS images are detected and extracted without external tools, including
  bootable images, compressed images, and bare `imagefs` filesystems.

## 4.0.0 — 2026-09-29

The first release from the `binwalk-ng` organization, published to crates.io as
`binwalk-ng`. The CLI binary is still named `binwalk`.

### Breaking changes

- **`Binwalk` is now configured through a builder.** `Binwalk::builder()` replaces
  direct field assignment; the struct's fields are private. `Binwalk::new()` still
  works and returns a default configuration. This is the main reason for the major
  version bump, and it is a breaking change for library consumers.
- **Modules are now organized by format rather than by layer.** Parsers,
  structures and extractors for a format live together instead of being split
  across separate top-level modules. Internal module paths have changed; the
  public API exported from the crate root is unchanged.
- Sample files used by the test suite moved out of the repository into the
  [`binwalk-ng-samples`](https://github.com/binwalk-ng/binwalk-ng-samples)
  submodule, keeping large binary fixtures out of the main tree.
- Some other minor API breakings compared to v3.

### Features

- **Fritz!Box EVA images** are now detected and extracted, using an internally
  written extractor rather than an external tool
- **Broadcom ProgramStore firmware** is supported
- **New dlink formats**, including DAP-1325
- **Internal extractors** now handle lzfse, zstd, lz4, rar, tar and Motorola
  srec, so these formats no longer depend on external utilities
- **Files are read via memory mapping** where possible, which avoids copying
  large firmware images into memory. Can be turned off with `--no-mmap`
- **Entropy graph generation was rewritten.** It no longer depends on plotly or
  opens a browser window, and is enabled by default
- **Published Docker images for both amd64 and arm64**, so the official image
  works on Apple Silicon and other arm64 machines without emulation
- Android sparse images are now extracted as genuinely sparse files, rather than
  as fully materialized ones
- The sevenzip extractor now uses `7z` instead of `7zz`, which is the name
  available on more systems
- The CLI binary was switched to use the library crate directly, so the binary
  and the library can no longer drift apart

### Performance and Security

- Migrated the thread pool to [rayon](https://github.com/rayon-rs/rayon) for
  parallel scanning, and the analysis loop now blocks on a channel timeout instead
  of polling and sleeping every millisecond, so idle time no longer burns CPU
  wakeups and shutdown is more predictable
- Scanning skips ahead through runs of zero bytes, which are common in firmware
  padding, making analysis of each file considerably faster
- **Structure parsing migrated to [zerocopy](https://github.com/google/zerocopy/)**,
  replacing hand-written offset and endianness code across roughly 60 formats and
  structures, which removes a large class of bounds-checking mistakes
- Assorted allocation and cloning reductions across the parsers, and main engine
- **Extraction can no longer escape its output directory through symlinks.** Chroot
  paths are now resolved physically, so a crafted archive cannot write outside the
  directory it was given
- **Reduced memory use on large inputs.** The analysis state is shared between
  worker threads instead of being copied for each one
- Format parsers hardened against integer overflow and out-of-bounds reads
- Extraction no longer panics on malformed symlink targets, and falls back to
  carving when a symlink cannot be created
- Backported the upstream csman decompression-bomb fixes, and the Android sparse
  image fixes
- Zip parsing treats a truncated archive as the end of the archive rather than an
  error, and the `dlob` parser no longer panics on malformed input
- The Aho-Corasick magic-pattern automaton is now built once per `Binwalk` instance
  instead of per scan, and single-pattern searches use `memchr::memmem` directly
- Numerous smaller optimizations

### Internal

- Test suite expanded to cover more formats in the samples directory, and now runs
  in CI inside Docker.
- Various CLI improvements.
- Added benchmarks to the CI with [gungraun](https://github.com/gungraun/gungraun).
- Added pre-commit-hooks with [prek](https://prek.j178.dev/).
- Additional clippy lints, and stricter fmt, link-check and clippy jobs in CI.
- The Docker base image was updated, and unused packages were dropped from it.
- Dependency updates.
