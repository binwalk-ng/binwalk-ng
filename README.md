# binwalk-ng

Firmware analysis tool, built for speed and accuracy.

This repository is a fork of the [ReFirmLabs/binwalk](https://github.com/ReFirmLabs/binwalk) project.

Binwalk identifies and optionally extracts files and data embedded inside other files. While its primary focus is firmware analysis, it supports a wide variety of file and data types including compressed archives, file systems, boot images, and more.

## Features

- Parallel, multi-threaded scanning
- Extraction of known file types
- Data carving of known and unknown content
- Entropy analysis to detect compression and encryption
- Recursive extraction (matryoshka mode)
- JSON logging for automation
- Usable as a Rust library

## Running binwalk-ng

Docker images are published to GitHub Container Registry with all system and runtime dependencies pre-installed:

```bash
docker pull ghcr.io/binwalk-ng/binwalk-ng:main
```

```bash
docker run --rm -v "$PWD:/analysis" ghcr.io/binwalk-ng/binwalk-ng:main -Me firmware.bin
```

## Library Usage

Binwalk can be used as a Rust library in your own projects:

```rust
use binwalk_ng::Binwalk;

// Create a new Binwalk instance
let binwalker = Binwalk::new();

// Read in the data to analyze
let file_data = std::fs::read("/tmp/firmware.bin").expect("Failed to read from file");

// Scan the file data and print the results
for result in binwalker.scan(&file_data) {
    println!("{:#?}", result);
}
```

Add binwalk-ng to your project:

```bash
cargo add binwalk-ng
```

## Supported Formats

Binwalk recognizes many file formats, including:

- **Compression**: gzip, bzip2, xz, lzma, lz4, zstd, lzfse, zlib, rar, 7zip, tar
- **File systems**: ext2/3/4, squashfs, jffs2, cramfs, romfs, yaffs2, UBIFS, NTFS, FAT, APFS, HFS+
- **Firmware**: U-Boot, uImage, FIT, EVA, TRX, program store, D-Link, TP-Link, Arcadyan
- **Executables**: ELF, PE, PE32+, Mach-O, DEX
- **Boot images**: Android boot images, EFI/GPT, MBR, program store
- **Archives**: ZIP, RAR, 7z, CAB, ARJ, cpio, deb
- **Media**: JPEG, PNG, BMP, GIF, PDF, SVG, RIFF/AVI

Run `binwalk --list` to see all supported signatures.

## Entropy Analysis

Generate an entropy graph to identify regions of unknown compression or encryption.

The entropy plot feature requires building with the `entropy-plot` Cargo feature:
```bash
cargo build --release --features entropy-plot
```

Then run:

```bash
binwalk -E firmware.bin
```

Or, to save the graph as a PNG file:

```bash
binwalk -E --png entropy.png firmware.bin
```

## Development

### Prerequisites

- Rust toolchain (stable)
- Docker (for full test suite)

### Code Quality

This project uses [`prek`](https://prek.j178.dev/) for Git pre-commit hooks. To start using the hooks, after installing `prek` run

```bash
prek install
```

### Testing

Tests run inside Docker to ensure all external tool dependencies are available:

```bash
docker build --target dev --tag binwalk-ng:dev .
docker run --rm -v "$(pwd):/tmp/binwalk" -e INSTA_UPDATE=new binwalk-ng:dev cargo insta test --unreferenced=reject
```
