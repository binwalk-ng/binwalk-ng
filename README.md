# binwalk-ng

A Rust re-implementation of the [ReFirmLabs/binwalk](https://github.com/ReFirmLabs/binwalk) firmware analysis tool. Identifies and extracts files and data embedded inside other files — compressed archives, file systems, boot images, executables, and more.

## Features

- Parallel, multi-threaded scanning and (optionally) extracting
- 30+ file signature definitions (firmware, filesystems, archives, media, executables, boot images)
- [Entropy analysis](#entropy-analysis) to detect compression and encryption
- Recursive extraction (matryoshka mode)
- JSON output for automation
- Usable as a Rust library

## Usage

```bash
# Scan a file for embedded data
binwalk firmware.bin

# Extract (-e) all signatures found, recursively (-M)
binwalk -Me firmware.bin
```

### Docker

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
