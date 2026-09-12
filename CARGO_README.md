# binwalk-ng

Firmware analysis tool, built for speed and accuracy.

This crate is a fork of [ReFirmLabs/binwalk](https://github.com/ReFirmLabs/binwalk).

## System Requirements

Building requires the following system packages:

```bash
build-essential libfontconfig1-dev liblzma-dev
```

Full extraction support requires additional system and Python dependencies. See the [Dockerfile](https://github.com/binwalk-ng/binwalk-ng/blob/main/Dockerfile) for details.

## Example

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

### Optional Features

Enable the `entropy-plot` feature for entropy graph generation:

```toml
[dependencies]
binwalk-ng = { version = "4", features = ["entropy-plot"] }
```

## Links

- [Repository](https://github.com/binwalk-ng/binwalk-ng)
- [Documentation](https://docs.rs/binwalk-ng)
- [Issues](https://github.com/binwalk-ng/binwalk-ng/issues)
