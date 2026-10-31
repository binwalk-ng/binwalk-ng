#!/bin/bash
# Install dependencies from source.
# Requires that git and build tools (make, gcc, etc) are already installed.

BUILD_DIR=$(mktemp -d)
trap 'rm -rf "$BUILD_DIR"' EXIT

# Install LZFSE utility and library
git -C "$BUILD_DIR" clone https://github.com/lzfse/lzfse.git
make -C "$BUILD_DIR/lzfse" install

# Install dmg2img with LZFSE support
git -C "$BUILD_DIR" clone https://github.com/Lekensteyn/dmg2img.git
make -C "$BUILD_DIR/dmg2img" dmg2img HAVE_LZFSE=1
make -C "$BUILD_DIR/dmg2img" install
