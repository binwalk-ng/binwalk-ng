#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
d=$(mktemp -d)
trap 'rm -rf "$d"' EXIT
git clone --depth 1 --single-branch https://github.com/ssokolow/rar-test-files.git "$d" || { echo "error: failed to clone rar-test-files repo" >&2; exit 1; }
cp "$d/build/"* .
echo "Copied $(ls -1 "$d/build/"* | wc -l) test files"
