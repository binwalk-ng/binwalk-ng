#!/bin/bash

cd "$(dirname "$0")" || exit 1

{
  # Spaces
  printf '%1000s' ''
  for _ in $(seq 100); do
    printf 'Testing, 1, 2, 3...\n'
  done
} | lzfse -encode > lzfse.bin
