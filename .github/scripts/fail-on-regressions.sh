#!/usr/bin/env bash
# Fail the job if compare.json reports benchmark regressions.
set -euo pipefail

if jq -e '.regressed' target/bench/workdir/compare.json >/dev/null 2>&1; then
  echo 'Benchmark regressions detected:'
  jq -r '.warnings[]' target/bench/workdir/compare.json | sed 's/^/  - /'
  exit 1
fi
