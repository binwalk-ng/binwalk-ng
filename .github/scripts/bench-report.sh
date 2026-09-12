#!/usr/bin/env bash
# Fetch the latest baseline from the benchmark-baseline branch and run
# scripts/bench-compare.py against the PR results. Writes compare.json and
# appends the results table to the GitHub step summary.
#
# Env: COMPARE_JSON (path to write), HEAD_SHA (PR head sha).
set -euo pipefail

mkdir -p target/bench/workdir
if git ls-remote --exit-code --heads origin benchmark-baseline >/dev/null 2>&1; then
  git fetch -q origin benchmark-baseline:refs/remotes/origin/benchmark-baseline
else
  status=$?
  if [ "$status" -ne 2 ]; then
    echo 'ERROR: could not determine benchmark baseline status' >&2
    exit "$status"
  fi
  echo 'No benchmark baseline found yet; skipping comparison'
  exit 0
fi

git show origin/benchmark-baseline:baseline.json > target/bench/baseline.json
BASE_SHA=$(git rev-parse --short origin/benchmark-baseline)

# bench-compare.py always writes compare.json before exiting; its exit code
# only distinguishes "regression reported" from "failed to run". Capture the
# table regardless and gate on compare.json, so a regression can't hide a
# genuine failure and vice versa.
python3 scripts/bench-compare.py \
  --results target/bench/results.json \
  --baseline target/bench/baseline.json \
  --sha "$HEAD_SHA" \
  --base-sha "$BASE_SHA" \
  --compare-json "$COMPARE_JSON" \
  > target/bench/workdir/report.md || true

if ! jq -e . "$COMPARE_JSON" >/dev/null 2>&1; then
  echo 'ERROR: comparison failed without writing compare.json' >&2
  exit 1
fi
# Regressions are decided by fail-on-regressions.sh; this step only surfaces
# the table in the job summary.
{
  echo '## Benchmark results'
  cat target/bench/workdir/report.md
} >> "$GITHUB_STEP_SUMMARY"
