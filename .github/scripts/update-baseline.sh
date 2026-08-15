#!/usr/bin/env bash
# Update benchmark-baseline branch from target/bench/results.json when metrics changed.
set -euo pipefail

if ! test -s target/bench/results.json \
  || ! jq -e 'type == "array"' target/bench/results.json >/dev/null 2>&1; then
  echo 'ERROR: target/bench/results.json missing or invalid; not updating baseline' >&2
  exit 1
fi

baseline_tmp=$(mktemp)
trap 'rm -f "$baseline_tmp"' EXIT

git fetch -q origin benchmark-baseline:refs/remotes/origin/benchmark-baseline || true
if git rev-parse -q --verify origin/benchmark-baseline >/dev/null \
  && git show origin/benchmark-baseline:baseline.json > "$baseline_tmp" 2>/dev/null \
  && cmp -s "$baseline_tmp" target/bench/results.json; then
  echo 'Metrics unchanged; keeping the committed baseline'
  exit 0
fi

tree=$(printf '100644 blob %s\tbaseline.json\n' \
  "$(git hash-object -w target/bench/results.json)" | git mktree)
parent=$(git rev-parse -q --verify origin/benchmark-baseline || git rev-parse HEAD)
commit=$(echo 'Update benchmark baseline' | \
  git -c user.name='github-actions[bot]' \
      -c user.email='41898282+github-actions[bot]@users.noreply.github.com' \
      commit-tree "$tree" -p "$parent")
git push -q origin "$commit:refs/heads/benchmark-baseline"
