# Benchmarks

CI benchmarking for `binwalk-ng`: total runtime and memory usage (heap and
stack), designed so numbers stay comparable across different CI CPU hardware.

## What is measured

Four scenarios: three scan a single file with the release binary (`-q`), and
`list_signatures` lists signatures without scanning a file:

| scenario | workload |
|---|---|
| `scan_corpus` | `tests/inputs/*` concatenated (~6.6 MB) |
| `extract_corpus` | `-Me` (extract + matryoshka recursion) on `scan_corpus`' file, into a fresh `benchmark/workdir/extract-corpus/` dir per run |
| `list_signatures` | `-L` (list signatures/extractors, no file scan) |
| `scan_large` | `tests/inputs/*` content repeated to 128 MB (`LARGE_MB`) |

Per scenario:

| metric | how | notes |
|---|---|---|
| `wall_ms` | hyperfine median of 10 runs (2 warmup) | |
| `wall_stats` | hyperfine mean/stddev/min/max (ms) | shown as `±stddev` in the compare table to judge whether a wall delta is noise |
| `cpu_ms` | bash `time` builtin, user+sys, median of 7 runs | `--threads 4` + CPU pinned |
| `mem.massif.peak_heap_bytes` | valgrind `--tool=massif` | peak live heap (`mem_heap_B + mem_heap_extra_B` over all snapshots) |
| `mem.massif.peak_stack_bytes` | massif `--stacks=yes` | peak stack (`mem_stacks_B` over all snapshots) |

Every scenario is memory-profiled. Memory runs use `--threads 1` (valgrind
serializes threads anyway) and measure the `binwalk` process itself: extractor
child processes (7zip, sasquatch, ...) run natively under valgrind, so their
memory is not attributed to binwalk.

## Running locally

Benchmarks are meant to run inside the Docker `benchmark` image (Dockerfile target
`benchmark`, which extends `dev` and adds `hyperfine`, `valgrind`, `git`). The
harness is `benchmark/bench.py` (python3, stdlib only, already present in the
image); `--compare` delegates to `benchmark/compare.py`. Running in the image
guarantees the binary sees the same runtime dependencies (7zip, sasquatch,
jefferson, uefi_firmware, ...) as in production:

```sh
docker build --target benchmark --tag 'binwalk-ng:benchmark' .
docker run --rm -v "$(pwd):/tmp/binwalk" -w /tmp/binwalk \
    -e BINWALK=/usr/local/bin/binwalk \
    'binwalk-ng:benchmark' benchmark/bench.py --run
git fetch origin benchmark-baseline && git show FETCH_HEAD:baseline.json > benchmark/baseline.json
docker run --rm -v "$(pwd):/tmp/binwalk" -w /tmp/binwalk \
    -e COMPARE_JSON=benchmark/workdir/compare.json \
    'binwalk-ng:benchmark' benchmark/bench.py --compare
```

The repo is mounted read-write into the container; files written under
`benchmark/workdir` and `benchmark/results.json` will be owned by root. The
`BINWALK=/usr/local/bin/binwalk` override uses the binary baked into the image
(no rebuild inside the container); without it the harness builds
`target/release/binwalk` with the image's cargo instead.

Useful env vars (pass with `-e`): `RUNS`, `WARMUP`, `CPU_REPS`, `LARGE_MB`,
`THREADS`, `JOBS`, `THRESH_TIME_PCT` (default 20),
`THRESH_CPU_PCT` (20), `THRESH_MEM_PCT` (5), `BINWALK`,
`WORKDIR`.

## CI behavior (`.github/workflows/benchmark.yaml`)

- Runs on every PR, on `main` pushes, and via `workflow_dispatch`.
- Builds the Dockerfile `benchmark` target with BuildKit (Buildx + GHA layer cache
  as in `ghcr.yaml`; the Dockerfile's cargo-registry cache mounts speed up local
  rebuilds only, BuildKit doesn't persist them to the GHA cache), then runs the
  harness inside the image with the repo mounted at `/tmp/binwalk`.
- On PRs: posts/updates a results table as a comment and **fails the job** if any
  metric exceeds its threshold. Fork PRs get the comparison in the job summary
  but no comment (the bot token is read-only there).
- On pushes to `main` (not PRs or manual runs): the results are pushed to the
  dedicated `benchmark-baseline` branch (root file `baseline.json`), but only
  when the metrics actually changed (`date`/`git_sha` are ignored). The bot
  never commits to `main`, so every commit on `main` is a code commit that CI
  ran on. PRs fetch the latest baseline from that branch before comparing.

## Objectivity notes

- Memory metrics are CPU-independent: deterministic workloads, pinned threads,
  single-threaded memory runs. This is why the memory threshold is tight (+5%).
- Wall time varies with runner hardware; the gate uses the hyperfine median and
  CPU time (user+sys), with a loose +20% threshold. `scan_large` (128 MB) is long
  enough that wall time is dominated by scanning, not startup noise.
- `large.bin` repeats the same `tests/inputs` bytes (sorted, deterministic), so it
  is byte-identical on every machine.
- The whole measurement runs inside the Docker `benchmark` image, so binwalk sees the
  same runtime dependency set (and glibc version) as production. Absolute numbers
  differ from bare-host runs; the baseline is refreshed by CI on every `main`
  push, so a one-off environment change resets itself on the next merge.
- Thresholds are only applied when both baseline and result values exist for a
  metric (e.g. if a metric is missing from either side it is shown as `—`).

## results.json format

```json
{
  "git_sha": "abc1234",
  "date": "2026-08-01T07:10:43Z",
  "scenarios": {
    "scan_corpus": {
      "wall_ms": 28,
      "wall_stats": {"mean_ms": 28, "stddev_ms": 2, "min_ms": 26, "max_ms": 33},
      "cpu_ms": 30,
      "mem": {
        "massif": {"peak_heap_bytes": 1148048, "peak_stack_bytes": 12008},
        "dhat": {"peak_heap_bytes": 921857, "total_alloc_bytes": 3436989, "alloc_count": 6934}
      }
    },
    "extract_corpus": {"wall_ms": 310, "wall_stats": {"mean_ms": 312, "stddev_ms": 8, "min_ms": 300, "max_ms": 328}, "cpu_ms": 280, "mem": {"massif": {"peak_heap_bytes": 1500112, "peak_stack_bytes": 16384}, "dhat": {"peak_heap_bytes": 1312410, "total_alloc_bytes": 5122230, "alloc_count": 9241}}},
    "list_signatures": {"wall_ms": 4, "wall_stats": {"mean_ms": 4, "stddev_ms": 1, "min_ms": 3, "max_ms": 6}, "cpu_ms": 3, "mem": {"massif": {"peak_heap_bytes": 901110, "peak_stack_bytes": 16384}, "dhat": {"peak_heap_bytes": 840021, "total_alloc_bytes": 2101033, "alloc_count": 5187}}},
    "scan_large": {"wall_ms": 258, "wall_stats": {"mean_ms": 260, "stddev_ms": 9, "min_ms": 244, "max_ms": 279}, "cpu_ms": 260, "mem": {"massif": {"peak_heap_bytes": 1955520, "peak_stack_bytes": 16384}, "dhat": {"peak_heap_bytes": 1912201, "total_alloc_bytes": 7745120, "alloc_count": 11960}}}
  }
}
```
