# Benchmarks

CI benchmarking for `binwalk-ng`, based on [Gungraun](https://github.com/gungraun/gungraun)
(Valgrind's Callgrind + DHAT behind a Rust benchmark harness). Everything is
measured **deterministically** — instruction counts and allocation totals from a
single profiled run — so the numbers do not depend on how fast the CI runner is.
Wall-clock time is deliberately not measured.

## What is measured

Four scenarios against the release binary:

| scenario | workload |
|---|---|
| `scan_corpus` | `tests/testdata/samples/*` concatenated (~33 MB) |
| `extract_corpus` | `-Me` (extract + matryoshka recursion) on `scan_corpus`' file, into a fresh per-run sandbox |
| `list_signatures` | `-L` (list signatures/extractors, no file scan) |
| `scan_large` | `tests/testdata/samples/*` content repeated to exactly 128 MB |

Every scenario runs under **Callgrind** (instructions) and **DHAT** (heap):

| metric | tool | notes |
|---|---|---|
| `instructions` | callgrind `Ir` | total instructions of the whole `binwalk` process run, including all `--threads 4` worker threads |
| `total bytes allocated` | dhat `TotalBytes` | **total** heap bytes allocated over the run (cumulative, includes freed memory) |
| `heap allocations` | dhat `TotalBlocks` | total number of heap allocations |
| `peak live heap` | dhat `AtTGmaxBytes` | peak simultaneous live heap |

Measurement boundaries (see `benches/gungraun.rs`):

- **Child processes are excluded.** Gungraun forces `--trace-children=yes` by
  default; we pass `--trace-children=no`, so extractor subprocesses (7zip,
  sasquatch, jefferson, ...) run natively and their instructions/memory are not
  attributed to binwalk.
- **All threads are included.** Callgrind runs with `EntryPoint::None` and
  `--collect-atstart=yes` (and no `--toggle-collect`), so counting starts at
  process start and every `--threads 4` worker thread is counted. With
  Gungraun's default entry point (a toggle on `main`) spawned threads would
  collect *zero* metrics — that is why the default is overridden.
- **Instructions only.** `--cache-sim=no`; cache-hit and estimated-cycle metrics
  depend on the host CPU model and would make baselines from different runner
  hardware incomparable. `Ir` is deterministic per ISA (pin x64 in CI, never
  compare against an arm64 baseline).
- **ASLR disabled.** Gungraun's default — it runs Valgrind under
  `setarch -R`, which works on GitHub Actions runners (the `personality` syscall
  is allowed there) and matches what the tool's authors recommend. The measured
  metrics (`Ir`, dhat totals) are ASLR-independent, so this is hygiene more than
  correctness. Locally, either disable seccomp so `personality` is allowed
  (`docker run --security-opt seccomp=unconfined`) or pass `--allow-aslr`.
- **Sandboxed.** Each run executes in a fresh temp dir seeded with the workload
  fixtures, so the working-directory path length (which can change event
  counts) is identical on every machine.
- Workload files are generated once, at command-collection time (outside
  valgrind), into `target/gungraun/fixtures/`. `large.bin` repeats the sorted
  `tests/testdata/samples` bytes, so it is byte-identical on every machine.
  Fixtures are regenerated on every bench run, so derived files can't go stale
  when the samples change.

Because the metrics are one-shot and deterministic, a run has no stddev and the
old noise-band verdict is gone: the gate is a plain percentage threshold.

## Running locally

The benchmark environment is the Docker `dev` image (Dockerfile target `dev`),
which already has cargo, `cargo-binstall`, valgrind, and every external
extractor tool binwalk shells out to (7zip, sasquatch, dumpifs, dmg2img,
vfdecrypt, lzfse, jefferson, uefi_firmware, ...). `scripts/bench-run.py` does
the rest: it provisions a matching `gungraun-runner` via binstall (version read
from Cargo.toml), runs `cargo bench`, and writes the sanitized
`target/bench/results.json`.

```sh
docker build --target dev --tag binwalk-ng:dev .
docker run --rm --security-opt seccomp=unconfined \
  -v "$(pwd):/tmp/binwalk" -w /tmp/binwalk \
  binwalk-ng:dev \
  python3 scripts/bench-run.py
```

Gungraun disables ASLR via `setarch -R` by default; `--security-opt
seccomp=unconfined` unblocks the `personality` syscall in the container (or
pass `--allow-aslr` to the runner if you prefer to keep seccomp).

Without Docker, install valgrind and a `gungraun-runner` matching the
`gungraun` dev-dependency, then run `python3 scripts/bench-run.py` from the
repo root.

To compare two runs locally, run the benchmark twice — Gungraun diffs each
benchmark against the previous run's output and reports per-metric deltas.

## CI behavior (`.github/workflows/benchmark.yaml` + `.github/workflows/benchmark-report.yml`)

- Runs on every PR, on `main` pushes, and via `workflow_dispatch`.
- The `benchmark` job builds the Docker `dev` image (pinned environment:
  valgrind + all extractor tools) and runs
  `docker run ... python3 scripts/bench-run.py` with the repo mounted. That
  script installs `gungraun-runner` at the exact version of the `gungraun`
  dev-dependency, runs `cargo bench -- --output-format=json`, and strips
  run-specific fields (log/output paths, PIDs, per-thread parts) so identical
  runs produce byte-comparable `results.json`. `results.json` is uploaded as a
  workflow artifact.
- The `report` job lives in a separate `benchmark-report.yml` triggered by
  `workflow_run` once the `Benchmark` workflow completes, so it runs with a
  write-scoped token even on fork PRs (where the `pull_request` run itself
  only gets a read-only token). It downloads the artifact, fetches the latest
  baseline from `benchmark-baseline`, diffs, posts/updates a results table as a
  PR comment (including on fork PRs), surfaces the table in the job summary,
  and **fails the job** if a metric exceeds its threshold:
  - instructions / total bytes / heap allocations: **+5%**
  - peak live heap: **+10%** (measured under `--threads 4`, where valgrind's
    serialized scheduling can move the peak; treat it as indicative)
- On pushes to `main` (not PRs or manual runs): the results are pushed to the
  dedicated `benchmark-baseline` branch (root file `baseline.json`), but only
  when the metrics actually changed (the JSON is compared byte-for-byte). The
  bot never commits to `main`, so every commit on `main` is a code commit that
  CI ran on. PRs fetch the latest baseline from that branch before comparing.

## Objectivity notes

- Instruction counts and dhat totals are deterministic: same source + same ISA
  → same numbers, on any runner. This is what makes the baseline-branch
  mechanism sound even though each CI run lands on different runner hardware.
- Cache metrics and estimated cycles are intentionally not measured (they vary
  with CPU cache sizes, which would create bogus cross-runner deltas).
- Everything runs inside the Docker `dev` image, so binwalk sees the same
  runtime dependency set (glibc, valgrind, extractor tools) as production. A
  one-off environment change resets itself on the next `main` merge (baseline
  refresh).
- `peak live heap` is the one metric that can drift run-to-run under threads;
  if it proves flaky, either run `--threads 1` or relax its threshold in
  `scripts/bench-compare.py`.
- Thresholds are only applied when both baseline and result values exist for a
  metric. A benchmark (or metric) present in the baseline but missing from the
  new results is reported as a regression; a benchmark added in the new run
  that the baseline doesn't know about is shown in the table but not flagged.
- First run on a branch: if no `benchmark-baseline` exists yet, the PR
  comparison is skipped and the baseline is established on the next `main`
  push.

## results.json format

`target/bench/results.json` (and `baseline.json` on the `benchmark-baseline`
branch) is an array of Gungraun `BenchmarkSummary` objects — one per benchmark,
matching `cargo bench -- --output-format=json | jq -s`, with the PID-bearing
fields stripped. Schema: `profiles[].summaries.total.summary` keyed by
`Callgrind` / `Dhat`, each metric a `{metrics: {"Left": {"Int": n}}}`
object; see the [summary schema v6](https://github.com/gungraun/gungraun/blob/main/crates/gungraun-summary/schemas/summary.v6.schema.json).
`scripts/bench-compare.py` reads two such arrays, diffs by summary `id`, and renders
the verdict.
