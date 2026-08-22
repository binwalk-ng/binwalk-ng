//! Gungraun (callgrind + dhat) benchmarks for the `binwalk` binary.
//!
//! Each benchmark runs the release binary once under callgrind and once under
//! dhat. Only the `binwalk` process itself is measured: child extractors
//! (7zip, sasquatch, ...) are excluded with `--trace-children=no`, while all
//! worker threads (binwalk runs with `--threads 4`) are counted because
//! callgrind collects from process start (`--collect-atstart=yes`,
//! `EntryPoint::None`).
//!
//! The workload files (corpus.bin, large.bin) are generated once, at command
//! collection time (outside valgrind), into `target/gungraun/fixtures` and
//! copied into a fresh per-run sandbox by Gungraun.

use gungraun::prelude::*;
use gungraun::{BinaryBenchmarkConfig, Callgrind, Dhat, EntryPoint, Sandbox};
use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;

const LARGE_MB: usize = 128;
const THREADS: &str = "4";

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Relative fixture path, resolved by Gungraun against the workspace root.
fn fixture(name: &str) -> String {
    format!("target/gungraun/fixtures/{name}")
}

/// Generate the deterministic workload exactly once, before any sandbox is set
/// up. Runs in the runner process (not under valgrind), so it is not counted.
fn ensure_fixtures() {
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| {
        let inputs = workspace_root()
            .join("tests")
            .join("testdata")
            .join("samples");
        let mut files: Vec<PathBuf> = fs::read_dir(&inputs)
            .expect("samples submodule must exist; run cargo bench from the repo root")
            .map(|entry| entry.expect("read samples entry").path())
            .filter(|p| p.is_file())
            .collect();
        files.sort();
        let mut corpus: Vec<u8> = Vec::new();
        for f in &files {
            corpus.extend(fs::read(f).expect("read input file"));
        }
        assert!(
            !corpus.is_empty(),
            "tests/testdata/samples contains no files"
        );

        let dir = workspace_root()
            .join("target")
            .join("gungraun")
            .join("fixtures");
        fs::create_dir_all(&dir).expect("create fixtures dir");
        fs::write(dir.join("corpus.bin"), &corpus).expect("write corpus.bin");

        // Always regenerated, so derived fixtures can never go stale when the
        // samples submodule changes.
        let size = LARGE_MB * 1024 * 1024;
        let mut large = Vec::with_capacity(size);
        while large.len() < size {
            large.extend_from_slice(&corpus);
        }
        large.truncate(size);
        fs::write(dir.join("large.bin"), large).expect("write large.bin");
    });
}

fn binwalk() -> Command {
    Command::new(env!("CARGO_BIN_EXE_binwalk"))
}

/// Common config: exclude child processes, count everything in the `binwalk`
/// process (including all threads), instructions only, and run in a fresh
/// sandbox seeded with the given fixtures.
fn config(fixtures: &[&str]) -> BinaryBenchmarkConfig {
    BinaryBenchmarkConfig::default()
        .valgrind_args(["--trace-children=no"])
        .tool(
            Callgrind::with_args(["--collect-atstart=yes", "--cache-sim=no"])
                .entry_point(EntryPoint::None),
        )
        .tool(Dhat::default())
        .sandbox(Sandbox::new(true).fixtures(fixtures.iter().map(|f| fixture(f))))
        .clone()
}

#[binary_benchmark]
#[bench::scan_corpus(config = config(&["corpus.bin"]))]
fn bench_scan_corpus() -> Command {
    ensure_fixtures();
    binwalk()
        .args(["--threads", THREADS, "-q", "corpus.bin"])
        .build()
}

#[binary_benchmark]
#[bench::scan_large(config = config(&["large.bin"]))]
fn bench_scan_large() -> Command {
    ensure_fixtures();
    binwalk()
        .args(["--threads", THREADS, "-q", "large.bin"])
        .build()
}

#[binary_benchmark]
#[bench::list_signatures(config = config(&[]))]
fn bench_list_signatures() -> Command {
    ensure_fixtures();
    binwalk().args(["-L"]).build()
}

#[binary_benchmark]
#[bench::extract_corpus(config = config(&["corpus.bin"]))]
fn bench_extract_corpus() -> Command {
    ensure_fixtures();
    binwalk()
        .args([
            "--threads",
            THREADS,
            "-q",
            "-M",
            "-e",
            "-d",
            "extract-out",
            "corpus.bin",
        ])
        .build()
}

binary_benchmark_group!(
    name = binwalk_bench,
    benchmarks = [
        bench_scan_corpus,
        bench_scan_large,
        bench_list_signatures,
        bench_extract_corpus
    ]
);

main!(binary_benchmark_groups = binwalk_bench);
