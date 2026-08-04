#!/usr/bin/env python3
"""CI benchmark harness for binwalk-ng: wall/cpu timing and heap profiling.

Measurement methodology matches the previous bash harness: hyperfine medians
for wall time, getrusage(RUSAGE_CHILDREN) for CPU time (same accounting as
bash's `time` builtin), valgrind dhat for heap, CPU affinity pinning, and
single-threaded memory runs.
"""

import argparse
import json
import os
import re
import resource
import shlex
import shutil
import statistics
import subprocess
import sys
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

BINWALK = os.environ.get("BINWALK", "target/release/binwalk")
CORPUS_DIR = os.environ.get("CORPUS_DIR", "tests/inputs")
WORKDIR = os.environ.get("WORKDIR", "benchmark/workdir")
RESULTS_JSON = os.environ.get("RESULTS_JSON", "benchmark/results.json")
BASELINE_JSON = os.environ.get("BASELINE_JSON", "benchmark/baseline.json")
THREADS = int(os.environ.get("THREADS", "4"))
LARGE_MB = int(os.environ.get("LARGE_MB", "128"))
RUNS = int(os.environ.get("RUNS", "10"))
WARMUP = int(os.environ.get("WARMUP", "2"))
CPU_REPS = int(os.environ.get("CPU_REPS", "7"))
JOBS = int(os.environ.get("JOBS", str(os.cpu_count() or 1)))
THRESH_TIME_PCT = float(os.environ.get("THRESH_TIME_PCT", "20"))
THRESH_CPU_PCT = float(os.environ.get("THRESH_CPU_PCT", "20"))
THRESH_MEM_PCT = float(os.environ.get("THRESH_MEM_PCT", "5"))


def sha() -> str:
    r = subprocess.run(
        ["git", "-c", "safe.directory=*", "rev-parse", "--short", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    return r.stdout.strip() if r.returncode == 0 else "unknown"


def require(tool: str, hint: str) -> None:
    if shutil.which(tool) is None:
        raise SystemExit(f"ERROR: required tool '{tool}' not found. {hint}")


def preflight() -> None:
    require("hyperfine", "install with: apt-get install hyperfine")
    require("valgrind", "install with: apt-get install valgrind")
    require("git", "needed to record the benchmarked commit sha")
    if not Path(CORPUS_DIR).is_dir():
        raise SystemExit(f"ERROR: CORPUS_DIR '{CORPUS_DIR}' does not exist")
    Path(WORKDIR).mkdir(parents=True, exist_ok=True)
    Path(RESULTS_JSON).parent.mkdir(parents=True, exist_ok=True)


def build_binwalk() -> Path:
    binwalk = Path(BINWALK)
    if not os.access(binwalk, os.X_OK):
        print(f"building {binwalk}", file=sys.stderr)
        subprocess.run(["cargo", "build", "--release"], check=True)
    binwalk = binwalk.resolve()
    if not os.access(binwalk, os.X_OK):
        raise SystemExit(f"ERROR: no binwalk binary at '{binwalk}' (build failed?)")
    return binwalk


def pin_cpuset() -> None:
    available = sorted(os.sched_getaffinity(0))[:JOBS]
    if not available:
        raise SystemExit("ERROR: no CPUs available for pinning")
    try:
        os.sched_setaffinity(0, available)
    except OSError as exc:
        raise SystemExit(f"ERROR: cannot pin to CPUs {available}: {exc}") from exc


def wall_ms_of(
    name: str, cmd: list[str], prepare: str | None = None
) -> tuple[int, dict[str, int]]:
    export = Path(WORKDIR) / f"hf-{name}.json"
    log = Path(WORKDIR) / f"hf-{name}.log"
    hf = [
        "hyperfine",
        "--warmup",
        str(WARMUP),
        "--runs",
        str(RUNS),
        "--export-json",
        str(export),
        "-n",
        name,
    ]
    if prepare is not None:
        hf += ["--prepare", prepare]
    hf.append(" ".join(shlex.quote(c) for c in cmd))
    with open(log, "w") as fh:
        r = subprocess.run(hf, stdout=subprocess.DEVNULL, stderr=fh, check=False)
    if r.returncode != 0:
        raise RuntimeError(f"ERROR: hyperfine failed for {name} (see {log})")
    data = json.loads(export.read_text())["results"][0]
    wall = round(data["median"] * 1000)
    stats = {f"{k}_ms": round(data[k] * 1000) for k in ("mean", "stddev", "min", "max")}
    return wall, stats


def cpu_ms_of(
    cmd: list[str], reps: int, prepare: Callable[[], None] | None = None
) -> int:
    values: list[float] = []
    for _ in range(reps):
        if prepare is not None:
            prepare()
        before = resource.getrusage(resource.RUSAGE_CHILDREN)
        subprocess.run(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True
        )
        after = resource.getrusage(resource.RUSAGE_CHILDREN)
        values.append(
            (after.ru_utime - before.ru_utime + after.ru_stime - before.ru_stime) * 1000
        )
    return round(statistics.median(values))


def massif_peak(out: Path) -> tuple[int, int]:
    heap = extra = stack = 0
    peak_heap = peak_stack = 0
    seen_snapshot = False
    for line in out.read_text().splitlines():
        if line.startswith("mem_heap_B="):
            heap = int(line.split("=", 1)[1])
        elif line.startswith("mem_heap_extra_B="):
            extra = int(line.split("=", 1)[1])
        elif line.startswith("mem_stacks_B="):
            stack = int(line.split("=", 1)[1])
        elif line.startswith("snapshot="):
            seen_snapshot = True
            peak_heap = max(peak_heap, heap + extra)
            peak_stack = max(peak_stack, stack)
    if not seen_snapshot:
        raise RuntimeError(f"ERROR: massif output contains no snapshots: {out}")
    return max(peak_heap, heap + extra), max(peak_stack, stack)


def valgrind_of(
    name: str, kind: str, tool_args: list[str], out_flag: str, cmd: list[str]
) -> tuple[Path, Path]:
    log = (Path(WORKDIR) / f"{kind}-{name}.log").resolve()
    out = (Path(WORKDIR) / f"{kind}-{name}.out").resolve()
    with open(log, "w") as fh:
        r = subprocess.run(
            ["valgrind", *tool_args, f"{out_flag}={out}", *cmd],
            cwd=WORKDIR,
            stdout=subprocess.DEVNULL,
            stderr=fh,
            check=False,
        )
    if r.returncode != 0:
        raise RuntimeError(f"ERROR: valgrind ({kind}) failed for {name} (see {log})")
    if re.search(r"\bERROR binwalk_ng\b", log.read_text()):
        raise RuntimeError(
            f"ERROR: binwalk reported an error under valgrind for {name} (see {log})"
        )
    # Valgrind (esp. DHAT) writes its output files mode 0600 owned by the
    # invoking user. In CI the benchmark container runs as root (uid 0) and
    # the upload-artifact step runs as the `runner` user, so those files must
    # be made world-readable for the artifacts to upload. Only the
    # valgrind-owned outputs here need relaxing; files written by bench.py
    # itself are already created with the process umask (0644).
    for path in (out, log):
        mode = path.stat().st_mode | 0o444
        path.chmod(mode)
    return out, log


def massif_of(name: str, cmd: list[str]) -> dict[str, int]:
    out, _ = valgrind_of(
        name, "massif", ["--tool=massif", "--stacks=yes"], "--massif-out-file", cmd
    )
    peak_heap, peak_stack = massif_peak(out)
    return {"peak_heap_bytes": peak_heap, "peak_stack_bytes": peak_stack}


def dhat_of(name: str, cmd: list[str]) -> dict[str, int]:
    out, _ = valgrind_of(name, "dhat", ["--tool=dhat"], "--dhat-out-file", cmd)
    try:
        data = json.loads(out.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"ERROR: failed to read dhat JSON for {name}: {exc}")
    pps = data.get("pps")
    if not isinstance(pps, list) or not pps:
        raise RuntimeError(
            f"ERROR: dhat JSON for {name} has no 'pps' array (valgrind schema changed?) — see {out}"
        )
    sample = pps[0]
    if not all(k in sample for k in ("tb", "tbk", "gb")):
        raise RuntimeError(
            f"ERROR: dhat JSON for {name} is missing pps fields tb/tbk/gb (valgrind schema changed?) — see {out}"
        )
    return {
        "peak_heap_bytes": sum(pp.get("gb", 0) for pp in pps),
        "total_alloc_bytes": sum(pp.get("tb", 0) for pp in pps),
        "alloc_count": sum(pp.get("tbk", 0) for pp in pps),
    }


def gen_workload() -> None:
    corpus = Path(WORKDIR) / "corpus.bin"
    files = sorted(p for p in Path(CORPUS_DIR).iterdir() if p.is_file())
    corpus_data = b"".join(p.read_bytes() for p in files)
    if not corpus_data:
        raise SystemExit(f"ERROR: no input files found in CORPUS_DIR '{CORPUS_DIR}'")
    corpus.write_bytes(corpus_data)
    size = LARGE_MB * 1024 * 1024
    if size < 16 * 1024 * 1024:
        raise SystemExit("ERROR: LARGE_MB too small (need >= 16)")
    large = Path(WORKDIR) / "large.bin"
    if not large.exists() or large.stat().st_size != size:
        large.write_bytes((corpus_data * (size // len(corpus_data) + 1))[:size])


def run_benchmarks() -> None:
    preflight()
    binwalk = build_binwalk()
    pin_cpuset()
    gen_workload()

    corpus = Path(WORKDIR) / "corpus.bin"
    large = Path(WORKDIR) / "large.bin"
    extract_dir = Path(WORKDIR) / "extract-corpus"
    scan = [str(binwalk), "--threads", str(THREADS), "-q"]
    list_cmd = [str(binwalk), "-q", "-L"]

    print("scan-corpus: wall clock", file=sys.stderr)
    scan_wall, scan_stats = wall_ms_of("scan-corpus", scan + [str(corpus)])
    print("scan-corpus: cpu time", file=sys.stderr)
    scan_cpu = cpu_ms_of(scan + [str(corpus)], CPU_REPS)

    def clean_extract() -> None:
        shutil.rmtree(extract_dir, ignore_errors=True)
        extract_dir.mkdir(parents=True)

    extract_cmd = scan + ["-M", "-e", "-d", str(extract_dir), str(corpus)]
    prepare = (
        f"rm -rf {shlex.quote(str(extract_dir))} "
        f"&& mkdir -p {shlex.quote(str(extract_dir))}"
    )
    print("extract-corpus: wall clock", file=sys.stderr)
    extract_wall, extract_stats = wall_ms_of("extract-corpus", extract_cmd, prepare)
    print("extract-corpus: cpu time", file=sys.stderr)
    extract_cpu = cpu_ms_of(extract_cmd, CPU_REPS, clean_extract)

    print("list-signatures: wall clock", file=sys.stderr)
    list_wall, list_stats = wall_ms_of("list-signatures", list_cmd)
    print("list-signatures: cpu time", file=sys.stderr)
    list_cpu = cpu_ms_of(list_cmd, CPU_REPS)

    print("scan-large: wall clock", file=sys.stderr)
    large_wall, large_stats = wall_ms_of("scan-large", scan + [str(large)])
    print("scan-large: cpu time", file=sys.stderr)
    large_cpu = cpu_ms_of(scan + [str(large)], CPU_REPS)

    mem_cmd = [str(binwalk), "--threads", "1", "-q"]

    print("scan-corpus: heap/stack profile (valgrind massif + dhat)", file=sys.stderr)
    mem_corpus = {
        "massif": massif_of("scan-corpus", mem_cmd + [str(corpus.resolve())]),
        "dhat": dhat_of("scan-corpus", mem_cmd + [str(corpus.resolve())]),
    }

    print(
        "extract-corpus: heap/stack profile (valgrind massif + dhat)", file=sys.stderr
    )
    extract_mem_cmd = mem_cmd + [
        "-M",
        "-e",
        "-d",
        str(extract_dir.resolve()),
        str(corpus.resolve()),
    ]
    clean_extract()
    mem_extract_massif = massif_of("extract-corpus", extract_mem_cmd)
    clean_extract()
    mem_extract_dhat = dhat_of("extract-corpus", extract_mem_cmd)
    mem_extract = {"massif": mem_extract_massif, "dhat": mem_extract_dhat}

    print(
        "list-signatures: heap/stack profile (valgrind massif + dhat)", file=sys.stderr
    )
    mem_list = {
        "massif": massif_of("list-signatures", mem_cmd + ["-L"]),
        "dhat": dhat_of("list-signatures", mem_cmd + ["-L"]),
    }

    print("scan-large: heap/stack profile (valgrind massif + dhat)", file=sys.stderr)
    mem_large = {
        "massif": massif_of("scan-large", mem_cmd + [str(large.resolve())]),
        "dhat": dhat_of("scan-large", mem_cmd + [str(large.resolve())]),
    }

    results = {
        "git_sha": sha(),
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "scenarios": {
            "scan_corpus": {
                "wall_ms": scan_wall,
                "wall_stats": scan_stats,
                "cpu_ms": scan_cpu,
                "mem": mem_corpus,
            },
            "extract_corpus": {
                "wall_ms": extract_wall,
                "wall_stats": extract_stats,
                "cpu_ms": extract_cpu,
                "mem": mem_extract,
            },
            "list_signatures": {
                "wall_ms": list_wall,
                "wall_stats": list_stats,
                "cpu_ms": list_cpu,
                "mem": mem_list,
            },
            "scan_large": {
                "wall_ms": large_wall,
                "wall_stats": large_stats,
                "cpu_ms": large_cpu,
                "mem": mem_large,
            },
        },
    }
    with open(RESULTS_JSON, "w") as fh:
        json.dump(results, fh, indent=2)
    print(json.dumps(results, indent=2))


def compare() -> None:
    if not Path(RESULTS_JSON).is_file():
        raise SystemExit(f"ERROR: results file '{RESULTS_JSON}' does not exist")
    if not Path(BASELINE_JSON).is_file():
        raise SystemExit(f"ERROR: baseline file '{BASELINE_JSON}' does not exist")
    cmd = [
        sys.executable,
        str(Path(__file__).with_name("compare.py")),
        "--results",
        RESULTS_JSON,
        "--baseline",
        BASELINE_JSON,
        "--time-threshold",
        str(THRESH_TIME_PCT),
        "--cpu-threshold",
        str(THRESH_CPU_PCT),
        "--mem-threshold",
        str(THRESH_MEM_PCT),
    ]
    if os.environ.get("COMPARE_JSON"):
        cmd += ["--compare-json", os.environ["COMPARE_JSON"]]
    raise SystemExit(subprocess.call(cmd))


def main() -> None:
    ap = argparse.ArgumentParser()
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--run", action="store_true", help="run benchmarks (default)")
    mode.add_argument(
        "--compare", action="store_true", help="compare results against baseline"
    )
    args = ap.parse_args()
    Path(WORKDIR).mkdir(parents=True, exist_ok=True)
    Path(RESULTS_JSON).parent.mkdir(parents=True, exist_ok=True)
    if args.compare:
        compare()
    else:
        run_benchmarks()


if __name__ == "__main__":
    main()
