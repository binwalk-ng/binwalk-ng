#!/usr/bin/env python3
"""Run the gungraun benchmark suite and write target/bench/results.json.

Provisions `gungraun-runner` (via `cargo binstall`, version taken from the
`gungraun` dev-dependency in Cargo.toml) if missing or mismatched, runs
`cargo bench`, and sanitizes the JSON output into a stable results file:
PID-bearing and per-thread/part fields are dropped so identical runs produce
byte-comparable output.

Run from the repo root (locally, or inside the Docker `dev` image with the
repo mounted at /tmp/binwalk).
"""

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import tomllib


def runner_version() -> str:
    with Path("Cargo.toml").open("rb") as fh:
        manifest = tomllib.load(fh)
    dep = None
    for section in ("dev-dependencies", "dependencies", "build-dependencies"):
        dep = (manifest.get(section) or {}).get("gungraun")
        if dep:
            break
    if dep is None:
        raise SystemExit("ERROR: gungraun dependency not found in Cargo.toml")
    if isinstance(dep, str):
        return dep
    return dep.get("version", "")


def ensure_runner(version: str) -> None:
    exe = shutil.which("gungraun-runner")
    if exe:
        try:
            out = subprocess.run(
                [exe, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if re.search(re.escape(version), out.stdout + out.stderr):
                return
        except (OSError, subprocess.SubprocessError):
            pass
    print(f"Installing gungraun-runner@{version} ...", file=sys.stderr)
    subprocess.run(
        ["cargo", "binstall", "-y", f"gungraun-runner@{version}"], check=True
    )


def main() -> None:
    version = runner_version()
    ensure_runner(version)

    bench_dir = Path("target/bench")
    bench_dir.mkdir(parents=True, exist_ok=True)

    proc = subprocess.run(
        ["cargo", "bench", "--bench", "gungraun", "--", "--output-format=json"],
        capture_output=True,
        text=True,
        check=False,
    )
    (bench_dir / "bench.log").write_text(proc.stderr)
    if proc.returncode != 0:
        print(proc.stderr, file=sys.stderr)
        raise SystemExit(f"ERROR: cargo bench failed (exit {proc.returncode})")

    results = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        summary = json.loads(line)
        results.append(
            {
                "id": summary.get("id"),
                "module_path": summary.get("module_path"),
                "profiles": [
                    {
                        "tool": profile.get("tool"),
                        "summaries": {
                            "total": (profile.get("summaries") or {}).get("total")
                        },
                    }
                    for profile in (summary.get("profiles") or [])
                ],
            }
        )

    (bench_dir / "results.json").write_text(json.dumps(results, sort_keys=True))
    print(f"Wrote {bench_dir / 'results.json'} ({len(results)} benchmarks)")


if __name__ == "__main__":
    main()
