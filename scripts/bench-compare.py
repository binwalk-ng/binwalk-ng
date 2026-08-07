#!/usr/bin/env python3
"""Compare Gungraun (callgrind/dhat) benchmark results against a baseline.

`--results` and `--baseline` are both arrays of Gungraun summary objects, as
produced by `cargo bench -- --output-format=json` slurped into a single JSON
array. Benchmarks are matched by their summary `id`.

Metrics are one-shot and deterministic: callgrind instruction counts and dhat
allocation totals do not depend on runner speed, so the verdict is a plain
percentage-threshold gate (no wall-time noise band). The `peak heap` (dhat
AtTGmaxBytes) is measured with `--threads 4`, so under valgrind's serialized
thread scheduling it is the one metric that can drift; it therefore gets a
looser threshold and should be treated as indicative.
"""

import argparse
import json
import sys
from typing import Any

DASH = "—"

# (tool name in summary, metric key, display label, threshold %)
# Instructions + allocation totals are scheduling-independent; peak heap is not.
METRICS = [
    ("Callgrind", "Ir", "instructions", 5.0),
    ("DHAT", "TotalBytes", "total bytes allocated", 5.0),
    ("DHAT", "TotalBlocks", "heap allocations", 5.0),
    ("DHAT", "AtTGmaxBytes", "peak live heap", 10.0),
]


def load(path: str) -> list[Any]:
    with open(path) as fh:
        return json.load(fh)


def by_id(items: list[Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for item in items:
        out[item.get("id") or item.get("module_path") or ""] = item
    return out


def unwrap(v: Any) -> Any:
    if isinstance(v, dict):
        return v.get("Int", v.get("Float"))
    return v


# `profiles[].tool` uses the ValgrindTool const ("DHAT"), while the summary
# map is keyed by the ToolMetricSummary variant name ("Dhat").
SUMMARY_KEY = {"Callgrind": "Callgrind", "DHAT": "Dhat"}


def metric_value(summary: dict[str, Any], tool: str, metric: str) -> Any:
    """New-side value of (tool, metric) for one benchmark summary, or None."""
    for profile in summary.get("profiles") or []:
        if profile.get("tool") != tool:
            continue
        total = (profile.get("summaries") or {}).get("total") or {}
        tool_map = (total.get("summary") or {}).get(SUMMARY_KEY.get(tool, tool)) or {}
        md = tool_map.get(metric) or {}
        metrics = md.get("metrics") or {}
        if "Left" in metrics:
            return unwrap(metrics["Left"])
        if "Both" in metrics:
            return unwrap(metrics["Both"][0])
        return None
    return None


def delta(a: Any, b: Any) -> float | None:
    if a is None or b is None or a == 0:
        return None
    return round((b - a) / a * 1000) / 10


def pct(x: float | None) -> str:
    return DASH if x is None else ("+" if x > 0 else "") + f"{x}%"


def fmt_count(x: Any) -> str:
    return DASH if x is None else f"{int(x):,}"


def fmt_bytes(x: Any) -> str:
    if x is None:
        return DASH
    n = int(x)
    if n >= 1000 * 1000:
        return f"{n / (1000 * 1000):.1f} MB"
    if n >= 1000:
        return f"{n / 1000:.1f} KB"
    return f"{n} B"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", required=True)
    ap.add_argument("--baseline", required=True)
    ap.add_argument(
        "--threshold",
        type=float,
        default=None,
        help="override all metric thresholds with one %% value",
    )
    ap.add_argument("--compare-json", default=None)
    ap.add_argument("--sha", default="")
    ap.add_argument("--base-sha", default="")
    args = ap.parse_args()

    res = load(args.results)
    base = load(args.baseline)
    if not isinstance(res, list) or not isinstance(base, list):
        raise SystemExit("ERROR: results/baseline must be arrays of gungraun summaries")

    rs = by_id(res)
    bs = by_id(base)

    thresholds = {
        name: args.threshold if args.threshold is not None else t
        for _, _, name, t in METRICS
    }

    rows: list[dict[str, Any]] = []
    warnings: list[str] = []
    regressed = False

    for name in sorted(set(rs) | set(bs)):
        if name not in rs:
            regressed = True
            warnings.append(f"{name}: missing from new results")
            continue
        r = rs[name]
        b = bs.get(name)
        row: dict[str, Any] = {"scenario": name, "regressed": False, "cells": {}}
        for tool, key, label, _ in METRICS:
            bv = metric_value(b, tool, key) if b else None
            nv = metric_value(r, tool, key)
            d = delta(bv, nv)
            if bv is not None and nv is None:
                regressed = True
                row["regressed"] = True
                warnings.append(f"{name} {label}: missing from new results")
            elif bv == 0 and nv is not None and nv > 0:
                regressed = True
                row["regressed"] = True
                warnings.append(f"{name} {label}: increased from zero to {nv}")
            elif (
                bv is not None
                and nv is not None
                and d is not None
                and d > thresholds[label]
            ):
                regressed = True
                row["regressed"] = True
                warnings.append(f"{name} {label}: +{d}%")
            row["cells"][label] = {"base": bv, "new": nv, "delta_pct": d}
        rows.append(row)

    md = [
        (
            "| scenario | instructions (base → new) | Δ | total bytes allocated | Δ | "
            "heap allocations | Δ | peak live heap | Δ | verdict |"
        ),
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    fmt = {
        "instructions": fmt_count,
        "total bytes allocated": fmt_bytes,
        "heap allocations": fmt_count,
        "peak live heap": fmt_bytes,
    }
    for row in rows:
        cells = row["cells"]
        line = [f"| {row['scenario']} "]
        for label, formatter in fmt.items():
            c = cells.get(label, {})
            b, n, d = c.get("base"), c.get("new"), c.get("delta_pct")
            pair = (
                "—" if b is None and n is None else (f"{formatter(b)} → {formatter(n)}")
            )
            line.append(f"| {pair} | {pct(d)} ")
        line.append(f"| {'❌' if row['regressed'] else '✅'} |")
        md.append("".join(line))

    verdict = {
        "base_sha": args.base_sha,
        "sha": args.sha,
        "regressed": regressed,
        "warnings": warnings,
        "notes": [],
        "rows": rows,
        "md": "\n".join(md),
    }
    if args.compare_json:
        with open(args.compare_json, "w") as fh:
            json.dump(verdict, fh, indent=2)
    print("\n".join(md))
    if regressed:
        print("\nregressions:")
        for w in warnings:
            print(f"  - {w}")
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
