#!/usr/bin/env python3
import argparse
import json
import sys
from typing import Any, TypeAlias

DASH = "—"

# One compared metric: {"base": ..., "new": ..., "delta_pct": ...}
Cell: TypeAlias = dict[str, float | int | None]
# Metric name -> Cell
MetricSet: TypeAlias = dict[str, Cell]
# Memory source (e.g. "dhat") -> MetricSet
Mems: TypeAlias = dict[str, MetricSet]


def load(path: str) -> dict[str, Any]:
    with open(path) as fh:
        return json.load(fh)


def delta(a: float | None, b: float | None) -> float | None:
    if a is None or b is None or a == 0:
        return None
    return round((b - a) / a * 1000) / 10


def pct(x: float | None) -> str:
    if x is None:
        return DASH
    return ("+" if x > 0 else "") + f"{x}%"


def fmt_ms(x: float | None) -> str:
    if x is None:
        return DASH
    return str(round(x))


def fmt_wall(cell: Cell) -> str:
    if cell.get("base") is None and cell.get("new") is None:
        return DASH
    sd = cell.get("stddev_ms")
    return f"{fmt_ms(cell.get('base'))} → {fmt_ms(cell.get('new'))}" + (
        f" ±{round(sd)}" if sd is not None else ""
    )


def per_source(rows: Mems, metric: str) -> str:
    cells = []
    for src, m in sorted(rows.items()):
        v = m.get(metric)
        if v and v.get("base") is not None:
            cells.append(f"{src} {pct(v['delta_pct'])}")
    return " · ".join(cells) if cells else DASH


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", required=True)
    ap.add_argument("--baseline", required=True)
    ap.add_argument("--time-threshold", type=float, default=20.0)
    ap.add_argument("--cpu-threshold", type=float, default=20.0)
    ap.add_argument("--mem-threshold", type=float, default=5.0)
    ap.add_argument("--compare-json", default=None)
    args = ap.parse_args()

    res = load(args.results)
    base = load(args.baseline)
    bs = base.get("scenarios", {})
    rs = res.get("scenarios", {})

    rows: list[dict[str, Any]] = []
    warnings = []
    regressed = False

    for name in sorted(set(rs) | set(bs)):
        if name not in rs:
            regressed = True
            warnings.append(f"{name}: missing from new results")
            continue
        r = rs[name]
        b = bs.get(name)
        row = {"scenario": name, "regressed": False}
        for field, thresh, key in (
            ("wall_ms", args.time_threshold, "wall"),
            ("cpu_ms", args.cpu_threshold, "cpu"),
        ):
            bv = b.get(field) if b else None
            nv = r.get(field)
            d = delta(bv, nv)
            cell = {"base": bv, "new": nv, "delta_pct": d}
            if field == "wall_ms":
                cell["stddev_ms"] = (r.get("wall_stats") or {}).get("stddev_ms")
            row[key] = cell
            if d is not None and d > thresh:
                regressed = True
                row["regressed"] = True
                warnings.append(f"{name} {key}: +{d}%")

        bmem = (b or {}).get("mem") or {}
        rmem = r.get("mem") or {}
        mems = {}
        for src in sorted(set(bmem) | set(rmem)):
            bm = bmem.get(src) or {}
            rm = rmem.get(src) or {}
            metrics = {}
            for field in (
                "peak_heap_bytes",
                "peak_stack_bytes",
                "total_alloc_bytes",
                "alloc_count",
            ):
                bv = bm.get(field)
                nv = rm.get(field)
                if bv is None and nv is None:
                    continue
                d = delta(bv, nv)
                metrics[field] = {"base": bv, "new": nv, "delta_pct": d}
                if d is not None and d > args.mem_threshold:
                    regressed = True
                    row["regressed"] = True
                    warnings.append(f"{name} {src}.{field}: +{d}%")
            if metrics:
                mems[src] = metrics
        row["mems"] = mems
        rows.append(row)

    md = [
        "| scenario | wall ms (base → new) | Δ wall | cpu ms (base → new) | Δ cpu | Δ heap | Δ stack | Δ total | Δ count | verdict |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for row in rows:
        bad = row["regressed"]
        md.append(
            f"| {row['scenario']} "
            f"| {fmt_wall(row['wall'])} "
            f"| {pct(row['wall']['delta_pct'])} "
            f"| {fmt_ms(row['cpu']['base'])} → {fmt_ms(row['cpu']['new'])} "
            f"| {pct(row['cpu']['delta_pct'])} "
            f"| {per_source(row['mems'], 'peak_heap_bytes')} "
            f"| {per_source(row['mems'], 'peak_stack_bytes')} "
            f"| {per_source(row['mems'], 'total_alloc_bytes')} "
            f"| {per_source(row['mems'], 'alloc_count')} "
            f"| {'❌' if bad else '✅'} |"
        )

    verdict = {
        "base_sha": base.get("git_sha"),
        "sha": res.get("git_sha"),
        "regressed": regressed,
        "warnings": warnings,
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
