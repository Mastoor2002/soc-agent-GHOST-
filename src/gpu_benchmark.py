"""
STEP 9 — CPU vs GPU: how fast can GHOST scan MILLIONS of events?

WHY: Our scenarios are small (25,461 events). A real company produces millions of
log events per day. This script scales our real data up and times the detection
layer, so we can compare normal pandas (CPU) against NVIDIA RAPIDS (GPU).

The trick: RAPIDS `cudf.pandas` runs the SAME pandas code on the GPU. Nothing in
detect.py changes. Only how you launch Python does:

    python -m src.gpu_benchmark --rows 5000000                   # CPU (normal pandas)
    python -m cudf.pandas -m src.gpu_benchmark --rows 5000000    # GPU (RAPIDS)

How the big dataset is built: all 5 scenarios are copied many times. Each copy is
shifted forward in time by one day and gets its own host names (WS-07 -> WS-07-C12),
like many offices' logs side by side. The attacks are copied too, so detectors
still have real work to do. Stored as Parquet, a compact column format both
engines read fast.

Results are appended to reports/gpu_benchmark.json and printed as a table.
"""
import argparse
import json
import platform
import sys
import time
from pathlib import Path

import pandas as pd

from . import detect, scenarios

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data" / "scaled"


def engine_name() -> str:
    """'GPU (RAPIDS cudf.pandas)' when launched with python -m cudf.pandas, else CPU."""
    return "GPU (RAPIDS cudf.pandas)" if "cudf" in sys.modules else "CPU (pandas)"


def build_scaled(rows: int) -> Path:
    """Write data/scaled/events_<rows>.parquet, built from all scenarios."""
    out = DATA / f"events_{rows}.parquet"
    if out.exists():
        return out
    base = pd.concat([detect.load_logs(scenarios.path(n) / "logs.jsonl").assign(scenario=n)
                      for n in scenarios.list_scenarios()], ignore_index=True)
    copies = -(-rows // len(base))  # ceiling division
    parts = []
    for k in range(copies):
        part = base.copy()
        part["timestamp"] = part["timestamp"] + pd.Timedelta(days=k)
        part["host"] = part["host"].astype(str) + f"-C{k}"
        parts.append(part)
    big = pd.concat(parts, ignore_index=True).head(rows)
    for c in big.columns:  # Parquet needs one type per column
        if c != "timestamp":
            big[c] = big[c].astype("string")
    big["bytes_out"] = pd.to_numeric(big["bytes_out"], errors="coerce")
    big["dst_port"] = pd.to_numeric(big["dst_port"], errors="coerce")
    DATA.mkdir(parents=True, exist_ok=True)
    big.to_parquet(out, index=False)
    print(f"Built {out.relative_to(ROOT)}: {len(big):,} events from {len(base):,} real ones "
          f"x {copies} copies")
    return out


def timed(fn):
    t0 = time.perf_counter()
    result = fn()
    return result, time.perf_counter() - t0


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--rows", type=int, default=1_000_000)
    p.add_argument("--repeat", type=int, default=3, help="runs per step; the best time is kept")
    args = p.parse_args()

    path = build_scaled(args.rows)
    engine = engine_name()
    print(f"Engine: {engine}")

    # Load once, untimed warm-up (the first GPU call also starts CUDA)
    df = pd.read_parquet(path)
    detect.run_all(df.head(50_000))

    steps = {"Load Parquet": lambda: pd.read_parquet(path),
             "All 8 detectors": lambda: detect.run_all(df)}
    steps.update({f"  {d.__name__}": (lambda d=d: d(df)) for d in detect.DETECTORS})
    results = {}
    for name, fn in steps.items():
        best = min(timed(fn)[1] for _ in range(args.repeat))
        results[name.strip()] = round(best, 4)
        print(f"{name:<34} {best:8.3f} s")

    alerts = detect.run_all(df)
    row = {"engine": engine, "rows": len(df), "alerts": len(alerts), "seconds": results,
           "events_per_second": round(len(df) / results["All 8 detectors"]),
           "machine": platform.node(), "python": platform.python_version()}
    print(f"\n{len(df):,} events -> {len(alerts)} alerts | "
          f"{row['events_per_second']:,} events/second through all detectors")

    log = ROOT / "reports" / "gpu_benchmark.json"
    log.parent.mkdir(exist_ok=True)
    history = json.loads(log.read_text()) if log.exists() else []
    history.append(row)
    log.write_text(json.dumps(history, indent=2))

    # Side-by-side table once both engines have run at this size
    same = {r["engine"]: r for r in history if r["rows"] == len(df)}
    if len(same) == 2:
        cpu = next(v for k, v in same.items() if k.startswith("CPU"))
        gpu = next(v for k, v in same.items() if k.startswith("GPU"))
        print(f"\n| Step ({len(df):,} events) | CPU (s) | GPU (s) | Speed-up |\n|---|---|---|---|")
        for step in cpu["seconds"]:
            c, g = cpu["seconds"][step], gpu["seconds"].get(step)
            if g:
                print(f"| {step} | {c:.3f} | {g:.3f} | {c / g:.1f}x |")


if __name__ == "__main__":
    main()
