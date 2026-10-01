"""Profile the ingest stage on a benchmark-sized submission.

    uv run python scripts/profile_ingest.py --entities 10 --alerts 50000 [--top 25] [--no-profile]

Generates the same canonical CSV submission as scripts/benchmark_scale.py, ingests it into a
fresh store and prints the wall time, the process's peak resident memory and (unless
--no-profile) the cProfile functions with the most cumulative and own time. cProfile slows
Python-heavy code down, so take timings from a --no-profile run.
"""

from __future__ import annotations

import argparse
import cProfile
import importlib.util
import io
import os
import pstats
import shutil
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

_spec = importlib.util.spec_from_file_location("benchmark_scale", REPO / "scripts" / "benchmark_scale.py")
assert _spec and _spec.loader
bench = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bench)


def main() -> int:
    parser = argparse.ArgumentParser(description="Profile SAT-SA ingest")
    parser.add_argument("--entities", type=int, default=10)
    parser.add_argument("--alerts", type=int, default=50000, help="alerts per entity")
    parser.add_argument("--top", type=int, default=25)
    parser.add_argument("--no-profile", action="store_true", help="time only, without cProfile")
    parser.add_argument("--workdir", default=None)
    args = parser.parse_args()

    workspace = Path(tempfile.mkdtemp(prefix="satsa_profile_", dir=args.workdir))
    try:
        shutil.copytree(REPO / "config", workspace / "config")
        counts = bench.generate(workspace / "csv", args.entities, args.alerts)
        print(f"submission: {args.entities}x{args.alerts}, {counts['alert']:,} alerts, {sum(counts.values()):,} rows")
        os.chdir(workspace)

        from satsa.ingest.pipeline import IngestionPipeline
        from satsa.store.duckdb import DuckDBStore
        from satsa.store.sqlite import SQLiteStore

        duck, sql = DuckDBStore("data"), SQLiteStore("data/satsa.db")
        pipeline = IngestionPipeline(duck, sql)
        profiler = None if args.no_profile else cProfile.Profile()
        started = time.perf_counter()
        if profiler:
            profiler.enable()
        result = pipeline.ingest_directory(workspace / "csv")
        if profiler:
            profiler.disable()
        seconds = time.perf_counter() - started
        duck.close()
        sql.close()
        print(f"status: {result['status']}, dq issues: {result['dq_issues']}")
        print(f"ingest seconds: {seconds:.1f}{' (under cProfile)' if profiler else ''}")
        print(f"peak resident memory: {bench.peak_memory_mb():.0f} MiB")
        if profiler:
            for key in ("cumulative", "tottime"):
                out = io.StringIO()
                pstats.Stats(profiler, stream=out).strip_dirs().sort_stats(key).print_stats(args.top)
                print(f"\n--- top {args.top} by {key} ---")
                print("\n".join(line for line in out.getvalue().splitlines() if line.strip())[:6000])
    finally:
        os.chdir(REPO)
        shutil.rmtree(workspace, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
