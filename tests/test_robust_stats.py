"""RobustStats.quantile_cont reproduces DuckDB's quantile_cont bit for bit.

EG01 computes its peer baseline (the cohort's 5th-percentile close time) in Python from close times
read once per assessment, instead of one DuckDB query over the cohort per entity. Its findings are
unchanged only if the two agree exactly; a DuckDB upgrade that changed the interpolation would
fail here.
"""

from __future__ import annotations

import random

import duckdb
import polars as pl
import pytest

from satsa.peers.robust_stats import RobustStats


def _samples() -> list[list[float]]:
    rng = random.Random(20261020)
    out: list[list[float]] = []
    for n in (1, 2, 3, 4, 5, 10, 21, 100, 997, 5000):
        out.append([rng.uniform(-1e6, 1e6) for _ in range(n)])
        out.append([float(rng.randint(0, 86400 * 30)) for _ in range(n)])  # whole seconds
        out.append([rng.randint(0, 10**9) / 1e6 for _ in range(n)])  # microsecond epochs
        out.append([rng.expovariate(1 / 900) for _ in range(n)])
        out.append([float(rng.randint(0, 5)) for _ in range(n)])  # many ties
    return out


@pytest.mark.parametrize("q", [0.05, 0.25, 0.5, 0.95])
def test_quantile_cont_is_duckdbs_bit_for_bit(q):
    con = duckdb.connect()
    con.execute("PRAGMA threads=1")
    try:
        for values in _samples():
            con.register("t", pl.DataFrame({"x": values}, schema={"x": pl.Float64}))
            expected = con.execute(f"SELECT quantile_cont(x, {q}) FROM t").fetchone()[0]
            con.unregister("t")
            assert RobustStats.quantile_cont(values, q) == expected, (len(values), q)
            assert RobustStats.quantile_cont_sorted(pl.Series(values, dtype=pl.Float64).sort(), q) == expected
    finally:
        con.close()


def test_no_values_has_no_quantile():
    assert RobustStats.quantile_cont([], 0.05) is None
    assert RobustStats.quantile_cont_sorted(pl.Series([], dtype=pl.Float64), 0.05) is None
