"""satsa.context.local_time_counts converts alerts to local time per entity and UTC hour, falling
back to converting alert by alert in an hour that holds an offset change. Its counts must equal
converting every alert on its own, across DST transitions and fractional offsets."""

from __future__ import annotations

from datetime import datetime, timedelta

import polars as pl
import pytest

from satsa.context import ENTITY_TZ_CTE, LOCALISED_ALERTS_CTE, local_time_counts
from satsa.store.duckdb import DuckDBStore

ZONES = {
    "E-NY": "America/New_York",  # DST, whole hours
    "E-LON": "Europe/London",
    "E-KTM": "Asia/Kathmandu",  # +05:45, no DST
    "E-KOL": "Asia/Kolkata",  # +05:30
    "E-LHI": "Australia/Lord_Howe",  # 30-minute DST shift
    "E-CHT": "Pacific/Chatham",  # +12:45 / +13:45
    "E-UTC": "UTC",
    "E-BAD": "Not/AZone",  # an unknown zone is read as UTC
    "E-NONE": None,
}

# Around 2026's transitions (UTC instants), plus ordinary days.
WINDOWS = [
    datetime(2026, 3, 8, 5, 0), datetime(2026, 11, 1, 4, 0),  # New York
    datetime(2026, 3, 29, 0, 0), datetime(2026, 10, 25, 0, 0),  # London
    datetime(2026, 4, 4, 14, 0), datetime(2026, 10, 3, 15, 0),  # Lord Howe
    datetime(2026, 4, 4, 13, 0), datetime(2026, 9, 26, 13, 0),  # Chatham
    datetime(2026, 1, 15, 0, 0), datetime(2026, 6, 30, 21, 0),
]


def _direct(store: DuckDBStore) -> dict:
    """Every alert converted on its own: what each query used to do."""
    local = "timezone(coalesce(_satsa_tz.tz, 'UTC'), a.created_at AT TIME ZONE 'UTC')"
    df = store.query(f"""
        WITH {ENTITY_TZ_CTE}
        SELECT a.entity_id, strftime(a.created_at, '%Y-%m') AS month, count(*) AS n,
               count(CASE WHEN extract(hour FROM {local}) >= 20 OR extract(hour FROM {local}) < 8 THEN 1 END),
               count(CASE WHEN dayofweek({local}) IN (0, 6) THEN 1 END),
               coalesce(any_value(_satsa_tz.tz), 'UTC')
        FROM alert a LEFT JOIN _satsa_tz ON _satsa_tz.entity_id = a.entity_id
        GROUP BY a.entity_id, month
    """)
    return {(e, m): (int(n), int(ni), int(we), str(tz)) for e, m, n, ni, we, tz in df.iter_rows()}


@pytest.fixture
def store(tmp_path):
    s = DuckDBStore(tmp_path / "data")
    for ent, tz in ZONES.items():
        s.execute("INSERT INTO entity (entity_id, timezone) VALUES (?, ?)", [ent, tz])
    rows = []
    n = 0
    for start in WINDOWS:
        # every 7 minutes 13 seconds for 30 hours, so every minute-of-hour phase is hit
        t = start - timedelta(hours=3)
        while t < start + timedelta(hours=27):
            for ent in ZONES:
                rows.append((ent, f"A{n}", t))
                n += 1
            t += timedelta(minutes=7, seconds=13)
    rows += [(None, "NOENT-1", datetime(2026, 3, 8, 6, 30)), ("E-NY", "NOTIME-1", None)]
    frame = pl.DataFrame(rows, schema={"entity_id": pl.String, "alert_id": pl.String, "created_at": pl.Datetime("us")},
                         orient="row")
    s.conn.register("_rows", frame)
    s.execute("INSERT INTO alert (entity_id, alert_id, created_at) SELECT * FROM _rows")
    s.conn.unregister("_rows")
    yield s
    s.close()


def test_per_hour_conversion_counts_equal_converting_every_alert(store):
    got = local_time_counts(store)
    assert got == _direct(store)
    # the windows really cross transitions: New York's offset changed inside the data
    assert {k[0] for k in got} >= set(ZONES) - {"E-NONE"} | {"E-NONE"}


def _local_per_alert(store: DuckDBStore) -> tuple[dict, dict]:
    """(alert_id -> lt as computed per entity and hour, alert_id -> lt converted on its own)."""
    fast = store.query(f"WITH {LOCALISED_ALERTS_CTE} SELECT alert_id, lt FROM localised")
    direct = store.query(f"""
        WITH {ENTITY_TZ_CTE}
        SELECT a.alert_id, timezone(coalesce(_satsa_tz.tz, 'UTC'), a.created_at AT TIME ZONE 'UTC') AS lt
        FROM alert a LEFT JOIN _satsa_tz ON _satsa_tz.entity_id = a.entity_id
    """)
    return dict(fast.iter_rows()), dict(direct.iter_rows())


def test_every_alert_gets_the_local_time_converting_it_alone_gives(store):
    fast, direct = _local_per_alert(store)
    assert len(fast) == len(direct) > 20000
    assert fast == direct


def test_an_hour_with_a_transition_is_converted_alert_by_alert(store):
    # Lord Howe moves from +10:30 to +11:00 at 2026-10-03 15:30 UTC, inside a UTC hour: one
    # offset for the whole hour would put one of these alerts in the wrong local hour.
    store.execute("DELETE FROM alert")
    store.execute(
        "INSERT INTO alert (entity_id, alert_id, created_at) VALUES "
        "('E-LHI', 'before', TIMESTAMP '2026-10-03 15:29:59'), ('E-LHI', 'after', TIMESTAMP '2026-10-03 15:30:00')"
    )
    local = store.query(
        "SELECT alert_id, timezone('Australia/Lord_Howe', created_at AT TIME ZONE 'UTC') AS lt FROM alert ORDER BY alert_id"
    )
    after, before = local["lt"].to_list()
    assert after - before == timedelta(minutes=30, seconds=1), "the offset changes inside the hour"
    assert (before.hour, after.hour) == (1, 2)  # 01:59:59 standard time, then 02:30:00 daylight time
    fast, direct = _local_per_alert(store)
    assert fast == direct, "the hour holding the transition is converted alert by alert"
    assert local_time_counts(store) == _direct(store)
