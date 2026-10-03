"""Three naive baselines, to compare the 20-rule engine against something simpler.

Each baseline is what a reviewer might write in an afternoon: one fixed threshold on one
metric, no peer cohort, no minimum sample, no exceptions. Each is mapped to the engine rule
that tests the same idea, so the two can be scored on the same ground truth:

* ``fast_closure``  -> EG01: share of human-closed High/Critical alerts closed within
  10 minutes above 10%.
* ``short_comment`` -> EG02: share of human closures whose closure comment is under 25
  characters above 10%.
* ``no_escalation`` -> EG03: any Critical alert, whatever its disposition, with no
  escalation record.

They read the same ingested store the engine reads. If a baseline ties or beats the engine on
the independent data, the report says so.
"""

from __future__ import annotations

from typing import Any

from satsa.store.duckdb import DuckDBStore

BASELINES: dict[str, dict[str, Any]] = {
    "fast_closure": {"maps_to": "EG01", "description": "human High/Critical closed within 10 min > 10%"},
    "short_comment": {"maps_to": "EG02", "description": "human closures with comment < 25 chars > 10%"},
    "no_escalation": {"maps_to": "EG03", "description": "any Critical alert without an escalation"},
}


def _flagged(store: DuckDBStore, sql: str) -> set[str]:
    return {str(r["entity_id"]) for r in store.query(sql).iter_rows(named=True)}


def run_baselines(store: DuckDBStore) -> dict[str, set[str]]:
    """Entities each baseline flags, from the store as loaded."""
    fast = _flagged(store, """
        SELECT entity_id FROM alert
        WHERE closed_by_type = 'human' AND severity_final IN ('high', 'critical') AND closed_at IS NOT NULL
        GROUP BY entity_id
        HAVING avg(CASE WHEN date_diff('second', created_at, closed_at) BETWEEN 0 AND 600 THEN 1.0 ELSE 0.0 END) > 0.10
    """)
    short = _flagged(store, """
        SELECT a.entity_id FROM alert a
        JOIN closure c ON c.entity_id = a.entity_id AND c.ref_id = a.alert_id
        WHERE a.closed_by_type = 'human'
        GROUP BY a.entity_id
        HAVING avg(CASE WHEN coalesce(c.comment_len, 0) < 25 THEN 1.0 ELSE 0.0 END) > 0.10
    """)
    no_esc = _flagged(store, """
        SELECT DISTINCT a.entity_id FROM alert a
        WHERE a.severity_final = 'critical'
          AND NOT EXISTS (SELECT 1 FROM escalation e WHERE e.entity_id = a.entity_id AND e.ref_id = a.alert_id)
    """)
    return {"fast_closure": fast, "short_comment": short, "no_escalation": no_esc}
