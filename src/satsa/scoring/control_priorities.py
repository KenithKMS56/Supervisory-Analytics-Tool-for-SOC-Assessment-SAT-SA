"""Portfolio-level prioritisation of controls and processes for manual review.

The problem statement asks the tool to "prioritise entities, controls, processes and alert
samples". Entities are ranked by risk index and alert samples by the review queue; this module
ranks the other two from the same stored results of one run:

* **controls**: each rule tests one control. A control is ranked by how many entities failed it,
  the highest severity among those failures and the summed finding score; the number of entities
  for which it could not be assessed (table never submitted) is reported next to it, because an
  untested control is itself something to follow up.
* **processes**: the eight capability domains. A process is ranked by how many entities score at
  or above `concern_threshold` in it, then by its median domain score across the portfolio; the
  exploratory anomaly signals in that domain are counted as supporting leads.

Nothing is recomputed from raw data, so the ranking always agrees with the findings shown.
"""

from __future__ import annotations

import sqlite3
from typing import Any

from satsa.peers.robust_stats import RobustStats

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def rank_controls(conn: sqlite3.Connection, run_id: str) -> list[dict[str, Any]]:
    """Rules failed in this run, most widespread and severe first."""
    rows = conn.execute(
        """
        SELECT rule_id, domain, entity_id, severity, score, title
        FROM findings WHERE run_id = ?
        """,
        (run_id,),
    ).fetchall()
    controls: dict[str, dict[str, Any]] = {}
    for r in rows:
        c = controls.setdefault(
            r["rule_id"],
            {
                "rule_id": r["rule_id"],
                "domain": r["domain"],
                "title": r["title"],
                "entities": set(),
                "max_severity": "low",
                "total_score": 0.0,
            },
        )
        c["entities"].add(r["entity_id"])
        c["total_score"] += float(r["score"] or 0.0)
        if SEVERITY_RANK.get(r["severity"], 0) > SEVERITY_RANK.get(c["max_severity"], 0):
            c["max_severity"] = r["severity"]

    not_assessed: dict[str, int] = {}
    for r in conn.execute(
        "SELECT issue_id FROM dq_issues WHERE check_name = 'rule_not_assessed'"
    ).fetchall():
        rule_id = str(r["issue_id"]).rsplit("-", 1)[-1]
        not_assessed[rule_id] = not_assessed.get(rule_id, 0) + 1

    ranked: list[dict[str, Any]] = []
    for c in controls.values():
        ranked.append(
            {
                "rule_id": c["rule_id"],
                "domain": c["domain"],
                "title": c["title"],
                "entities_failing": len(c["entities"]),
                "entity_ids": sorted(c["entities"]),
                "max_severity": c["max_severity"],
                "total_score": round(c["total_score"], 1),
                "entities_not_assessed": not_assessed.get(c["rule_id"], 0),
            }
        )
    ranked.sort(
        key=lambda c: (
            -c["entities_failing"],
            -SEVERITY_RANK.get(c["max_severity"], 0),
            -c["total_score"],
            c["rule_id"],
        )
    )
    return ranked


def rank_processes(
    conn: sqlite3.Connection, run_id: str, concern_threshold: float = 50.0
) -> list[dict[str, Any]]:
    """Capability domains, the ones most entities are weak in first."""
    scores: dict[str, list[tuple[str, float]]] = {}
    for r in conn.execute(
        "SELECT domain, entity_id, score FROM domain_scores WHERE run_id = ?", (run_id,)
    ).fetchall():
        scores.setdefault(r["domain"], []).append((r["entity_id"], float(r["score"] or 0.0)))

    leads: dict[str, int] = {}
    try:
        for r in conn.execute(
            "SELECT domain, count(*) AS n FROM anomaly_signals WHERE run_id = ? GROUP BY domain", (run_id,)
        ).fetchall():
            leads[r["domain"]] = int(r["n"])
    except sqlite3.OperationalError:
        pass  # database created before the anomaly scan existed

    ranked: list[dict[str, Any]] = []
    for domain, entries in scores.items():
        weak = sorted((e for e in entries if e[1] >= concern_threshold), key=lambda e: (-e[1], e[0]))
        ranked.append(
            {
                "domain": domain,
                "entities_of_concern": len(weak),
                "entity_ids": [e[0] for e in weak],
                "median_score": round(RobustStats.median([s for _, s in entries]), 1),
                "max_score": round(max(s for _, s in entries), 1),
                "anomaly_leads": leads.get(domain, 0),
            }
        )
    ranked.sort(key=lambda p: (-p["entities_of_concern"], -p["median_score"], -p["max_score"], p["domain"]))
    return ranked
