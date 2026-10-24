"""A small, fully known deployment for the examiner-workflow tests (tests/test_cases*.py).

Runs, findings and rule results are written directly, so every reassessment outcome is set by
the test rather than by whatever the synthetic generator happens to produce. The deployment
lives in its own directory (`data/satsa.db` relative to it), as the application expects.
"""

from __future__ import annotations

import json
from pathlib import Path

from satsa.store.sqlite import SQLiteStore

ENTITY, RULE = "CSE-01", "NS03"
PASSPHRASE = "Examiner-Two#2026x"
Q1 = ("2026-01-01T00:00:00+00:00", "2026-04-01T00:00:00+00:00")
Q2 = ("2026-04-01T00:00:00+00:00", "2026-07-01T00:00:00+00:00")


def make_store(root: Path) -> SQLiteStore:
    (root / "data").mkdir(parents=True, exist_ok=True)
    store = SQLiteStore(root / "data" / "satsa.db")
    for name in ("examiner2", "examiner3"):
        if not store.conn.execute("SELECT 1 FROM identities WHERE username = ?", (name,)).fetchone():
            store.create_user(name, "examiner", PASSPHRASE)
    return store


def add_run(store: SQLiteStore, run_id: str, created_at: str, window: tuple[str, str] | None = Q1,
            period: str = "2026-Q1", rules_sha: str = "rules-v1", peers_sha: str = "peers-v1") -> None:
    selection = ({"mode": "window", "start": window[0], "end_exclusive": window[1]} if window
                 else {"mode": "all_submitted", "start": None, "end_exclusive": None})
    with store.transaction():
        store.conn.execute(
            "INSERT INTO runs (run_id, period, created_at, config_hash, code_version, status, manifest_json, "
            "selection_json) VALUES (?, ?, ?, 'cfg', 'test', 'completed', '{}', ?)",
            (run_id, period, created_at, json.dumps(selection)),
        )
        for key, sha in (("rules", rules_sha), ("peers", peers_sha)):
            store.conn.execute(
                "INSERT INTO run_config_snapshots (run_id, key, path, sha256, content) VALUES (?, ?, ?, ?, '')",
                (run_id, key, f"config/{key}.yaml", sha),
            )


def add_result(store: SQLiteStore, run_id: str, state: str, version: str = "1.0", population: int = 400,
               reason: str = "assessed", risk_index: float = 20.0, band: str = "Low Supervisory Concern",
               classification: str = "assessable", coverage: float = 1.0) -> None:
    with store.transaction():
        store.conn.execute(
            "INSERT INTO rule_results (run_id, entity_id, rule_id, rule_version, domain, state, reason, "
            "population, min_sample, findings_count) VALUES (?, ?, ?, ?, 'Coverage', ?, ?, ?, 30, ?)",
            (run_id, ENTITY, RULE, version, state, reason, population, 1 if state == "finding" else 0),
        )
        store.conn.execute(
            "INSERT OR REPLACE INTO entity_scores (run_id, entity_id, risk_index, risk_band, "
            "distinct_rules_triggered, classification_status, coverage) VALUES (?, ?, ?, ?, 1, ?, ?)",
            (run_id, ENTITY, risk_index, band, classification, coverage),
        )


def add_finding(store: SQLiteStore, run_id: str, finding_id: str, score: float = 72.0, version: str = "1.0",
                records: tuple[str, ...] = ("A-1", "A-2", "A-3"), peer_count: int = 6) -> None:
    with store.transaction():
        store.conn.execute(
            "INSERT INTO findings (finding_id, run_id, entity_id, rule_id, rule_version, domain, level, score, "
            "confidence, severity, title, rationale, peer_comparison_json, examiner_check, created_at) "
            "VALUES (?, ?, ?, ?, ?, 'Coverage', 'L2', ?, 0.8, 'high', 'Off-shift coverage gap', "
            "'Alerts outside staffed hours wait far longer than peers.', ?, 'Check the rota.', ?)",
            (finding_id, run_id, ENTITY, RULE, version, score, json.dumps({"peer_count": peer_count}),
             "2026-04-02T00:00:00+00:00"),
        )
        for rec in records:
            store.conn.execute(
                "INSERT INTO finding_evidences (finding_id, record_type, record_id, details_json) "
                "VALUES (?, 'alert', ?, '{}')",
                (finding_id, rec),
            )


def seed_q1_concern(store: SQLiteStore) -> str:
    """Run Q1 found the concern. Returns the finding id."""
    add_run(store, "RUN-Q1", "2026-04-02T00:00:00+00:00")
    add_result(store, "RUN-Q1", "finding", risk_index=71.0, band="High Supervisory Concern")
    add_finding(store, "RUN-Q1", "FND-Q1-NS03")
    return "FND-Q1-NS03"
