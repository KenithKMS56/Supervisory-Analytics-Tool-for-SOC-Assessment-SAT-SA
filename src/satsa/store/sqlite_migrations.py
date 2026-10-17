"""Numbered migrations of the operational store (`satsa.db`). See satsa.store.migrations.

Version 0 is the schema `SQLiteStore._init_tables` / `_ensure_migrations` create (the layout at
commit 47f10c9). Every later change is a numbered migration below and is documented, with its
recovery path, in docs/migrations.md. Legacy rows keep their values; columns they never had are
NULL, which the UI and reports show as "not recorded" rather than as a value.
"""

from __future__ import annotations

import sqlite3

from satsa.store.migrations import Migration


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}


def _add_column(conn: sqlite3.Connection, table: str, column: str, decl: str) -> None:
    if column not in _columns(conn, table):
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")


def _m1_evidence_coverage(conn: sqlite3.Connection) -> None:
    """Per-rule result states, unknown domain scores, entity coverage, applicability decisions."""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS rule_results (
            run_id TEXT NOT NULL REFERENCES runs (run_id),
            entity_id TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            rule_version TEXT NOT NULL,
            domain TEXT NOT NULL,
            state TEXT NOT NULL CHECK (state IN
                ('finding', 'assessed_clear', 'insufficient_evidence', 'degraded', 'not_applicable')),
            reason TEXT NOT NULL,
            missing_inputs_json TEXT NOT NULL DEFAULT '[]',
            population INTEGER,
            min_sample INTEGER,
            findings_count INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (run_id, entity_id, rule_id)
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_rule_results_entity ON rule_results (entity_id, run_id)")

    # domain_scores.score becomes nullable: a domain no rule could assess is unknown, not 0.
    # Copy-then-swap keeps every legacy row and value.
    if "rules_applicable" not in _columns(conn, "domain_scores"):
        conn.execute(
            """
            CREATE TABLE domain_scores_v1 (
                run_id TEXT NOT NULL,
                entity_id TEXT NOT NULL,
                domain TEXT NOT NULL,
                score REAL,
                rules_applicable INTEGER,
                rules_assessed INTEGER,
                coverage_status TEXT,
                PRIMARY KEY (run_id, entity_id, domain),
                FOREIGN KEY (run_id) REFERENCES runs (run_id)
            )
            """
        )
        conn.execute(
            "INSERT INTO domain_scores_v1 (run_id, entity_id, domain, score) "
            "SELECT run_id, entity_id, domain, score FROM domain_scores"
        )
        conn.execute("DROP TABLE domain_scores")
        conn.execute("ALTER TABLE domain_scores_v1 RENAME TO domain_scores")

    for column, decl in (
        ("classification_status", "TEXT"),
        ("rules_applicable", "INTEGER"),
        ("rules_assessed", "INTEGER"),
        ("rules_degraded", "INTEGER"),
        ("rules_insufficient", "INTEGER"),
        ("rules_not_applicable", "INTEGER"),
        ("coverage", "REAL"),
        ("data_request_priority", "TEXT"),
        ("missing_inputs_json", "TEXT"),
    ):
        _add_column(conn, "entity_scores", column, decl)

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS applicability_decisions (
            decision_id TEXT PRIMARY KEY,
            entity_id TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            reason TEXT NOT NULL,
            decided_by TEXT NOT NULL,
            decided_at TEXT NOT NULL,
            rule_version TEXT NOT NULL,
            expires_at TEXT,
            revoked_at TEXT,
            revoked_by TEXT,
            revoke_reason TEXT
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_applicability_entity_rule ON applicability_decisions (entity_id, rule_id)"
    )


def _m2_run_snapshots(conn: sqlite3.Connection) -> None:
    """Complete run identity: fingerprint, selection, source snapshot and full config copies."""
    for column, decl in (
        ("fingerprint", "TEXT"),
        ("selection_json", "TEXT"),
        ("source_snapshot", "INTEGER"),
        ("data_fingerprint_json", "TEXT"),
        ("environment_json", "TEXT"),
        ("published_at", "TEXT"),
    ):
        _add_column(conn, "runs", column, decl)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS run_config_snapshots (
            run_id TEXT NOT NULL REFERENCES runs (run_id),
            key TEXT NOT NULL,
            path TEXT NOT NULL,
            sha256 TEXT,
            content TEXT,
            PRIMARY KEY (run_id, key)
        )
        """
    )


OPERATIONAL_MIGRATIONS: list[Migration] = [
    Migration(1, "evidence coverage and rule results", _m1_evidence_coverage),
    Migration(2, "run snapshots and analytical fingerprint", _m2_run_snapshots),
]
