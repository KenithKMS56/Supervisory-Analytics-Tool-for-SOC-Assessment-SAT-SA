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


def _m3_jobs(conn: sqlite3.Connection) -> None:
    """Durable jobs (satsa.jobs): imports, assessments and demo seeding run in a worker process.

    A job survives a restart of the web app or the worker. `lease_until` and `heartbeat_at`
    say whether its worker is still alive; an expired lease is requeued or failed by the next
    worker (satsa.jobs.queue.JobQueue.recover_expired). At most one job with the same input
    fingerprint is queued or running at a time.
    """
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS jobs (
            job_id TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            state TEXT NOT NULL CHECK (state IN ('queued', 'running', 'succeeded', 'failed', 'cancelled')),
            stage TEXT,
            params_json TEXT NOT NULL DEFAULT '{}',
            input_fingerprint TEXT NOT NULL,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            started_at TEXT,
            finished_at TEXT,
            attempts INTEGER NOT NULL DEFAULT 0,
            max_attempts INTEGER NOT NULL DEFAULT 3,
            lease_owner TEXT,
            lease_until TEXT,
            heartbeat_at TEXT,
            cancel_requested INTEGER NOT NULL DEFAULT 0,
            result_json TEXT,
            error_json TEXT
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_jobs_state_created ON jobs (state, created_at)")
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_jobs_active_fingerprint ON jobs (input_fingerprint) "
        "WHERE state IN ('queued', 'running')"
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS worker_heartbeats (
            worker_id TEXT PRIMARY KEY,
            hostname TEXT,
            pid INTEGER,
            started_at TEXT NOT NULL,
            heartbeat_at TEXT NOT NULL,
            current_job_id TEXT,
            stopped_at TEXT
        )
        """
    )


def _m4_deployment_settings(conn: sqlite3.Connection) -> None:
    """Deployment identity and mode (satsa.deployment): demo or production, name, time zone,
    retention, first-run setup state. Key-value, one row per setting."""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS deployment_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            updated_by TEXT NOT NULL
        )
        """
    )


def _m5_access_controls(conn: sqlite3.Connection) -> None:
    """Service credentials, session activity (idle timeout) and entity retirement.

    - `service_credentials`: scoped, expiring, revocable machine credentials for the submission
      API (satsa.auth.service_credentials). Only a verifier (SHA-256 of a 256-bit random secret)
      is stored; the secret is shown once.
    - `sessions.last_seen_at`, `admin_sessions.last_seen_at`: when a session was last used, for the
      idle timeout. NULL on existing sessions, which then count from their creation.
    - `entity_retirements`: entities taken out of future assessments. Retiring never deletes an
      entity's submissions, runs, findings or scores (it replaces the old delete, which did).
    """
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS service_credentials (
            credential_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            verifier TEXT NOT NULL,
            scopes_json TEXT NOT NULL,
            entity_scope_json TEXT NOT NULL,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            revoked_at TEXT,
            revoked_by TEXT,
            last_used_at TEXT,
            use_count INTEGER NOT NULL DEFAULT 0
        )
        """
    )
    _add_column(conn, "sessions", "last_seen_at", "TEXT")
    _add_column(conn, "admin_sessions", "last_seen_at", "TEXT")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS entity_retirements (
            entity_id TEXT PRIMARY KEY,
            retired_at TEXT NOT NULL,
            retired_by TEXT NOT NULL,
            reason TEXT NOT NULL
        )
        """
    )


def _m6_admin_mfa(conn: sqlite3.Connection) -> None:
    """Offline TOTP second factor for Admin Portal accounts (satsa.auth.mfa): one factor per
    account, hashed one-time recovery codes, and per-session verification."""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS mfa_factors (
            username TEXT PRIMARY KEY,
            secret_b32 TEXT NOT NULL,
            created_at TEXT NOT NULL,
            confirmed_at TEXT,
            last_step INTEGER
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
            username TEXT NOT NULL,
            code_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            used_at TEXT,
            PRIMARY KEY (username, code_hash)
        )
        """
    )
    _add_column(conn, "admin_sessions", "mfa_verified_at", "TEXT")


CASE_STATES = (
    "new", "assigned", "explanation_requested", "response_received", "confirmed", "dismissed",
    "inconclusive", "corrective_action", "verification", "closed", "reopened",
)


def _immutable(conn: sqlite3.Connection, table: str) -> None:
    """Refuse UPDATE and DELETE on an append-only table, whoever the writer is."""
    for op in ("UPDATE", "DELETE"):
        conn.execute(
            f"CREATE TRIGGER IF NOT EXISTS {table}_no_{op.lower()} BEFORE {op} ON {table} "
            f"BEGIN SELECT RAISE(ABORT, '{table} rows are immutable'); END"
        )


def _m7_examiner_workflow(conn: sqlite3.Connection) -> None:
    """Supervisory cases (satsa.cases.workflow), offline response packages (satsa.cases.packages)
    and assigned blind-review tasks (satsa.cases.blind).

    - `cases`: the current state of one supervisory concern (entity x rule lineage), a projection
      of its events. At most one case per entity and rule is open; `version` detects concurrent
      edits.
    - `case_events`: the immutable history: every transition, decision, superseding decision,
      review, adjudication and note. Triggers refuse UPDATE and DELETE.
    - `case_attachments`: evidence files (content-addressed under data/case_files/), immutable.
    - `corrective_actions`: what the entity must do and how completion is verified.
    - `case_packages`: explanation requests exported for the entity and the responses imported.
    - `blind_samples`, `blind_tasks`: blind-review samples (flagged, random and control entities,
      with their seed and provenance) assigned to an examiner; the system's band is recorded at
      submission and shown only after the examiner reveals it.

    Existing review-queue dispositions (`feedback`) and blind reviews (`blind_reviews`) are kept
    as they are: they are record-level triage and earlier reviews, not cases.
    """
    states = ", ".join(f"'{s}'" for s in CASE_STATES)
    conn.execute(
        f"""
        CREATE TABLE IF NOT EXISTS cases (
            case_id TEXT PRIMARY KEY,
            entity_id TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            rule_version TEXT NOT NULL,
            finding_id TEXT NOT NULL REFERENCES findings (finding_id),
            run_id TEXT NOT NULL REFERENCES runs (run_id),
            title TEXT NOT NULL,
            state TEXT NOT NULL CHECK (state IN ({states})),
            outcome TEXT CHECK (outcome IS NULL OR outcome IN ('confirmed', 'dismissed', 'inconclusive')),
            decided_by TEXT,
            owner TEXT,
            due_date TEXT,
            previous_case_id TEXT REFERENCES cases (case_id),
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            closed_at TEXT,
            version INTEGER NOT NULL DEFAULT 1
        )
        """
    )
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_cases_one_open_per_lineage ON cases (entity_id, rule_id) "
        "WHERE state != 'closed'"
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cases_state ON cases (state, updated_at)")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS case_events (
            event_id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL REFERENCES cases (case_id),
            seq INTEGER NOT NULL,
            action TEXT NOT NULL,
            actor TEXT NOT NULL,
            actor_role TEXT NOT NULL,
            from_state TEXT,
            to_state TEXT,
            rationale TEXT,
            payload_json TEXT NOT NULL DEFAULT '{}',
            supersedes_event_id TEXT REFERENCES case_events (event_id),
            created_at TEXT NOT NULL,
            UNIQUE (case_id, seq)
        )
        """
    )
    _immutable(conn, "case_events")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS case_attachments (
            attachment_id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL REFERENCES cases (case_id),
            event_id TEXT NOT NULL REFERENCES case_events (event_id),
            filename TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            bytes INTEGER NOT NULL,
            source TEXT NOT NULL CHECK (source IN ('examiner_upload', 'response_package')),
            added_by TEXT NOT NULL,
            added_at TEXT NOT NULL
        )
        """
    )
    _immutable(conn, "case_attachments")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS corrective_actions (
            action_id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL REFERENCES cases (case_id),
            description TEXT NOT NULL,
            owner TEXT NOT NULL,
            due_date TEXT NOT NULL,
            verification_criteria TEXT NOT NULL,
            state TEXT NOT NULL CHECK (state IN ('open', 'submitted', 'verified', 'failed')),
            created_event_id TEXT NOT NULL REFERENCES case_events (event_id),
            created_at TEXT NOT NULL,
            resolved_event_id TEXT REFERENCES case_events (event_id),
            resolved_at TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS case_packages (
            package_id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL REFERENCES cases (case_id),
            request_event_id TEXT NOT NULL REFERENCES case_events (event_id),
            exported_by TEXT NOT NULL,
            exported_at TEXT NOT NULL,
            response_sha256 TEXT,
            response_event_id TEXT REFERENCES case_events (event_id),
            imported_by TEXT,
            imported_at TEXT,
            UNIQUE (request_event_id)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS blind_samples (
            sample_id TEXT PRIMARY KEY,
            run_id TEXT NOT NULL REFERENCES runs (run_id),
            seed INTEGER NOT NULL,
            flagged_n INTEGER NOT NULL,
            random_n INTEGER NOT NULL,
            control_n INTEGER NOT NULL,
            method_json TEXT NOT NULL,
            assigned_to TEXT NOT NULL,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS blind_tasks (
            task_id TEXT PRIMARY KEY,
            sample_id TEXT NOT NULL REFERENCES blind_samples (sample_id),
            position INTEGER NOT NULL,
            entity_id TEXT NOT NULL,
            run_id TEXT NOT NULL REFERENCES runs (run_id),
            sample_kind TEXT NOT NULL CHECK (sample_kind IN ('flagged', 'random', 'control')),
            provenance_json TEXT NOT NULL,
            assigned_to TEXT NOT NULL,
            created_at TEXT NOT NULL,
            examiner_concern TEXT,
            examiner_priority TEXT,
            examiner_recommendation TEXT,
            examiner_notes TEXT,
            submitted_at TEXT,
            system_risk_index REAL,
            system_risk_band TEXT,
            system_classification TEXT,
            concordance_score REAL,
            revealed_at TEXT,
            UNIQUE (sample_id, position)
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_blind_tasks_assignee ON blind_tasks (assigned_to, submitted_at)")


def _m8_context_and_peers(conn: sqlite3.Connection) -> None:
    """Entity context, recorded peer comparisons and saved portfolio views (satsa.context,
    satsa.peers.grouping, docs/analytics_context.md).

    - `maintenance_windows`: approved maintenance for an entity (all assets, or one asset) over
      inclusive local dates. Requested by one user, approved by a different examiner; only an
      approved, unrevoked window changes an assessment, and only for its own scope and dates.
    - `rule_exceptions`: a documented, time-limited exception for one entity and rule (reason,
      scope, evidence, approver, mandatory expiry). Requested and approved by different examiners.
    - `peer_comparisons`: per run and entity, the cohort actually used: members, excluded
      entities with the reason, fallback level, denominator, minimum support and whether the
      comparison is established or only exploratory.
    - `saved_views`: a user's named portfolio filter.
    - `findings.exception_id`, `rule_results.exception_id`: the exception a finding was recorded
      under (kept, shown, and left out of the score and queue while the exception is in force).

    Nothing existing is rewritten: runs recorded earlier have no peer comparison rows and show
    "not recorded"; their findings have no exception.
    """
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS maintenance_windows (
            window_id TEXT PRIMARY KEY,
            entity_id TEXT NOT NULL,
            asset_id TEXT,
            starts_on TEXT NOT NULL,
            ends_on TEXT NOT NULL,
            reason TEXT NOT NULL,
            evidence_ref TEXT NOT NULL,
            requested_by TEXT NOT NULL,
            requested_at TEXT NOT NULL,
            approved_by TEXT,
            approved_at TEXT,
            revoked_by TEXT,
            revoked_at TEXT,
            revoke_reason TEXT,
            CHECK (ends_on >= starts_on),
            CHECK (approved_by IS NULL OR approved_by <> requested_by)
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_maintenance_entity ON maintenance_windows (entity_id)")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS rule_exceptions (
            exception_id TEXT PRIMARY KEY,
            entity_id TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            scope TEXT NOT NULL,
            reason TEXT NOT NULL,
            evidence_ref TEXT NOT NULL,
            requested_by TEXT NOT NULL,
            requested_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            approved_by TEXT,
            approved_at TEXT,
            revoked_by TEXT,
            revoked_at TEXT,
            revoke_reason TEXT,
            CHECK (approved_by IS NULL OR approved_by <> requested_by)
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_rule_exceptions_entity ON rule_exceptions (entity_id, rule_id)")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS peer_comparisons (
            run_id TEXT NOT NULL REFERENCES runs (run_id),
            entity_id TEXT NOT NULL,
            cohort_label TEXT NOT NULL,
            attributes_json TEXT NOT NULL,
            fallback_level INTEGER NOT NULL,
            member_ids_json TEXT NOT NULL,
            excluded_json TEXT NOT NULL,
            denominator INTEGER NOT NULL,
            min_support INTEGER NOT NULL,
            strength TEXT NOT NULL CHECK (strength IN ('established', 'exploratory', 'none')),
            reason TEXT NOT NULL,
            PRIMARY KEY (run_id, entity_id)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS saved_views (
            view_id TEXT PRIMARY KEY,
            owner TEXT NOT NULL,
            name TEXT NOT NULL,
            query_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE (owner, name)
        )
        """
    )
    _add_column(conn, "findings", "exception_id", "TEXT")
    # Provider-level leads (satsa.rules.systemic): affected / assessable / group size, the
    # comparison rate and the bound. Earlier rows keep NULL ("not recorded").
    for column, decl in (
        ("assessable_count", "INTEGER"), ("group_size", "INTEGER"), ("comparison_affected", "INTEGER"),
        ("comparison_assessable", "INTEGER"), ("p_value", "REAL"), ("q_value", "REAL"),
    ):
        _add_column(conn, "systemic_findings", column, decl)
    _add_column(conn, "rule_results", "exception_id", "TEXT")


def _m9_pilot_evaluation(conn: sqlite3.Connection) -> None:
    """Independent validation tooling (satsa.validate.pilot, docs/shadow_pilot_runbook.md).

    - `blind_samples.replica_of`: a sample that repeats another one's entities for a second,
      independent examiner (in its own order), so two blinded labels exist per entity.
    - `blind_tasks.opened_at`: when the examiner first opened the task; with `submitted_at` it
      gives the reviewer's time.
    - `pilot_protocols`: a frozen evaluation protocol: the configuration hash the thresholds were
      frozen at, the seeded calibration / held-out split of entities and the review budget.
    - `pilot_adjudications`: a third examiner's label for an entity two reviewers disagreed on.

    Nothing existing changes: earlier samples have no replica, earlier tasks no opening time
    (their review time is "not recorded").
    """
    _add_column(conn, "blind_samples", "replica_of", "TEXT REFERENCES blind_samples (sample_id)")
    _add_column(conn, "blind_tasks", "opened_at", "TEXT")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS pilot_protocols (
            protocol_id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            frozen_run_id TEXT NOT NULL REFERENCES runs (run_id),
            frozen_config_hash TEXT NOT NULL,
            seed INTEGER NOT NULL,
            calibration_fraction REAL NOT NULL CHECK (calibration_fraction >= 0 AND calibration_fraction < 1),
            budget INTEGER NOT NULL CHECK (budget > 0),
            split_json TEXT NOT NULL,
            notes TEXT,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS pilot_adjudications (
            adjudication_id TEXT PRIMARY KEY,
            protocol_id TEXT NOT NULL REFERENCES pilot_protocols (protocol_id),
            run_id TEXT NOT NULL REFERENCES runs (run_id),
            entity_id TEXT NOT NULL,
            label TEXT NOT NULL CHECK (label IN ('Low', 'Moderate', 'Elevated', 'Critical')),
            rationale TEXT NOT NULL,
            adjudicated_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE (protocol_id, run_id, entity_id)
        )
        """
    )


def _m10_rule_pack_versions(conn: sqlite3.Connection) -> None:
    """Rule-configuration lifecycle (satsa.rules.lifecycle, docs/rule_governance.md).

    `rule_pack_versions`: every rule configuration that was proposed, with its full text and
    SHA-256, the version it was based on, what changed, and its state: draft -> approved ->
    active -> retired, or rejected. Approval is by someone other than the author (a CHECK, as
    well as the code). At most one version is active (a partial unique index).

    Nothing existing changes. The configuration in force when the lifecycle is first used is
    recorded as version 1, "adopted"; every run keeps its own full configuration snapshot as
    before (run_config_snapshots).
    """
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS rule_pack_versions (
            version_no INTEGER PRIMARY KEY,
            state TEXT NOT NULL CHECK (state IN ('draft', 'approved', 'active', 'retired', 'rejected')),
            rules_yaml TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            base_version_no INTEGER REFERENCES rule_pack_versions (version_no),
            changes_json TEXT NOT NULL DEFAULT '[]',
            source TEXT NOT NULL,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            approved_by TEXT,
            approved_at TEXT,
            approval_note TEXT,
            activated_by TEXT,
            activated_at TEXT,
            retired_at TEXT,
            rejected_by TEXT,
            rejected_at TEXT,
            note TEXT,
            CHECK (approved_by IS NULL OR approved_by <> created_by)
        )
        """
    )
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_rule_pack_one_active ON rule_pack_versions (state) "
        "WHERE state = 'active'"
    )


OPERATIONAL_MIGRATIONS: list[Migration] = [
    Migration(1, "evidence coverage and rule results", _m1_evidence_coverage),
    Migration(2, "run snapshots and analytical fingerprint", _m2_run_snapshots),
    Migration(3, "durable jobs and worker heartbeats", _m3_jobs),
    Migration(4, "deployment settings and mode", _m4_deployment_settings),
    Migration(5, "service credentials, session idle timeout, entity retirement", _m5_access_controls),
    Migration(6, "administrator MFA", _m6_admin_mfa),
    Migration(7, "supervisory cases, case events, response packages, blind tasks", _m7_examiner_workflow),
    Migration(8, "maintenance windows, rule exceptions, peer comparisons, saved views", _m8_context_and_peers),
    Migration(9, "pilot evaluation: replicate reviews, review times, protocols, adjudications", _m9_pilot_evaluation),
    Migration(10, "rule configuration lifecycle", _m10_rule_pack_versions),
]
