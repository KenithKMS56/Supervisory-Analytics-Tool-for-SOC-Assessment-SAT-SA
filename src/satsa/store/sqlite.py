"""SQLite store for operational state, findings, audit trail, and examiner feedback."""

import datetime as _dt
import hashlib
import json
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from satsa.models.outputs import (
    AuditLogEntry,
    DomainScore,
    DQIssue,
    EntityScore,
    ExaminerFeedback,
    Finding,
    FindingEvidence,
    ReviewQueueItem,
    Run,
)


def utc_now_iso() -> str:
    """Current UTC time as ISO-8601 with FIXED microsecond precision.

    datetime.isoformat() omits the fractional part when microsecond == 0, so
    two timestamps from the same second could differ in length
    ("...:05+00:00" vs "...:05.000123+00:00") and compare wrongly as strings.
    Every timestamp this store writes or compares uses this fixed format.
    """
    return _dt.datetime.now(_dt.UTC).isoformat(timespec="microseconds")


def parse_utc(ts: str) -> _dt.datetime:
    """Parse a stored ISO timestamp (any precision; naive treated as UTC) to aware UTC."""
    parsed = _dt.datetime.fromisoformat(ts)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=_dt.UTC)
    return parsed.astimezone(_dt.UTC)


# --- Audit hash chain -----------------------------------------------------------
#
# Each audit row stores prev_hash (the previous row's curr_hash) and curr_hash,
# a hash over the row's own fields plus prev_hash. Rows record which algorithm
# produced their hash (hash_alg):
#   * "sha256"   -- legacy rows: sha256(payload)
#   * "sha3_256" -- current rows: sha3_256("sha3_256:" + payload)
# The algorithm tag is part of the hashed input for SHA3 rows, so relabeling a
# row's hash_alg column is detected rather than silently switching algorithms.
# Verification recomputes every row with ITS OWN recorded algorithm, so a chain
# mixing legacy and current rows verifies end to end.
#
# What the chain does NOT detect (see DECISIONS.md ADR-005): someone with write
# access recomputing the whole chain from scratch, and deletion of the newest
# rows (tail truncation) -- use `satsa audit head` to record an external
# checkpoint and `satsa audit verify --checkpoint-*` to compare against it.

# Upper bound on events returned by one activity-feed query.
LIVE_EVENTS_MAX_LIMIT = 200

HASH_ALG_LEGACY = "sha256"
HASH_ALG_CURRENT = "sha3_256"


def compute_chain_hash(alg: str, payload: str) -> str:
    """Hash an audit-row payload with the named algorithm."""
    if alg == HASH_ALG_LEGACY:
        return hashlib.sha256(payload.encode()).hexdigest()
    if alg == HASH_ALG_CURRENT:
        return hashlib.sha3_256(f"{HASH_ALG_CURRENT}:{payload}".encode()).hexdigest()
    raise ValueError(f"Unknown audit hash algorithm: {alg!r}")


# Audit appends must be serialized: the web app opens a new connection per
# request, so two concurrent appends could otherwise read the same previous hash
# and fork the chain (a false tamper report later). A process-wide lock per
# database file serializes threads (including threads sharing one connection);
# BEGIN IMMEDIATE takes SQLite's write lock before the previous hash is read,
# serializing writers in other processes too.
_CHAIN_LOCKS: dict[str, threading.Lock] = {}
_CHAIN_LOCKS_GUARD = threading.Lock()


def _chain_lock_for(db_path: Path) -> threading.Lock:
    key = str(db_path.resolve())
    with _CHAIN_LOCKS_GUARD:
        return _CHAIN_LOCKS.setdefault(key, threading.Lock())


@dataclass(frozen=True)
class ChainVerification:
    ok: bool
    message: str
    entries: int
    bad_row: int | None = None  # 1-based position (rowid order) of the first bad row
    bad_log_id: str | None = None


@dataclass(frozen=True)
class AuditHead:
    count: int
    head_hash: str
    hash_alg: str | None


class SQLiteStore:
    """Manages SQLite tables for runs, findings, review queue, feedback, and audit logs."""

    GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"

    def __init__(self, db_path: Path | str = "data/satsa.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(
            str(self.db_path),
            check_same_thread=False,
            timeout=30.0,
            isolation_level=None,
        )
        self.conn.row_factory = sqlite3.Row
        # Best effort: e.g. WAL is unavailable on some network filesystems.
        with suppress(sqlite3.Error):
            self.conn.execute("PRAGMA journal_mode=WAL;")
            self.conn.execute("PRAGMA busy_timeout=30000;")
            self.conn.execute("PRAGMA synchronous=NORMAL;")

        # Fast schema check: only run DDL migrations/seeding if schema is missing or incomplete
        cur = self.conn.cursor()
        cur.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='entities' LIMIT 1")
        needs_init = cur.fetchone() is None
        if not needs_init:
            cur.execute("PRAGMA table_info(identities)")
            cols = {row[1] for row in cur.fetchall()}
            if "is_admin_user" not in cols or "org_id" not in cols:
                needs_init = True

        if needs_init:
            self._init_tables()
            self.seed_default_identities()
        self._ensure_migrations()

    @contextmanager
    def _serialized_chain_write(self) -> Iterator[sqlite3.Cursor]:
        """Hold the chain lock and an IMMEDIATE transaction around read-prev + insert."""
        with _chain_lock_for(self.db_path):
            cur = self.conn.cursor()
            cur.execute("BEGIN IMMEDIATE")
            try:
                yield cur
            except BaseException:
                cur.execute("ROLLBACK")
                raise
            cur.execute("COMMIT")

    def _ensure_migrations(self) -> None:
        """Idempotent schema upgrades applied on every open (cheap: IF NOT EXISTS / column checks)."""
        tables = {
            r[0] for r in self.conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        with self.conn:
            for table in ("audit_log", "admin_audit_log"):
                if table not in tables:
                    continue
                cols = {r[1] for r in self.conn.execute(f"PRAGMA table_info({table})")}
                if "hash_alg" not in cols:
                    # Every pre-existing row was hashed with plain SHA-256.
                    self.conn.execute(
                        f"ALTER TABLE {table} ADD COLUMN hash_alg TEXT NOT NULL DEFAULT 'sha256'"
                    )
                # Login-lockout lookups filter audit rows by (actor, action).
                self.conn.execute(
                    f"CREATE INDEX IF NOT EXISTS idx_{table}_actor_action ON {table} (actor, action)"
                )
            # One JSON batch submission per (entity, period): see claim_batch_submission.
            self.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS batch_submissions (
                    entity_id TEXT NOT NULL,
                    period TEXT NOT NULL,
                    submitted_at TIMESTAMP NOT NULL,
                    actor TEXT NOT NULL,
                    PRIMARY KEY (entity_id, period)
                )
                """
            )
            # Shadow-pilot evaluations (see satsa.validate.harness.ShadowPilotAdapter),
            # kept so the /shadow-pilot page and the validation report can show them.
            self.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS shadow_pilot_results (
                    result_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    created_at TIMESTAMP NOT NULL,
                    actor TEXT NOT NULL,
                    source_name TEXT NOT NULL,
                    result_json TEXT NOT NULL
                )
                """
            )
        if "identities" in tables:
            self._migrate_supervisor_to_analyst()

    def _migrate_supervisor_to_analyst(self) -> None:
        """Rename the legacy `supervisor` role to `analyst` (SAT-SA's technical operator).

        The untouched demo account (username `supervisor`, default passphrase) also
        becomes username `analyst` with the new default passphrase; an account whose
        passphrase was rotated keeps its username. Audit rows are left as they are:
        rewriting historical actors would break the hash chain.
        """
        from satsa.auth.identities import generate_salt, hash_passphrase, verify_passphrase

        cur = self.conn.cursor()
        # Checked before the role rewrite below, so the PBKDF2 verify runs at most once.
        cur.execute(
            "SELECT pass_hash, pass_salt FROM identities WHERE username = 'supervisor' AND role = 'supervisor'"
        )
        demo = cur.fetchone()
        cur.execute("SELECT 1 FROM identities WHERE username = 'analyst'")
        analyst_exists = cur.fetchone() is not None
        with self.conn:
            if (
                demo is not None
                and not analyst_exists
                and verify_passphrase("ChangeMe-Supervisor#2026", demo["pass_salt"], demo["pass_hash"])
            ):
                salt = generate_salt()
                self.conn.execute("DELETE FROM sessions WHERE username = 'supervisor'")
                self.conn.execute("DELETE FROM admin_sessions WHERE username = 'supervisor'")
                self.conn.execute(
                    "UPDATE identities SET username = 'analyst', pass_hash = ?, pass_salt = ? "
                    "WHERE username = 'supervisor'",
                    (hash_passphrase("ChangeMe-Analyst#2026", salt), salt.hex()),
                )
            self.conn.execute(
                "UPDATE identities SET role = 'analyst' WHERE role IN ('supervisor', 'NCIIPC_SUPERVISOR')"
            )
            self.conn.execute(
                "UPDATE identities SET role = 'NCIIPC Analyst' WHERE role = 'NCIIPC Supervisor'"
            )

    def _init_tables(self) -> None:
        """Create tables if not existing."""
        with self.conn:
            self.conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS entities (
                    entity_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    sector TEXT NOT NULL,
                    size_band TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS runs (
                    run_id TEXT PRIMARY KEY,
                    period TEXT NOT NULL,
                    created_at TIMESTAMP NOT NULL,
                    config_hash TEXT NOT NULL,
                    code_version TEXT NOT NULL,
                    status TEXT NOT NULL,
                    manifest_json TEXT
                );

                CREATE TABLE IF NOT EXISTS metric_values (
                    run_id TEXT NOT NULL,
                    entity_id TEXT NOT NULL,
                    period TEXT NOT NULL,
                    metric TEXT NOT NULL,
                    value REAL NOT NULL,
                    n INTEGER NOT NULL,
                    PRIMARY KEY (run_id, entity_id, period, metric)
                );

                CREATE TABLE IF NOT EXISTS findings (
                    finding_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    entity_id TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    rule_version TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    level TEXT NOT NULL,
                    score REAL NOT NULL,
                    confidence REAL NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    rationale TEXT NOT NULL,
                    peer_comparison_json TEXT,
                    limitations TEXT,
                    benign_explanations_json TEXT,
                    examiner_check TEXT NOT NULL,
                    created_at TIMESTAMP NOT NULL,
                    FOREIGN KEY (run_id) REFERENCES runs (run_id)
                );

                CREATE TABLE IF NOT EXISTS finding_evidences (
                    finding_id TEXT NOT NULL,
                    record_type TEXT NOT NULL,
                    record_id TEXT NOT NULL,
                    details_json TEXT,
                    PRIMARY KEY (finding_id, record_type, record_id),
                    FOREIGN KEY (finding_id) REFERENCES findings (finding_id)
                );

                CREATE TABLE IF NOT EXISTS domain_scores (
                    run_id TEXT NOT NULL,
                    entity_id TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    score REAL NOT NULL,
                    PRIMARY KEY (run_id, entity_id, domain),
                    FOREIGN KEY (run_id) REFERENCES runs (run_id)
                );

                CREATE TABLE IF NOT EXISTS entity_scores (
                    run_id TEXT NOT NULL,
                    entity_id TEXT NOT NULL,
                    risk_index REAL NOT NULL,
                    risk_band TEXT NOT NULL,
                    distinct_rules_triggered INTEGER NOT NULL,
                    domain_scores_json TEXT,
                    PRIMARY KEY (run_id, entity_id),
                    FOREIGN KEY (run_id) REFERENCES runs (run_id)
                );

                CREATE TABLE IF NOT EXISTS review_queue (
                    queue_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    entity_id TEXT NOT NULL,
                    record_type TEXT NOT NULL,
                    record_id TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    score REAL NOT NULL,
                    selection_reason TEXT NOT NULL,
                    is_random INTEGER NOT NULL,
                    examiner_status TEXT NOT NULL DEFAULT 'pending',
                    examiner_note TEXT,
                    FOREIGN KEY (run_id) REFERENCES runs (run_id)
                );

                CREATE TABLE IF NOT EXISTS feedback (
                    feedback_id TEXT PRIMARY KEY,
                    queue_id TEXT NOT NULL,
                    finding_id TEXT,
                    examiner_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    notes TEXT,
                    created_at TIMESTAMP NOT NULL,
                    FOREIGN KEY (queue_id) REFERENCES review_queue (queue_id)
                );

                CREATE TABLE IF NOT EXISTS dq_issues (
                    issue_id TEXT PRIMARY KEY,
                    batch_id TEXT,
                    entity_id TEXT NOT NULL,
                    check_name TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    count INTEGER NOT NULL,
                    sample_records_json TEXT,
                    details TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS audit_log (
                    log_id TEXT PRIMARY KEY,
                    ts TIMESTAMP NOT NULL,
                    action TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    details_json TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    curr_hash TEXT NOT NULL,
                    hash_alg TEXT NOT NULL DEFAULT 'sha256'
                );

                CREATE TABLE IF NOT EXISTS identities (
                    username TEXT PRIMARY KEY,
                    role TEXT NOT NULL,
                    pass_hash TEXT NOT NULL,
                    pass_salt TEXT NOT NULL,
                    is_blocked INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS sessions (
                    session_hash TEXT PRIMARY KEY,
                    username TEXT NOT NULL,
                    role TEXT NOT NULL,
                    created_at TIMESTAMP NOT NULL,
                    expires_at TIMESTAMP NOT NULL,
                    FOREIGN KEY (username) REFERENCES identities (username)
                );

                CREATE TABLE IF NOT EXISTS systemic_findings (
                    systemic_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    shared_attribute TEXT NOT NULL,
                    shared_value TEXT NOT NULL,
                    entity_count INTEGER NOT NULL,
                    entity_ids_json TEXT NOT NULL,
                    title TEXT NOT NULL,
                    rationale TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    created_at TIMESTAMP NOT NULL,
                    FOREIGN KEY (run_id) REFERENCES runs (run_id)
                );

                CREATE TABLE IF NOT EXISTS blind_reviews (
                    review_id TEXT PRIMARY KEY,
                    entity_id TEXT NOT NULL,
                    run_id TEXT NOT NULL,
                    examiner_id TEXT NOT NULL,
                    examiner_concern TEXT NOT NULL,
                    examiner_priority TEXT NOT NULL,
                    examiner_recommendation TEXT NOT NULL,
                    examiner_notes TEXT,
                    system_risk_index REAL NOT NULL,
                    system_risk_band TEXT NOT NULL,
                    concordance_score REAL NOT NULL,
                    created_at TIMESTAMP NOT NULL
                );

                CREATE TABLE IF NOT EXISTS organisations (
                    org_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    sector TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'ACTIVE',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS cses (
                    cse_id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    sector TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'ACTIVE',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (org_id) REFERENCES organisations (org_id)
                );

                CREATE TABLE IF NOT EXISTS admin_audit_log (
                    log_id TEXT PRIMARY KEY,
                    ts TIMESTAMP NOT NULL,
                    action TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    target TEXT,
                    details_json TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    curr_hash TEXT NOT NULL,
                    hash_alg TEXT NOT NULL DEFAULT 'sha256'
                );

                CREATE TABLE IF NOT EXISTS admin_sessions (
                    session_hash TEXT PRIMARY KEY,
                    username TEXT NOT NULL,
                    role TEXT NOT NULL,
                    created_at TIMESTAMP NOT NULL,
                    expires_at TIMESTAMP NOT NULL,
                    FOREIGN KEY (username) REFERENCES identities (username)
                );

                CREATE TABLE IF NOT EXISTS live_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TIMESTAMP NOT NULL,
                    event_type TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    role TEXT,
                    entity_id TEXT,
                    details_json TEXT,
                    is_admin INTEGER DEFAULT 0
                );
                """
            )
            # Migration check: Ensure identities has all required columns
            cur = self.conn.cursor()
            cur.execute("PRAGMA table_info(identities)")
            cols = [row[1] for row in cur.fetchall()]
            if "is_blocked" not in cols:
                self.conn.execute("ALTER TABLE identities ADD COLUMN is_blocked INTEGER DEFAULT 0")
            if "org_id" not in cols:
                self.conn.execute("ALTER TABLE identities ADD COLUMN org_id TEXT")
            if "cse_id" not in cols:
                self.conn.execute("ALTER TABLE identities ADD COLUMN cse_id TEXT")
            if "status" not in cols:
                self.conn.execute("ALTER TABLE identities ADD COLUMN status TEXT DEFAULT 'ACTIVE'")
            if "last_login" not in cols:
                self.conn.execute("ALTER TABLE identities ADD COLUMN last_login TIMESTAMP")
            if "force_password_change" not in cols:
                self.conn.execute("ALTER TABLE identities ADD COLUMN force_password_change INTEGER DEFAULT 0")
            if "is_admin_user" not in cols:
                self.conn.execute("ALTER TABLE identities ADD COLUMN is_admin_user INTEGER DEFAULT 0")

    # --- Audit Log with Cryptographic Hash Chaining ---

    def append_audit(self, action: str, actor: str, details: dict[str, Any]) -> AuditLogEntry:
        """Append an entry to the audit log, hash-chained to the previous entry (SHA3-256).

        Serialized (process lock + BEGIN IMMEDIATE) so concurrent writers can't fork the chain.
        """
        details_json = json.dumps(details, sort_keys=True)
        with self._serialized_chain_write() as cursor:
            cursor.execute("SELECT curr_hash FROM audit_log ORDER BY rowid DESC LIMIT 1")
            row = cursor.fetchone()
            prev_hash = row["curr_hash"] if row else self.GENESIS_HASH

            ts_now = utc_now_iso()
            log_id = hashlib.sha256(
                f"{action}_{actor}_{prev_hash}_{ts_now}".encode()
            ).hexdigest()[:16]
            payload = f"{log_id}:{ts_now}:{action}:{actor}:{details_json}:{prev_hash}"
            curr_hash = compute_chain_hash(HASH_ALG_CURRENT, payload)
            cursor.execute(
                """
                INSERT INTO audit_log (log_id, ts, action, actor, details_json, prev_hash, curr_hash, hash_alg)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (log_id, ts_now, action, actor, details_json, prev_hash, curr_hash, HASH_ALG_CURRENT),
            )

        return AuditLogEntry(
            log_id=log_id,
            action=action,
            actor=actor,
            details_json=details_json,
            prev_hash=prev_hash,
            curr_hash=curr_hash,
        )

    def verify_chain(self, table: str) -> ChainVerification:
        """Walk a hash chain in rowid order, recomputing each row with its own hash_alg.

        Detects edits to any hashed field, relabeled hash_alg, swapped/edited
        hashes, deleted or inserted middle rows, and reordered rows. It does NOT
        detect removal of the newest rows (the shortened chain is still
        internally consistent) or a full recomputation of the chain by someone
        with write access -- see audit_head() / verify_checkpoint().
        """
        if table not in ("audit_log", "admin_audit_log"):
            raise ValueError(f"Unsupported audit table: {table}")
        with_target = table == "admin_audit_log"
        target_col = "target, " if with_target else ""
        cursor = self.conn.cursor()
        cursor.execute(
            f"SELECT log_id, ts, action, actor, {target_col}details_json, prev_hash, curr_hash, hash_alg "
            f"FROM {table} ORDER BY rowid ASC"
        )
        rows = cursor.fetchall()
        expected_prev = self.GENESIS_HASH
        for idx, row in enumerate(rows, start=1):
            if row["prev_hash"] != expected_prev:
                return ChainVerification(
                    False,
                    f"Broken prev_hash chain at entry {row['log_id']} (row {idx}).",
                    len(rows), idx, row["log_id"],
                )
            fields = [row["log_id"], row["ts"], row["action"], row["actor"]]
            if with_target:
                fields.append(row["target"] or "")
            payload = ":".join([*fields, row["details_json"], row["prev_hash"]])
            try:
                recomputed = compute_chain_hash(row["hash_alg"], payload)
            except ValueError:
                return ChainVerification(
                    False,
                    f"Unknown hash algorithm {row['hash_alg']!r} at entry {row['log_id']} (row {idx}).",
                    len(rows), idx, row["log_id"],
                )
            if recomputed != row["curr_hash"]:
                return ChainVerification(
                    False,
                    f"Tampered record at entry {row['log_id']} (row {idx}). Hash mismatch.",
                    len(rows), idx, row["log_id"],
                )
            expected_prev = row["curr_hash"]
        if not rows:
            return ChainVerification(True, "Audit log is empty.", 0)
        return ChainVerification(
            True, f"Audit chain verified successfully ({len(rows)} entries intact).", len(rows)
        )

    def verify_audit_chain_detailed(self) -> ChainVerification:
        return self.verify_chain("audit_log")

    def verify_audit_chain(self) -> tuple[bool, str]:
        """Verify the integrity of the audit log hash chain (see verify_chain for limits)."""
        result = self.verify_chain("audit_log")
        return result.ok, result.message

    def audit_head(self, table: str = "audit_log") -> AuditHead:
        """Row count and newest curr_hash, to be recorded OFF-BOX as a checkpoint.

        A hash chain alone cannot reveal deletion of its newest rows; comparing
        a later chain against an externally recorded head (verify_checkpoint)
        can.
        """
        if table not in ("audit_log", "admin_audit_log"):
            raise ValueError(f"Unsupported audit table: {table}")
        count = self.conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
        row = self.conn.execute(
            f"SELECT curr_hash, hash_alg FROM {table} ORDER BY rowid DESC LIMIT 1"
        ).fetchone()
        if not row:
            return AuditHead(0, self.GENESIS_HASH, None)
        return AuditHead(count, row["curr_hash"], row["hash_alg"])

    def verify_checkpoint(
        self, count: int, head_hash: str, table: str = "audit_log"
    ) -> tuple[bool, str]:
        """Check the chain still contains a previously recorded head.

        Passes if the chain verifies AND its row #count (rowid order) still has
        curr_hash == head_hash. Rows appended after the checkpoint are fine;
        fewer rows than recorded (tail truncation) or a different hash at that
        position (rewrite) fail.
        """
        chain = self.verify_chain(table)
        if not chain.ok:
            return False, chain.message
        if count == 0:
            return True, "Checkpoint was an empty chain."
        if chain.entries < count:
            return False, (
                f"Audit log truncated: {chain.entries} entries present but the recorded checkpoint "
                f"had {count}."
            )
        row = self.conn.execute(
            f"SELECT curr_hash FROM {table} ORDER BY rowid ASC LIMIT 1 OFFSET ?", (count - 1,)
        ).fetchone()
        if row["curr_hash"] != head_hash:
            return False, (
                f"Checkpoint mismatch at entry {count}: recorded head {head_hash[:16]}..., "
                f"found {row['curr_hash'][:16]}... (history rewritten)."
            )
        return True, (
            f"Checkpoint verified: entry {count} matches the recorded head "
            f"({chain.entries - count} entries appended since)."
        )

    # --- Shadow-pilot evaluations ---

    def save_shadow_result(
        self, run_id: str, actor: str, source_name: str, result: dict[str, Any]
    ) -> int:
        with self.conn:
            cur = self.conn.execute(
                "INSERT INTO shadow_pilot_results (run_id, created_at, actor, source_name, result_json) "
                "VALUES (?, ?, ?, ?, ?)",
                (run_id, utc_now_iso(), actor, source_name, json.dumps(result)),
            )
        return int(cur.lastrowid or 0)

    def list_shadow_results(self, run_id: str | None = None, limit: int = 20) -> list[dict[str, Any]]:
        """Newest first; each row's `result` is the decoded evaluation."""
        sql = "SELECT * FROM shadow_pilot_results"
        params: list[Any] = []
        if run_id is not None:
            sql += " WHERE run_id = ?"
            params.append(run_id)
        sql += " ORDER BY result_id DESC LIMIT ?"
        params.append(limit)
        rows = []
        for r in self.conn.execute(sql, params):
            row = dict(r)
            row["result"] = json.loads(row.pop("result_json"))
            rows.append(row)
        return rows

    # --- Periodic batch submissions (one per entity and period) ---

    def claim_batch_submission(self, entity_id: str, period: str, actor: str) -> bool:
        """Atomically reserve the (entity_id, period) slot; False if already submitted."""
        try:
            with self.conn:
                self.conn.execute(
                    "INSERT INTO batch_submissions (entity_id, period, submitted_at, actor) "
                    "VALUES (?, ?, ?, ?)",
                    (entity_id, period, utc_now_iso(), actor),
                )
        except sqlite3.IntegrityError:
            return False
        return True

    def release_batch_submission(self, entity_id: str, period: str) -> None:
        with self.conn:
            self.conn.execute(
                "DELETE FROM batch_submissions WHERE entity_id = ? AND period = ?",
                (entity_id, period),
            )

    # --- Login lockout (backed by the existing hash-chained audit logs) ---

    _LOGIN_AUDIT_TABLES = frozenset({"audit_log", "admin_audit_log"})

    def count_recent_login_failures(
        self,
        username: str,
        window_minutes: int,
        *,
        table: str = "audit_log",
        fail_action: str = "login_failed",
        success_action: str = "login",
        now: _dt.datetime | None = None,
    ) -> int:
        """Count `fail_action` rows for `username` within the last `window_minutes`.

        Only failures after the most recent `success_action` count: a successful
        login resets the counter. Timestamps are parsed and compared as aware
        UTC datetimes rather than as strings, so rows written with and without
        fractional seconds (see utc_now_iso) compare correctly.
        """
        if table not in self._LOGIN_AUDIT_TABLES:
            raise ValueError(f"Unsupported audit table: {table}")
        cutoff = (now or _dt.datetime.now(_dt.UTC)) - _dt.timedelta(minutes=window_minutes)
        cur = self.conn.cursor()
        cur.execute(
            f"SELECT action, ts FROM {table} WHERE actor = ? AND action IN (?, ?) "
            "ORDER BY rowid DESC LIMIT 200",
            (username, fail_action, success_action),
        )
        failures = 0
        for row in cur.fetchall():
            if row["action"] == success_action:
                break
            if parse_utc(row["ts"]) < cutoff:
                break
            failures += 1
        return failures

    # --- Auth: Identities & Sessions (local, offline RBAC) ---

    def seed_default_identities(self) -> bool:
        """Seed the built-in demo admin/analyst/examiner identities if the table is empty.

        Returns True if identities were seeded, False if identities already existed
        (never overwrites an operator's rotated credentials).
        """
        from satsa.auth.identities import DEFAULT_IDENTITIES, generate_salt, hash_passphrase

        cur = self.conn.cursor()
        cur.execute("SELECT count(*) FROM identities")
        if cur.fetchone()[0] > 0:
            return False

        with self.conn:
            for username, role, passphrase in DEFAULT_IDENTITIES:
                salt = generate_salt()
                pass_hash = hash_passphrase(passphrase, salt)
                self.conn.execute(
                    "INSERT OR REPLACE INTO identities (username, role, pass_hash, pass_salt) VALUES (?, ?, ?, ?)",
                    (username, role, pass_hash, salt.hex()),
                )
        return True

    def upsert_identity(self, username: str, role: str, passphrase: str) -> None:
        """Create or update an identity with a freshly hashed passphrase."""
        from satsa.auth.identities import generate_salt, hash_passphrase

        salt = generate_salt()
        pass_hash = hash_passphrase(passphrase, salt)
        with self.conn:
            self.conn.execute(
                "INSERT OR REPLACE INTO identities (username, role, pass_hash, pass_salt) VALUES (?, ?, ?, ?)",
                (username, role, pass_hash, salt.hex()),
            )

    def get_identity(self, username: str) -> dict[str, Any] | None:
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM identities WHERE username = ?", (username,))
        row = cur.fetchone()
        return dict(row) if row else None

    def list_identities(self) -> list[dict[str, Any]]:
        cur = self.conn.cursor()
        cur.execute("SELECT username, role, is_blocked, created_at FROM identities ORDER BY username")
        return [dict(r) for r in cur.fetchall()]

    def set_blocked(self, username: str, blocked: bool = True) -> None:
        """Mark an identity as blocked (1) or unblocked (0)."""
        with self.conn:
            self.conn.execute(
                "UPDATE identities SET is_blocked = ? WHERE username = ?",
                (1 if blocked else 0, username),
            )

    def create_session(self, username: str, role: str, ttl_hours: int = 8) -> str:
        """Create a new session and return the raw token (only the SHA-256 hash is stored)."""
        import datetime
        import secrets

        raw_token = secrets.token_urlsafe(32)
        session_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        now = datetime.datetime.now(datetime.UTC)
        expires_at = now + datetime.timedelta(hours=ttl_hours)
        with self.conn:
            self.conn.execute(
                """
                INSERT INTO sessions (session_hash, username, role, created_at, expires_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (session_hash, username, role, now.isoformat(timespec="microseconds"), expires_at.isoformat(timespec="microseconds")),
            )
        return raw_token

    def get_session(self, raw_token: str) -> dict[str, Any] | None:
        """Look up a session by raw token, returning None if missing, expired, or user is blocked."""
        import datetime

        session_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        cur = self.conn.cursor()
        cur.execute(
            """
            SELECT s.session_hash, s.username, s.created_at, s.expires_at,
                   COALESCE(i.role, s.role) as role,
                   i.is_blocked, i.status, i.org_id, i.cse_id, i.is_admin_user,
                   o.name as org_name, c.name as cse_name
            FROM sessions s
            LEFT JOIN identities i ON s.username = i.username
            LEFT JOIN organisations o ON i.org_id = o.org_id
            LEFT JOIN cses c ON i.cse_id = c.cse_id
            WHERE s.session_hash = ?
            """,
            (session_hash,),
        )
        row = cur.fetchone()
        if not row:
            return None
        if row["is_blocked"] or row["status"] == "BLOCKED":
            self.delete_session(raw_token)
            return None
        expires_at = datetime.datetime.fromisoformat(row["expires_at"])
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=datetime.UTC)
        if datetime.datetime.now(datetime.UTC) > expires_at:
            self.delete_session(raw_token)
            return None
        return dict(row)

    def delete_session(self, raw_token: str) -> None:
        session_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        with self.conn:
            self.conn.execute("DELETE FROM sessions WHERE session_hash = ?", (session_hash,))

    # --- Systemic (cross-entity) findings ---

    def save_systemic_findings(self, findings: list[dict[str, Any]]) -> None:
        with self.conn:
            for f in findings:
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO systemic_findings (
                        systemic_id, run_id, rule_id, shared_attribute, shared_value,
                        entity_count, entity_ids_json, title, rationale, severity, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        f["systemic_id"],
                        f["run_id"],
                        f["rule_id"],
                        f["shared_attribute"],
                        f["shared_value"],
                        f["entity_count"],
                        json.dumps(f["entity_ids"]),
                        f["title"],
                        f["rationale"],
                        f["severity"],
                        f["created_at"],
                    ),
                )

    def get_systemic_findings(self, run_id: str) -> list[dict[str, Any]]:
        cur = self.conn.cursor()
        cur.execute(
            "SELECT * FROM systemic_findings WHERE run_id = ? ORDER BY entity_count DESC",
            (run_id,),
        )
        rows = [dict(r) for r in cur.fetchall()]
        for r in rows:
            r["entity_ids"] = json.loads(r.pop("entity_ids_json"))
        return rows

    # --- Persistence Helpers ---

    def save_run(self, run: Run) -> None:
        with self.conn:
            self.conn.execute(
                """
                INSERT OR REPLACE INTO runs (run_id, period, created_at, config_hash, code_version, status, manifest_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run.run_id,
                    run.period,
                    run.created_at.isoformat(),
                    run.config_hash,
                    run.code_version,
                    run.status,
                    run.manifest_json,
                ),
            )

    def save_findings(self, findings: list[Finding], evidences: list[FindingEvidence]) -> None:
        with self.conn:
            for f in findings:
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO findings (
                        finding_id, run_id, entity_id, rule_id, rule_version, domain,
                        level, score, confidence, severity, title, rationale,
                        peer_comparison_json, limitations, benign_explanations_json,
                        examiner_check, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        f.finding_id,
                        f.run_id,
                        f.entity_id,
                        f.rule_id,
                        f.rule_version,
                        f.domain,
                        f.level,
                        f.score,
                        f.confidence,
                        f.severity,
                        f.title,
                        f.rationale,
                        json.dumps(f.peer_comparison),
                        f.limitations,
                        json.dumps(f.benign_explanations),
                        f.examiner_check,
                        f.created_at.isoformat(),
                    ),
                )
            for ev in evidences:
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO finding_evidences (finding_id, record_type, record_id, details_json)
                    VALUES (?, ?, ?, ?)
                    """,
                    (ev.finding_id, ev.record_type, ev.record_id, json.dumps(ev.details)),
                )

    def save_scores(
        self, domain_scores: list[DomainScore], entity_scores: list[EntityScore]
    ) -> None:
        with self.conn:
            for ds in domain_scores:
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO domain_scores (run_id, entity_id, domain, score)
                    VALUES (?, ?, ?, ?)
                    """,
                    (ds.run_id, ds.entity_id, ds.domain, ds.score),
                )
            for es in entity_scores:
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO entity_scores (
                        run_id, entity_id, risk_index, risk_band, distinct_rules_triggered, domain_scores_json
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        es.run_id,
                        es.entity_id,
                        es.risk_index,
                        es.risk_band,
                        es.distinct_rules_triggered,
                        json.dumps(es.domain_scores),
                    ),
                )

    def save_review_queue(self, queue_items: list[ReviewQueueItem]) -> None:
        with self.conn:
            for item in queue_items:
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO review_queue (
                        queue_id, run_id, entity_id, record_type, record_id, severity,
                        score, selection_reason, is_random, examiner_status, examiner_note
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        item.queue_id,
                        item.run_id,
                        item.entity_id,
                        item.record_type,
                        item.record_id,
                        item.severity,
                        item.score,
                        item.selection_reason,
                        1 if item.is_random else 0,
                        item.examiner_status,
                        item.examiner_note,
                    ),
                )

    def save_dq_issue(self, issue: DQIssue) -> None:
        with self.conn:
            self.conn.execute(
                """
                INSERT OR REPLACE INTO dq_issues (
                    issue_id, batch_id, entity_id, check_name, severity, count, sample_records_json, details
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    issue.issue_id,
                    issue.batch_id,
                    issue.entity_id,
                    issue.check_name,
                    issue.severity,
                    issue.count,
                    json.dumps(issue.sample_records),
                    issue.details,
                ),
            )

    def save_feedback(self, fb: ExaminerFeedback) -> None:
        with self.conn:
            self.conn.execute(
                """
                INSERT OR REPLACE INTO feedback (feedback_id, queue_id, finding_id, examiner_id, status, notes, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    fb.feedback_id,
                    fb.queue_id,
                    fb.finding_id,
                    fb.examiner_id,
                    fb.status,
                    fb.notes,
                    fb.created_at.isoformat(),
                ),
            )
            # Update review_queue status
            self.conn.execute(
                "UPDATE review_queue SET examiner_status = ?, examiner_note = ? WHERE queue_id = ?",
                (fb.status, fb.notes, fb.queue_id),
            )

    def save_blind_review(
        self,
        review_id: str,
        entity_id: str,
        run_id: str,
        examiner_id: str,
        examiner_concern: str,
        examiner_priority: str,
        examiner_recommendation: str,
        examiner_notes: str,
        system_risk_index: float,
        system_risk_band: str,
        concordance_score: float,
    ) -> None:
        """Save a blinded examiner assessment record and log to audit trail."""

        now = utc_now_iso()
        with self.conn:
            self.conn.execute(
                """
                INSERT OR REPLACE INTO blind_reviews (
                    review_id, entity_id, run_id, examiner_id,
                    examiner_concern, examiner_priority, examiner_recommendation,
                    examiner_notes, system_risk_index, system_risk_band,
                    concordance_score, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    review_id,
                    entity_id,
                    run_id,
                    examiner_id,
                    examiner_concern,
                    examiner_priority,
                    examiner_recommendation,
                    examiner_notes,
                    system_risk_index,
                    system_risk_band,
                    concordance_score,
                    now,
                ),
            )
        self.append_audit(
            action="blind_review_submitted",
            actor=examiner_id,
            details={
                "review_id": review_id,
                "entity_id": entity_id,
                "concordance": concordance_score,
                "examiner_concern": examiner_concern,
                "system_risk_band": system_risk_band,
            },
        )

    def get_blind_reviews(self, entity_id: str | None = None) -> list[dict[str, Any]]:
        """Retrieve historical blind reviews, optionally filtered by entity."""
        cur = self.conn.cursor()
        if entity_id:
            cur.execute(
                "SELECT * FROM blind_reviews WHERE entity_id = ? ORDER BY created_at DESC",
                (entity_id,),
            )
        else:
            cur.execute("SELECT * FROM blind_reviews ORDER BY created_at DESC")
        return [dict(r) for r in cur.fetchall()]

    # --- NCIIPC Administration Portal Management ---

    def seed_default_organisations_and_cses(self) -> None:
        """Seed default critical sector organisations and CSEs if tables are empty."""
        cur = self.conn.cursor()
        cur.execute("SELECT count(*) FROM organisations")
        if cur.fetchone()[0] == 0:
            orgs = [
                ("ORG-NCIIPC", "National Critical Information Infrastructure Protection Centre", "Government / Oversight", "ACTIVE"),
                ("ORG-POWER", "National Power Grid Corporation", "power", "ACTIVE"),
                ("ORG-FIN", "Indian Banking & Financial Services Consortium", "banking", "ACTIVE"),
                ("ORG-TELECOM", "National Telecommunications Infrastructure Corp", "telecom", "ACTIVE"),
                ("ORG-ENERGY", "Hydrocarbon & Petroleum Pipelines Board", "oil_and_gas", "ACTIVE"),
                ("ORG-TRANSPORT", "Strategic Rail & Freight Transit Authority", "transport", "ACTIVE"),
            ]
            with self.conn:
                self.conn.executemany(
                    "INSERT OR IGNORE INTO organisations (org_id, name, sector, status) VALUES (?, ?, ?, ?)",
                    orgs,
                )

        cur.execute("SELECT count(*) FROM cses")
        if cur.fetchone()[0] == 0:
            cses = [
                ("CSE-01", "ORG-POWER", "Northern Power Grid Ltd", "power", "ACTIVE"),
                ("CSE-02", "ORG-FIN", "Apex Central Bank", "banking", "ACTIVE"),
                ("CSE-03", "ORG-TELECOM", "Bharat Telecom Infra", "telecom", "ACTIVE"),
                ("CSE-04", "ORG-ENERGY", "Eastern Gas Pipeline Corp", "oil_and_gas", "ACTIVE"),
                ("CSE-05", "ORG-TRANSPORT", "National Rail Freight Logistics", "transport", "ACTIVE"),
                ("CSE-06", "ORG-POWER", "Solaris Energy Transmission", "power", "ACTIVE"),
                ("CSE-07", "ORG-FIN", "Mercantile Merchant Bank", "banking", "ACTIVE"),
                ("CSE-08", "ORG-TELECOM", "Metro Fiber Communications", "telecom", "ACTIVE"),
                ("CSE-09", "ORG-ENERGY", "Coastal Hydrocarbon Offshore", "oil_and_gas", "ACTIVE"),
                ("CSE-10", "ORG-TRANSPORT", "Metro Transit Automated Rail", "transport", "ACTIVE"),
            ]
            with self.conn:
                self.conn.executemany(
                    "INSERT OR IGNORE INTO cses (cse_id, org_id, name, sector, status) VALUES (?, ?, ?, ?, ?)",
                    cses,
                )

    def seed_default_admin(self) -> None:
        """Seed initial bootstrap NCIIPC Administrator and ensure admin user has full admin access."""
        from satsa.auth.identities import generate_salt, hash_passphrase

        cur = self.conn.cursor()
        cur.execute("SELECT username FROM identities WHERE username = 'nciipc_admin'")
        if not cur.fetchone():
            salt = generate_salt()
            pass_hash = hash_passphrase("ChangeMe-NCIIPC#2026", salt)
            with self.conn:
                self.conn.execute(
                    """
                    INSERT INTO identities (
                        username, role, pass_hash, pass_salt, is_blocked,
                        org_id, cse_id, status, is_admin_user
                    ) VALUES (?, ?, ?, ?, 0, 'ORG-NCIIPC', NULL, 'ACTIVE', 1)
                    """,
                    ("nciipc_admin", "NCIIPC Super Administrator", pass_hash, salt.hex()),
                )

        # Ensure demo 'admin' has admin portal access and active status
        cur.execute("SELECT username FROM identities WHERE username = 'admin'")
        if cur.fetchone():
            with self.conn:
                self.conn.execute(
                    """
                    UPDATE identities SET
                        role = 'admin',
                        org_id = COALESCE(org_id, 'ORG-NCIIPC'),
                        status = 'ACTIVE',
                        is_admin_user = 1
                    WHERE username = 'admin'
                    """
                )

    def list_organisations(self) -> list[dict[str, Any]]:
        cur = self.conn.cursor()
        cur.execute(
            """
            SELECT o.org_id, o.name, o.sector, o.status, o.created_at,
                   COUNT(DISTINCT c.cse_id) as cse_count,
                   COUNT(DISTINCT u.username) as user_count
            FROM organisations o
            LEFT JOIN cses c ON o.org_id = c.org_id
            LEFT JOIN identities u ON o.org_id = u.org_id
            GROUP BY o.org_id, o.name, o.sector, o.status, o.created_at
            ORDER BY o.name ASC
            """
        )
        return [dict(r) for r in cur.fetchall()]

    def get_organisation(self, org_id: str) -> dict[str, Any] | None:
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM organisations WHERE org_id = ?", (org_id,))
        row = cur.fetchone()
        return dict(row) if row else None

    def create_organisation(self, org_id: str, name: str, sector: str, status: str = "ACTIVE") -> None:
        with self.conn:
            self.conn.execute(
                "INSERT INTO organisations (org_id, name, sector, status) VALUES (?, ?, ?, ?)",
                (org_id.strip().upper(), name.strip(), sector.strip(), status),
            )

    def update_organisation(self, org_id: str, name: str, sector: str, status: str) -> None:
        with self.conn:
            self.conn.execute(
                "UPDATE organisations SET name = ?, sector = ?, status = ? WHERE org_id = ?",
                (name.strip(), sector.strip(), status, org_id),
            )

    def list_cses(self, org_id: str | None = None) -> list[dict[str, Any]]:
        cur = self.conn.cursor()
        if org_id:
            cur.execute(
                """
                SELECT c.cse_id, c.org_id, c.name, c.sector, c.status, c.created_at,
                       o.name as org_name,
                       COUNT(DISTINCT u.username) as user_count
                FROM cses c
                LEFT JOIN organisations o ON c.org_id = o.org_id
                LEFT JOIN identities u ON c.cse_id = u.cse_id
                WHERE c.org_id = ?
                GROUP BY c.cse_id, c.org_id, c.name, c.sector, c.status, c.created_at, o.name
                ORDER BY c.cse_id ASC
                """,
                (org_id,),
            )
        else:
            cur.execute(
                """
                SELECT c.cse_id, c.org_id, c.name, c.sector, c.status, c.created_at,
                       o.name as org_name,
                       COUNT(DISTINCT u.username) as user_count
                FROM cses c
                LEFT JOIN organisations o ON c.org_id = o.org_id
                LEFT JOIN identities u ON c.cse_id = u.cse_id
                GROUP BY c.cse_id, c.org_id, c.name, c.sector, c.status, c.created_at, o.name
                ORDER BY c.cse_id ASC
                """
            )
        return [dict(r) for r in cur.fetchall()]

    def get_cse(self, cse_id: str) -> dict[str, Any] | None:
        cur = self.conn.cursor()
        cur.execute(
            """
            SELECT c.*, o.name as org_name
            FROM cses c
            LEFT JOIN organisations o ON c.org_id = o.org_id
            WHERE c.cse_id = ?
            """,
            (cse_id,),
        )
        row = cur.fetchone()
        return dict(row) if row else None

    def create_cse(
        self, cse_id: str, org_id: str, sector: str, name: str | None = None, status: str = "ACTIVE"
    ) -> None:
        cse_clean = cse_id.strip().upper()
        cse_name = (name or cse_clean).strip()
        with self.conn:
            self.conn.execute(
                "INSERT INTO cses (cse_id, org_id, name, sector, status) VALUES (?, ?, ?, ?, ?)",
                (cse_clean, org_id, cse_name, sector.strip(), status),
            )

    def update_cse(self, cse_id: str, org_id: str, name: str, sector: str, status: str) -> None:
        with self.conn:
            self.conn.execute(
                "UPDATE cses SET org_id = ?, name = ?, sector = ?, status = ? WHERE cse_id = ?",
                (org_id, name.strip(), sector.strip(), status, cse_id),
            )

    def create_user(
        self,
        username: str,
        role: str,
        passphrase: str,
        org_id: str | None = None,
        cse_id: str | None = None,
        status: str = "ACTIVE",
        force_password_change: int = 0,
        is_admin_user: int = 0,
    ) -> None:
        from satsa.auth.identities import generate_salt, hash_passphrase

        salt = generate_salt()
        pass_hash = hash_passphrase(passphrase, salt)
        is_blocked = 1 if status == "BLOCKED" else 0
        with self.conn:
            self.conn.execute(
                """
                INSERT INTO identities (
                    username, role, pass_hash, pass_salt, is_blocked,
                    org_id, cse_id, status, force_password_change, is_admin_user
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    username.strip(),
                    role.strip(),
                    pass_hash,
                    salt.hex(),
                    is_blocked,
                    org_id,
                    cse_id,
                    status,
                    force_password_change,
                    is_admin_user,
                ),
            )

    def update_user(
        self,
        username: str,
        role: str | None = None,
        org_id: str | None = None,
        cse_id: str | None = None,
        status: str | None = None,
        force_password_change: int | None = None,
        is_admin_user: int | None = None,
    ) -> None:
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM identities WHERE username = ?", (username,))
        row = cur.fetchone()
        if not row:
            raise ValueError(f"User {username} does not exist.")

        new_role = role if role is not None else row["role"]
        new_org = org_id if org_id is not None else row["org_id"]
        new_cse = cse_id if cse_id is not None else row["cse_id"]
        new_status = status if status is not None else (row["status"] or "ACTIVE")
        new_fpc = force_password_change if force_password_change is not None else (row["force_password_change"] or 0)
        new_admin = is_admin_user if is_admin_user is not None else (row["is_admin_user"] or 0)
        is_blocked = 1 if new_status == "BLOCKED" else 0

        with self.conn:
            self.conn.execute(
                """
                UPDATE identities
                SET role = ?, org_id = ?, cse_id = ?, status = ?, is_blocked = ?, force_password_change = ?, is_admin_user = ?
                WHERE username = ?
                """,
                (new_role, new_org, new_cse, new_status, is_blocked, new_fpc, new_admin, username),
            )
            # If user is blocked, delete any active sessions immediately
            if is_blocked:
                self.conn.execute("DELETE FROM sessions WHERE username = ?", (username,))
                self.conn.execute("DELETE FROM admin_sessions WHERE username = ?", (username,))

    def reset_user_password(
        self, username: str, new_passphrase: str, force_password_change: int = 1
    ) -> None:
        from satsa.auth.identities import generate_salt, hash_passphrase

        salt = generate_salt()
        pass_hash = hash_passphrase(new_passphrase, salt)
        with self.conn:
            self.conn.execute(
                """
                UPDATE identities
                SET pass_hash = ?, pass_salt = ?, force_password_change = ?
                WHERE username = ?
                """,
                (pass_hash, salt.hex(), force_password_change, username),
            )
            # Invalidate all current sessions on credential reset
            self.conn.execute("DELETE FROM sessions WHERE username = ?", (username,))
            self.conn.execute("DELETE FROM admin_sessions WHERE username = ?", (username,))

    def set_user_status(self, username: str, status: str = "ACTIVE") -> None:
        is_blocked = 1 if status == "BLOCKED" else 0
        with self.conn:
            self.conn.execute(
                "UPDATE identities SET status = ?, is_blocked = ? WHERE username = ?",
                (status, is_blocked, username),
            )
            if is_blocked:
                self.conn.execute("DELETE FROM sessions WHERE username = ?", (username,))
                self.conn.execute("DELETE FROM admin_sessions WHERE username = ?", (username,))

    def get_user(self, username: str) -> dict[str, Any] | None:
        cur = self.conn.cursor()
        cur.execute(
            """
            SELECT u.username, u.role, u.is_blocked, u.org_id, u.cse_id,
                   COALESCE(u.status, CASE WHEN u.is_blocked = 1 THEN 'BLOCKED' ELSE 'ACTIVE' END) as status,
                   u.created_at, u.last_login, u.force_password_change, u.is_admin_user,
                   o.name as org_name, c.name as cse_name
            FROM identities u
            LEFT JOIN organisations o ON u.org_id = o.org_id
            LEFT JOIN cses c ON u.cse_id = c.cse_id
            WHERE u.username = ?
            """,
            (username,),
        )
        row = cur.fetchone()
        return dict(row) if row else None

    def list_admin_users(self) -> list[dict[str, Any]]:

        now_iso = utc_now_iso()
        cur = self.conn.cursor()
        cur.execute(
            """
            SELECT u.username, u.role, u.is_blocked, u.org_id, u.cse_id,
                   COALESCE(u.status, CASE WHEN u.is_blocked = 1 THEN 'BLOCKED' ELSE 'ACTIVE' END) as status,
                   u.created_at, u.last_login, u.force_password_change, u.is_admin_user,
                   o.name as org_name, c.name as cse_name,
                   CASE WHEN EXISTS (
                       SELECT 1 FROM sessions s
                       WHERE s.username = u.username AND s.expires_at > ?
                   ) OR EXISTS (
                       SELECT 1 FROM admin_sessions ast
                       WHERE ast.username = u.username AND ast.expires_at > ?
                   ) THEN 1 ELSE 0 END as is_online
            FROM identities u
            LEFT JOIN organisations o ON u.org_id = o.org_id
            LEFT JOIN cses c ON u.cse_id = c.cse_id
            ORDER BY u.created_at DESC, u.username ASC
            """,
            (now_iso, now_iso),
        )
        return [dict(r) for r in cur.fetchall()]

    def update_user_last_login(self, username: str) -> None:

        now_iso = utc_now_iso()
        with self.conn:
            self.conn.execute("UPDATE identities SET last_login = ? WHERE username = ?", (now_iso, username))

    def create_admin_session(self, username: str, role: str, ttl_hours: int = 8) -> str:
        import datetime
        import secrets

        raw_token = secrets.token_urlsafe(32)
        session_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        now = datetime.datetime.now(datetime.UTC)
        expires_at = now + datetime.timedelta(hours=ttl_hours)
        with self.conn:
            self.conn.execute(
                """
                INSERT INTO admin_sessions (session_hash, username, role, created_at, expires_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (session_hash, username, role, now.isoformat(timespec="microseconds"), expires_at.isoformat(timespec="microseconds")),
            )
        return raw_token

    def get_admin_session(self, raw_token: str) -> dict[str, Any] | None:
        import datetime

        session_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        cur = self.conn.cursor()
        cur.execute(
            """
            SELECT s.*, i.is_blocked, i.status, i.org_id, i.cse_id, i.is_admin_user
            FROM admin_sessions s
            LEFT JOIN identities i ON s.username = i.username
            WHERE s.session_hash = ?
            """,
            (session_hash,),
        )
        row = cur.fetchone()
        if not row:
            return None
        if row["is_blocked"] or row["status"] == "BLOCKED":
            self.delete_admin_session(raw_token)
            return None
        expires_at = datetime.datetime.fromisoformat(row["expires_at"])
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=datetime.UTC)
        if datetime.datetime.now(datetime.UTC) > expires_at:
            self.delete_admin_session(raw_token)
            return None
        return dict(row)

    def delete_admin_session(self, raw_token: str) -> None:
        session_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        with self.conn:
            self.conn.execute("DELETE FROM admin_sessions WHERE session_hash = ?", (session_hash,))

    def append_admin_audit(
        self, action: str, actor: str, target: str | None = None, details: dict[str, Any] | None = None
    ) -> AuditLogEntry:
        details_clean = details or {}
        # Security: Remove any potential password field
        details_clean = {k: v for k, v in details_clean.items() if "pass" not in k.lower()}
        details_json = json.dumps(details_clean, sort_keys=True)
        with self._serialized_chain_write() as cursor:
            cursor.execute("SELECT curr_hash FROM admin_audit_log ORDER BY rowid DESC LIMIT 1")
            row = cursor.fetchone()
            prev_hash = row["curr_hash"] if row else self.GENESIS_HASH

            ts_now = utc_now_iso()
            log_id = hashlib.sha256(
                f"admin_{action}_{actor}_{prev_hash}_{ts_now}".encode()
            ).hexdigest()[:16]
            payload = f"{log_id}:{ts_now}:{action}:{actor}:{target or ''}:{details_json}:{prev_hash}"
            curr_hash = compute_chain_hash(HASH_ALG_CURRENT, payload)
            cursor.execute(
                """
                INSERT INTO admin_audit_log (log_id, ts, action, actor, target, details_json, prev_hash, curr_hash, hash_alg)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (log_id, ts_now, action, actor, target, details_json, prev_hash, curr_hash, HASH_ALG_CURRENT),
            )

        return AuditLogEntry(
            log_id=log_id,
            action=action,
            actor=actor,
            details_json=details_json,
            prev_hash=prev_hash,
            curr_hash=curr_hash,
        )

    def list_admin_audit_logs(
        self, limit: int = 100, action: str | None = None, actor: str | None = None
    ) -> list[dict[str, Any]]:
        cur = self.conn.cursor()
        query = "SELECT log_id, ts, action, actor, target, details_json, prev_hash, curr_hash FROM admin_audit_log"
        params: list[Any] = []
        conditions: list[str] = []
        if action:
            conditions.append("action = ?")
            params.append(action)
        if actor:
            conditions.append("actor = ?")
            params.append(actor)
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY rowid DESC LIMIT ?"
        params.append(limit)

        cur.execute(query, tuple(params))
        rows = cur.fetchall()
        result = []
        for r in rows:
            d = dict(r)
            try:
                d["details"] = json.loads(d["details_json"])
            except (json.JSONDecodeError, TypeError):
                d["details"] = {}
            result.append(d)
        return result

    def verify_admin_audit_chain(self) -> tuple[bool, str]:
        result = self.verify_chain("admin_audit_log")
        if result.ok and result.entries == 0:
            return True, "Admin audit log is empty."
        if result.ok:
            return True, f"Cryptographic audit chain verified ({result.entries} entries intact)."
        return False, result.message

    def get_admin_overview_stats(self) -> dict[str, Any]:

        now_iso = utc_now_iso()
        cur = self.conn.cursor()

        cur.execute("SELECT COUNT(*) FROM organisations")
        total_orgs = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM cses")
        total_cses = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM identities WHERE status = 'ACTIVE' OR (status IS NULL AND is_blocked = 0)")
        active_users = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM identities WHERE status = 'BLOCKED' OR is_blocked = 1")
        blocked_users = cur.fetchone()[0]

        cur.execute(
            """
            SELECT COUNT(DISTINCT username) FROM (
                SELECT username FROM sessions WHERE expires_at > ?
                UNION
                SELECT username FROM admin_sessions WHERE expires_at > ?
            )
            """,
            (now_iso, now_iso),
        )
        active_sessions = cur.fetchone()[0]

        # Recent administrative activity (from admin_audit_log)
        cur.execute(
            """
            SELECT log_id, ts, action, actor, target, details_json
            FROM admin_audit_log
            ORDER BY rowid DESC
            LIMIT 7
            """
        )
        recent_admin = []
        for r in cur.fetchall():
            d = dict(r)
            try:
                d["details"] = json.loads(d["details_json"])
            except (json.JSONDecodeError, TypeError):
                d["details"] = {}
            recent_admin.append(d)

        # Recent SAT-SA user activity (from audit_log)
        cur.execute(
            """
            SELECT log_id, ts, action, actor, details_json
            FROM audit_log
            ORDER BY rowid DESC
            LIMIT 7
            """
        )
        recent_user = []
        for r in cur.fetchall():
            d = dict(r)
            try:
                d["details"] = json.loads(d["details_json"])
            except (json.JSONDecodeError, TypeError):
                d["details"] = {}
            recent_user.append(d)

        return {
            "total_organisations": total_orgs,
            "total_cses": total_cses,
            "active_users": active_users,
            "blocked_users": blocked_users,
            "active_sessions": active_sessions,
            "recent_admin_activity": recent_admin,
            "recent_user_activity": recent_user,
            "live_events": self.get_live_events(since_id=0, limit=25),
            "online_operators": self.get_online_operators(),
        }

    # --- Admin activity feed (operator session monitor; live_events table) ---

    def record_live_event(
        self,
        event_type: str,
        actor: str,
        role: str | None = None,
        entity_id: str | None = None,
        details: dict[str, Any] | None = None,
        is_admin: bool = False,
    ) -> int:
        """Record an operator event for the Admin Portal's activity feed (non-authoritative; see ADR-006)."""
        now = utc_now_iso()
        details_json = json.dumps(details or {})
        with self.conn:
            cur = self.conn.execute(
                """
                INSERT INTO live_events (ts, event_type, actor, role, entity_id, details_json, is_admin)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (now, event_type, actor, role, entity_id, details_json, 1 if is_admin else 0),
            )
            event_id = cur.lastrowid
        assert event_id is not None  # always set after a successful INSERT
        return event_id

    def get_live_events(self, since_id: int = 0, limit: int = 50) -> list[dict[str, Any]]:
        """Fetch activity-feed events newer than since_id (oldest first), or the latest `limit`.

        `since_id` must be a non-negative integer (bool and other types are
        rejected, not coerced); `limit` is clamped to [1, LIVE_EVENTS_MAX_LIMIT].
        Both are bound as query parameters.
        """
        if isinstance(since_id, bool) or not isinstance(since_id, int):
            raise TypeError(f"since_id must be an integer, got {since_id!r}")
        if since_id < 0:
            raise ValueError(f"since_id must be non-negative, got {since_id!r}")
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise TypeError(f"limit must be an integer, got {limit!r}")
        limit = max(1, min(limit, LIVE_EVENTS_MAX_LIMIT))
        cur = self.conn.cursor()
        if since_id > 0:
            cur.execute(
                """
                SELECT event_id, ts, event_type, actor, role, entity_id, details_json, is_admin
                FROM live_events
                WHERE event_id > ?
                ORDER BY event_id ASC
                LIMIT ?
                """,
                (since_id, limit),
            )
        else:
            cur.execute(
                """
                SELECT event_id, ts, event_type, actor, role, entity_id, details_json, is_admin
                FROM live_events
                ORDER BY event_id DESC
                LIMIT ?
                """,
                (limit,),
            )
        events = []
        for r in cur.fetchall():
            row = dict(r)
            try:
                row["details"] = json.loads(row["details_json"])
            except (json.JSONDecodeError, TypeError):
                row["details"] = {}
            events.append(row)
        if since_id == 0:
            events.reverse()
        return events

    def get_online_operators(self) -> list[dict[str, Any]]:
        """Get distinct users with active non-expired sessions, including their assigned CSE/Org."""
        now = utc_now_iso()
        cur = self.conn.cursor()
        cur.execute(
            """
            SELECT s.username, s.role, s.created_at as session_started_at,
                   i.status, i.is_blocked, i.org_id, i.cse_id, o.name as org_name, c.name as cse_name
            FROM sessions s
            JOIN identities i ON s.username = i.username
            LEFT JOIN organisations o ON i.org_id = o.org_id
            LEFT JOIN cses c ON i.cse_id = c.cse_id
            WHERE s.expires_at > ?
            GROUP BY s.username
            ORDER BY s.created_at DESC
            """,
            (now,),
        )
        return [dict(r) for r in cur.fetchall()]

    def close(self) -> None:
        """Close SQLite database connection."""
        self.conn.close()
