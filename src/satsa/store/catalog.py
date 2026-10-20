"""Publication catalog: immutable submission batches and the Parquet files they published.

Submitted data is never rewritten in place. Each submission is a *batch*: its tables are
written to a staging directory, checked, moved into the Parquet tree under names that include
the batch id (`<table>/entity_id=<E>/b-<batch>-<n>.parquet`), and only then marked
`published` in one short SQLite transaction in `<data_dir>/catalog.db`. Readers load only
files listed for published batches, so a reader never sees half a batch, and a crash at any
point leaves either a published batch or files that the next writer moves to
`<data_dir>/quarantine/`.

A correction is a new batch whose `parent_batch_id` names the batch it revises. Record
versions are kept side by side; the store selects the latest published version of each
business record (see `VERSION_KEYS` and `DuckDBStore.load_table_from_parquet`), so an updated
alert is counted once and the earlier version is still on disk for older assessments.

The catalog sits next to the Parquet tree (not in `satsa.db`) because it describes exactly
those files: a data directory and its catalog are backed up, restored and moved together.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import re
import shutil
import sqlite3
import sys
import threading
import uuid
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import polars as pl

from satsa.security import require_entity_id
from satsa.store.migrations import Migration, apply_migrations

CATALOG_FILE = "catalog.db"

# Business key of a record in each canonical table, within one entity and source system.
# Versions of the same key are revisions of one record: the latest published one is current.
# None: the table has no natural key (an event log), so a row's full content is its identity.
VERSION_KEYS: dict[str, tuple[str, ...] | None] = {
    "entity": ("entity_id",),
    "asset": ("entity_id", "asset_id"),
    "log_source_daily": ("entity_id", "asset_id", "source_type", "date"),
    "detection_rule": ("entity_id", "rule_id"),
    "alert": ("entity_id", "alert_id"),
    "case": ("entity_id", "case_id"),
    "case_alert_link": ("entity_id", "case_id", "alert_id"),
    "workflow_event": None,
    "escalation": ("entity_id", "esc_id"),
    "closure": ("entity_id", "ref_id"),
    "remediation": ("entity_id", "ticket_id"),
    "external_report": ("entity_id", "incident_id", "reported_to"),
    "declared_kpi": ("entity_id", "period", "metric", "severity"),
    "sla_policy": ("entity_id", "severity"),
    "submission_batch": ("batch_id",),
}

# Column written into every published file: the row's position in its batch, so the latest
# version within one batch is well defined.
SEQ_COLUMN = "_satsa_seq"

# How a batch declares each of its tables.
ROWS = "rows"  # submitted with rows
DECLARED_EMPTY = "declared_empty"  # submitted, and complete with no rows
REJECTED = "rejected"  # submitted but could not be parsed or stored

_BATCH_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


def _now() -> str:
    return _dt.datetime.now(_dt.UTC).isoformat(timespec="microseconds")


def _m1_catalog(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE batches (
            batch_id TEXT PRIMARY KEY,
            pub_seq INTEGER UNIQUE,
            state TEXT NOT NULL CHECK (state IN ('staging', 'held', 'published', 'failed', 'quarantined', 'discarded')),
            entity_id TEXT,
            entities_json TEXT NOT NULL DEFAULT '[]',
            source TEXT NOT NULL DEFAULT 'canonical',
            transport TEXT NOT NULL,
            period_label TEXT,
            period_start TEXT,
            period_end TEXT,
            content_hash TEXT,
            idempotency_key TEXT UNIQUE,
            parent_batch_id TEXT REFERENCES batches (batch_id),
            submitted_by TEXT,
            mapping_version TEXT,
            transform_version TEXT,
            provenance TEXT NOT NULL DEFAULT 'submitted',
            received_at TEXT NOT NULL,
            published_at TEXT,
            note TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE batch_tables (
            batch_id TEXT NOT NULL REFERENCES batches (batch_id),
            table_name TEXT NOT NULL,
            entity_id TEXT NOT NULL DEFAULT '',
            part INTEGER NOT NULL DEFAULT 0,
            completeness TEXT NOT NULL CHECK (completeness IN ('rows', 'declared_empty', 'rejected')),
            rel_path TEXT,
            sha256 TEXT,
            rows INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (batch_id, table_name, entity_id, part)
        )
        """
    )
    conn.execute("CREATE INDEX idx_batch_tables_table ON batch_tables (table_name)")
    conn.execute("CREATE INDEX idx_batches_entity_period ON batches (entity_id, period_start, period_end)")


CATALOG_MIGRATIONS: list[Migration] = [Migration(1, "publication catalog", _m1_catalog)]


@dataclass(frozen=True)
class PublishedFile:
    path: Path
    batch_id: str
    pub_seq: int
    source: str
    received_at: str
    entity_id: str = ""


class PublicationError(RuntimeError):
    """A batch could not be published; nothing of it is visible to readers."""


# --- cross-process writer lock ------------------------------------------------------------

@dataclass
class _LockState:
    rlock: threading.RLock = field(default_factory=threading.RLock)
    depth: int = 0
    fh: Any = None


_LOCK_STATES: dict[str, _LockState] = {}
_LOCK_STATES_GUARD = threading.Lock()


class WriterLock:
    """Serialises publications to one data directory across threads and processes.

    An OS lock on `<data_dir>/catalog.lock` (released by the OS if the process dies), plus a
    re-entrant thread lock because OS file locks are per process. The state is shared by every
    WriterLock on the same path in this process, so nested use from one thread never waits on
    itself.
    """

    def __init__(self, path: Path):
        self.path = path
        with _LOCK_STATES_GUARD:
            self._state = _LOCK_STATES.setdefault(str(path.resolve()), _LockState())

    def acquire(self, blocking: bool = True) -> bool:
        state = self._state
        if not state.rlock.acquire(blocking=blocking):
            return False
        if state.depth == 0:
            try:
                fh = open(self.path, "a+b")  # noqa: SIM115 - held until release()
                if not _os_lock(fh, blocking):
                    fh.close()
                    state.rlock.release()
                    return False
                state.fh = fh
            except BaseException:
                state.rlock.release()
                raise
        state.depth += 1
        return True

    def release(self) -> None:
        state = self._state
        state.depth -= 1
        if state.depth == 0 and state.fh is not None:
            _os_unlock(state.fh)
            state.fh.close()
            state.fh = None
        state.rlock.release()

    @contextmanager
    def held(self) -> Iterator[None]:
        self.acquire()
        try:
            yield
        finally:
            self.release()


def _os_lock(fh: Any, blocking: bool) -> bool:
    if sys.platform == "win32":
        import msvcrt

        fh.seek(0)
        mode = msvcrt.LK_LOCK if blocking else msvcrt.LK_NBLCK
        while True:
            try:
                msvcrt.locking(fh.fileno(), mode, 1)
                return True
            except OSError:
                if not blocking:
                    return False
                # LK_LOCK gives up after ~10 s; keep waiting like a POSIX blocking lock.
    import fcntl

    try:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
        return True
    except OSError:
        return False


def _os_unlock(fh: Any) -> None:
    if sys.platform == "win32":
        import msvcrt

        fh.seek(0)
        with suppress(OSError):
            msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
        return
    import fcntl

    fcntl.flock(fh.fileno(), fcntl.LOCK_UN)


def _fsync_file(path: Path) -> None:
    # Windows refuses fsync on a read-only handle.
    with open(path, "r+b") as fh:
        os.fsync(fh.fileno())


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def frame_content_hash(frames: dict[str, pl.DataFrame]) -> str:
    """Order-independent hash of a submission's canonical content (table -> rows).

    Per table: column names, row count and the wrapping sum of Polars row hashes with a fixed
    seed (stable within the pinned Polars version, which is all idempotency needs: it compares
    a retry with the original submission on the same deployment).
    """
    digest = hashlib.sha256()
    for table in sorted(frames):
        frame = frames[table]
        frame = frame.select(sorted(frame.columns))
        total = int(frame.hash_rows(seed=7, seed_1=11, seed_2=13, seed_3=17).cast(pl.UInt64).sum()) % (1 << 64) if frame.height else 0
        digest.update(f"{table}{','.join(frame.columns)}{frame.height}{total}".encode())
    return digest.hexdigest()


@dataclass
class _Staged:
    table: str
    entity_id: str
    part: int
    staged: Path
    final_rel: str
    rows: int


@dataclass
class BatchWriter:
    """One batch being written. Nothing is visible to readers until `publish()` commits."""

    catalog: Catalog
    batch_id: str
    staged: list[_Staged] = field(default_factory=list)
    declared: dict[tuple[str, str], str] = field(default_factory=dict)
    published: bool = False
    held: bool = False
    _parts: dict[tuple[str, str], int] = field(default_factory=dict)

    @property
    def staging_dir(self) -> Path:
        return self.catalog.staging_dir / self.batch_id

    def add_table(self, table: str, frame: pl.DataFrame) -> dict[str, int]:
        """Stage a table's rows (partitioned by entity_id). Returns rows staged per entity."""
        if frame.is_empty():
            return {}
        frame = frame.with_row_index(SEQ_COLUMN)
        per_entity: dict[str, int] = {}
        if "entity_id" in frame.columns:
            for (eid,), part in frame.group_by(["entity_id"], maintain_order=True):
                ent = "" if eid is None else require_entity_id(eid)
                self._stage(table, ent, part)
                per_entity[ent] = per_entity.get(ent, 0) + part.height
        else:
            self._stage(table, "", frame)
            per_entity[""] = frame.height
        return per_entity

    def _stage(self, table: str, entity_id: str, frame: pl.DataFrame) -> None:
        n = self._parts.get((table, entity_id), 0)
        self._parts[(table, entity_id)] = n + 1
        partition = f"entity_id={entity_id}" if entity_id else "_unpartitioned"
        staged = self.staging_dir / table / partition / f"part-{n}.parquet"
        staged.parent.mkdir(parents=True, exist_ok=True)
        frame.write_parquet(staged)
        final_dir = f"{table}/entity_id={entity_id}" if entity_id else table
        self.staged.append(
            _Staged(table, entity_id, n, staged, f"{final_dir}/b-{self.batch_id}-{n}.parquet", frame.height)
        )

    def declare(self, table: str, entity_ids: list[str], completeness: str) -> None:
        """Record that the batch submitted `table` for these entities with no rows (or rejected it)."""
        if completeness not in (DECLARED_EMPTY, REJECTED):
            raise ValueError(completeness)
        for ent in entity_ids:
            self.declared[(table, ent)] = completeness

    def publish(self) -> int:
        """Move the staged files into place and commit the batch. Returns its publication sequence."""
        if self.published:
            raise PublicationError(f"batch {self.batch_id} is already published")
        moved: list[Path] = []
        try:
            entries: list[tuple[str, str, int, str, str | None, str | None, int]] = []
            for item in self.staged:
                _fsync_file(item.staged)
                digest = _sha256(item.staged)
                final = self.catalog.parquet_dir / item.final_rel
                final.parent.mkdir(parents=True, exist_ok=True)
                if final.exists():
                    raise PublicationError(f"refusing to overwrite published file {item.final_rel}")
                os.replace(item.staged, final)
                moved.append(final)
                entries.append((item.table, item.entity_id, item.part, ROWS, item.final_rel, digest, item.rows))
            with_rows = {(e[0], e[1]) for e in entries}
            for (table, ent), completeness in sorted(self.declared.items()):
                if (table, ent) not in with_rows:
                    entries.append((table, ent, 0, completeness, None, None, 0))
            pub_seq = self.catalog._commit_publication(self.batch_id, entries)
        except BaseException as exc:
            self.catalog._quarantine(self.batch_id, moved, reason=f"publication failed: {type(exc).__name__}")
            self.catalog._discard_staging(self.batch_id)
            if isinstance(exc, PublicationError):
                raise
            raise PublicationError(f"batch {self.batch_id} was not published: {exc}") from exc
        self.published = True
        self.catalog._discard_staging(self.batch_id)
        return pub_seq

    def hold(self, reason: str) -> None:
        """Keep the staged batch unpublished for an authorised publish or discard decision.

        Nothing becomes visible to readers. The staged files and what was declared are written to
        `staging/<batch>/manifest.json` so `Catalog.publish_held` can finish it later.
        """
        manifest = {
            "staged": [
                {
                    "table": i.table, "entity_id": i.entity_id, "part": i.part,
                    "staged": i.staged.relative_to(self.staging_dir).as_posix(),
                    "final_rel": i.final_rel, "rows": i.rows,
                }
                for i in self.staged
            ],
            "declared": [[t, e, c] for (t, e), c in sorted(self.declared.items())],
        }
        self.staging_dir.mkdir(parents=True, exist_ok=True)
        (self.staging_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        self.catalog._set_state(self.batch_id, "held", reason)
        self.held = True

    def abort(self, reason: str) -> None:
        if not self.published and not self.held:
            self.catalog._discard_staging(self.batch_id)
            self.catalog._set_state(self.batch_id, "failed", reason)


class Catalog:
    """The publication catalog of one data directory (see module docstring)."""

    def __init__(self, data_dir: Path | str):
        self.data_dir = Path(data_dir)
        self.parquet_dir = self.data_dir / "parquet"
        self.staging_dir = self.data_dir / "staging"
        self.quarantine_dir = self.data_dir / "quarantine"
        self.parquet_dir.mkdir(parents=True, exist_ok=True)
        self.path = self.data_dir / CATALOG_FILE
        self.conn = sqlite3.connect(str(self.path), timeout=30.0, isolation_level=None, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        with suppress(sqlite3.Error):
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA busy_timeout=30000")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.lock = WriterLock(self.data_dir / "catalog.lock")
        with self.lock.held():
            apply_migrations(self.conn, CATALOG_MIGRATIONS, self.path)

    def close(self) -> None:
        self.conn.close()

    # --- writing ------------------------------------------------------------------------------

    @contextmanager
    def open_batch(
        self,
        *,
        transport: str,
        entity_id: str | None = None,
        source: str = "canonical",
        period_label: str | None = None,
        period_start: str | None = None,
        period_end: str | None = None,
        content_hash: str | None = None,
        idempotency_key: str | None = None,
        parent_batch_id: str | None = None,
        submitted_by: str | None = None,
        mapping_version: str | None = None,
        transform_version: str | None = None,
        provenance: str = "submitted",
        batch_id: str | None = None,
    ) -> Iterator[BatchWriter]:
        """Hold the writer lock for one batch. Leaving the block without `publish()` aborts it."""
        with self.lock.held():
            self.recover()
            bid = batch_id or f"BATCH-{_dt.datetime.now(_dt.UTC).strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:10]}"
            if not _BATCH_ID_RE.match(bid):
                raise ValueError(f"invalid batch id {bid!r}")
            with self.conn:
                self.conn.execute(
                    """
                    INSERT INTO batches (batch_id, state, entity_id, source, transport, period_label,
                        period_start, period_end, content_hash, idempotency_key, parent_batch_id,
                        submitted_by, mapping_version, transform_version, provenance, received_at)
                    VALUES (?, 'staging', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        bid, entity_id, source, transport, period_label, period_start, period_end,
                        content_hash, idempotency_key, parent_batch_id, submitted_by, mapping_version,
                        transform_version, provenance, _now(),
                    ),
                )
            writer = BatchWriter(self, bid)
            try:
                yield writer
            except BaseException as exc:
                writer.abort(f"aborted: {type(exc).__name__}")
                raise
            if not writer.published and not writer.held:
                writer.abort("closed without publishing")

    def _commit_publication(self, batch_id: str, entries: list[tuple[Any, ...]]) -> int:
        cur = self.conn.cursor()
        cur.execute("BEGIN IMMEDIATE")
        try:
            pub_seq = int(cur.execute("SELECT coalesce(max(pub_seq), 0) + 1 FROM batches").fetchone()[0])
            entities = sorted({e[1] for e in entries if e[1]})
            cur.executemany(
                """
                INSERT INTO batch_tables (batch_id, table_name, entity_id, part, completeness, rel_path, sha256, rows)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [(batch_id, *e) for e in entries],
            )
            updated = cur.execute(
                "UPDATE batches SET state = 'published', pub_seq = ?, published_at = ?, entities_json = ? "
                "WHERE batch_id = ? AND state IN ('staging', 'held')",
                (pub_seq, _now(), json.dumps(entities), batch_id),
            ).rowcount
            if updated != 1:
                raise PublicationError(f"batch {batch_id} is not in the staging state")
            cur.execute("COMMIT")
        except BaseException:
            cur.execute("ROLLBACK")
            raise
        return pub_seq

    def _set_state(self, batch_id: str, state: str, note: str | None = None) -> None:
        # A batch that will never publish releases its idempotency key, so a corrected retry of
        # the same submission is accepted; the key is kept in the note for the record.
        release = state in ("failed", "quarantined", "discarded")
        with self.conn:
            self.conn.execute(
                "UPDATE batches SET state = ?, "
                "note = CASE WHEN ? AND idempotency_key IS NOT NULL "
                "THEN coalesce(?, note, '') || ' [idempotency key released: ' || idempotency_key || ']' "
                "ELSE coalesce(?, note) END, "
                "idempotency_key = CASE WHEN ? THEN NULL ELSE idempotency_key END "
                "WHERE batch_id = ? AND state != 'published'",
                (state, release, note, note, release, batch_id),
            )

    def _discard_staging(self, batch_id: str) -> None:
        shutil.rmtree(self.staging_dir / batch_id, ignore_errors=True)

    def _quarantine(self, batch_id: str, files: list[Path], reason: str) -> None:
        for f in files:
            if f.exists():
                dest = self.quarantine_dir / batch_id / f.relative_to(self.parquet_dir)
                dest.parent.mkdir(parents=True, exist_ok=True)
                os.replace(f, dest)
        self._set_state(batch_id, "quarantined" if files else "failed", reason)

    def publish_held(self, batch_id: str, actor: str) -> int:
        """Publish a batch that was held for review (see BatchWriter.hold)."""
        with self.lock.held():
            row = self.batch(batch_id)
            if row is None or row["state"] != "held":
                raise PublicationError(f"batch {batch_id} is not awaiting publication")
            writer = BatchWriter(self, batch_id)
            manifest = json.loads((writer.staging_dir / "manifest.json").read_text(encoding="utf-8"))
            for item in manifest["staged"]:
                writer.staged.append(
                    _Staged(item["table"], item["entity_id"], item["part"], writer.staging_dir / item["staged"],
                            item["final_rel"], item["rows"])
                )
            writer.declared = {(t, e): c for t, e, c in manifest["declared"]}
            pub_seq = writer.publish()
            with self.conn:
                self.conn.execute(
                    "UPDATE batches SET note = coalesce(note || '; ', '') || ? WHERE batch_id = ?",
                    (f"published after review by {actor}", batch_id),
                )
            return pub_seq

    def discard_held(self, batch_id: str, actor: str) -> None:
        with self.lock.held():
            row = self.batch(batch_id)
            if row is None or row["state"] != "held":
                raise PublicationError(f"batch {batch_id} is not awaiting publication")
            self._discard_staging(batch_id)
            with self.conn:
                self.conn.execute(
                    "UPDATE batches SET note = coalesce(note || '; ', '') || ? WHERE batch_id = ?",
                    (f"discarded after review by {actor}", batch_id),
                )
            self._set_state(batch_id, "discarded")

    def recover(self) -> dict[str, int]:
        """Quarantine what an interrupted writer left behind. Idempotent; needs the writer lock.

        - staging directories of batches that never published are removed (their state becomes
          `failed`);
        - batch files in the Parquet tree that no published batch lists (a crash between moving
          files and committing) are moved to `quarantine/` (state `quarantined`).
        """
        report = {"staging_discarded": 0, "orphans_quarantined": 0}
        with self.lock.held():
            published = {r["rel_path"] for r in self.conn.execute(
                "SELECT bt.rel_path FROM batch_tables bt JOIN batches b USING (batch_id) "
                "WHERE b.state = 'published' AND bt.rel_path IS NOT NULL"
            )}
            held = {r[0] for r in self.conn.execute("SELECT batch_id FROM batches WHERE state = 'held'")}
            if self.staging_dir.exists():
                for entry in self.staging_dir.iterdir():
                    if entry.name in held:
                        continue
                    shutil.rmtree(entry, ignore_errors=True)
                    self._set_state(entry.name, "failed", "staging left by an interrupted writer")
                    report["staging_discarded"] += 1
            stale = self.conn.execute("SELECT batch_id FROM batches WHERE state = 'staging'").fetchall()
            for row in stale:
                self._set_state(row["batch_id"], "failed", "interrupted before publication")
            for f in self.parquet_dir.rglob("b-*.parquet"):
                rel = f.relative_to(self.parquet_dir).as_posix()
                if rel in published:
                    continue
                match = re.match(r"^b-(.+)-\d+\.parquet$", f.name)
                batch_id = match.group(1) if match else "unknown"
                self._quarantine(batch_id, [f], "file not listed by any published batch")
                report["orphans_quarantined"] += 1
        return report

    def adopt_legacy_files(self, table: str | None = None) -> str | None:
        """Bring Parquet files written before the catalog existed (`data.parquet`) under it.

        They become one published batch with provenance `legacy-unknown`: who submitted them,
        when, and for which period was not recorded. The originals are copied to
        `<data_dir>/backups/legacy-parquet-<time>/` first. `table` limits the search to one
        table's directory. Returns the batch id, or None.
        """
        root = self.parquet_dir / table if table else self.parquet_dir
        if not root.is_dir():
            return None
        legacy = sorted(p for p in root.rglob("data.parquet") if p.is_file())
        if not legacy:
            return None
        with self.lock.held():
            legacy = sorted(p for p in root.rglob("data.parquet") if p.is_file())
            if not legacy:
                return None
            stamp = _dt.datetime.now(_dt.UTC).strftime("%Y%m%dT%H%M%S%fZ")
            backup = self.data_dir / "backups" / f"legacy-parquet-{stamp}"
            for f in legacy:
                dest = backup / f.relative_to(self.parquet_dir)
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(f, dest)
            bid = f"LEGACY-{stamp}-{uuid.uuid4().hex[:6]}"
            with self.conn:
                self.conn.execute(
                    "INSERT INTO batches (batch_id, state, transport, source, provenance, received_at, note) "
                    "VALUES (?, 'staging', 'legacy', 'canonical', 'legacy-unknown', ?, ?)",
                    (bid, _now(), f"adopted from pre-catalog files; originals copied to {backup}"),
                )
            entries: list[tuple[Any, ...]] = []
            moved: list[Path] = []
            try:
                for n, f in enumerate(legacy):
                    rel_dir = f.parent.relative_to(self.parquet_dir)
                    table = rel_dir.parts[0]
                    entity = rel_dir.parts[1].removeprefix("entity_id=") if len(rel_dir.parts) > 1 else ""
                    if entity == "None":
                        entity = ""
                    final = f.parent / f"b-{bid}-{n}.parquet"
                    rows = pl.scan_parquet(f).select(pl.len()).collect().item()
                    os.replace(f, final)
                    moved.append(final)
                    entries.append(
                        (table, entity, n, ROWS, final.relative_to(self.parquet_dir).as_posix(), _sha256(final), rows)
                    )
                self._commit_publication(bid, entries)
            except BaseException:
                for f in moved:  # put the originals back; nothing was lost
                    with suppress(OSError):
                        os.replace(f, f.parent / "data.parquet")
                self._set_state(bid, "failed", "legacy adoption failed; files left in place")
                raise
            return bid

    # --- reading ------------------------------------------------------------------------------

    def max_pub_seq(self) -> int:
        return int(self.conn.execute("SELECT coalesce(max(pub_seq), 0) FROM batches").fetchone()[0])

    def published_files(self, table: str, max_pub_seq: int | None = None) -> list[PublishedFile]:
        rows = self.conn.execute(
            """
            SELECT bt.rel_path, b.batch_id, b.pub_seq, b.source, b.received_at, bt.entity_id
            FROM batch_tables bt JOIN batches b USING (batch_id)
            WHERE b.state = 'published' AND bt.table_name = ? AND bt.rel_path IS NOT NULL
              AND (? IS NULL OR b.pub_seq <= ?)
            ORDER BY b.pub_seq, bt.entity_id, bt.part
            """,
            (table, max_pub_seq, max_pub_seq),
        ).fetchall()
        return [
            PublishedFile(
                self.parquet_dir / r["rel_path"], r["batch_id"], int(r["pub_seq"]), r["source"], r["received_at"],
                r["entity_id"],
            )
            for r in rows
        ]

    def submitted_tables(self, max_pub_seq: int | None = None) -> dict[str, dict[str, str]]:
        """entity -> table -> how its published batches declared it (`rows`, `declared_empty`)."""
        out: dict[str, dict[str, str]] = {}
        for r in self.conn.execute(
            """
            SELECT bt.entity_id, bt.table_name, bt.completeness
            FROM batch_tables bt JOIN batches b USING (batch_id)
            WHERE b.state = 'published' AND bt.entity_id != '' AND (? IS NULL OR b.pub_seq <= ?)
            ORDER BY b.pub_seq
            """,
            (max_pub_seq, max_pub_seq),
        ):
            tables = out.setdefault(r["entity_id"], {})
            # Rows anywhere make the table populated; a later declared-empty batch does not erase that.
            if tables.get(r["table_name"]) != ROWS:
                tables[r["table_name"]] = r["completeness"]
        return out

    def tables_submitted_for_period(
        self, entity_id: str, start: str, end: str, max_pub_seq: int | None = None
    ) -> set[str]:
        """Tables a published batch declared for `entity_id` (with rows or empty) whose period
        overlaps [start, end). A batch that declared no period is an undated, complete export of
        what the entity had when it was submitted, so it counts for every period."""
        rows = self.conn.execute(
            """
            SELECT DISTINCT bt.table_name FROM batch_tables bt JOIN batches b USING (batch_id)
            WHERE b.state = 'published' AND bt.entity_id = ? AND bt.completeness IN ('rows', 'declared_empty')
              AND (b.period_start IS NULL OR (b.period_start < ? AND b.period_end > ?))
              AND (? IS NULL OR b.pub_seq <= ?)
            """,
            (entity_id, end, start, max_pub_seq, max_pub_seq),
        ).fetchall()
        return {r[0] for r in rows}

    def batch_ids(self) -> set[str]:
        return {r[0] for r in self.conn.execute("SELECT batch_id FROM batches")}

    def batch(self, batch_id: str) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM batches WHERE batch_id = ?", (batch_id,)).fetchone()
        return dict(row) if row else None

    def batch_by_idempotency_key(self, key: str) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM batches WHERE idempotency_key = ?", (key,)).fetchone()
        return dict(row) if row else None

    def overlapping_batches(
        self, entity_id: str, period_start: str, period_end: str, source: str | None = None
    ) -> list[dict[str, Any]]:
        """Published batches of `entity_id` whose declared period overlaps [start, end)."""
        rows = self.conn.execute(
            """
            SELECT * FROM batches
            WHERE state = 'published' AND entity_id = ? AND period_start IS NOT NULL
              AND period_start < ? AND period_end > ? AND (? IS NULL OR source = ?)
            ORDER BY pub_seq
            """,
            (entity_id, period_end, period_start, source, source),
        ).fetchall()
        return [dict(r) for r in rows]

    def batches(self, entity_id: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM batches WHERE (? IS NULL OR entity_id = ? OR entities_json LIKE ?) "
            "ORDER BY received_at DESC LIMIT ?",
            (entity_id, entity_id, f'%"{entity_id}"%', limit),
        ).fetchall()
        return [dict(r) for r in rows]

    def published_manifest(self, max_pub_seq: int | None = None) -> list[dict[str, Any]]:
        """Every published file with its hash: the source snapshot an assessment read."""
        rows = self.conn.execute(
            """
            SELECT b.batch_id, b.pub_seq, bt.table_name, bt.entity_id, bt.part, bt.completeness,
                   bt.rel_path, bt.sha256, bt.rows
            FROM batch_tables bt JOIN batches b USING (batch_id)
            WHERE b.state = 'published' AND (? IS NULL OR b.pub_seq <= ?)
            ORDER BY b.pub_seq, bt.table_name, bt.entity_id, bt.part
            """,
            (max_pub_seq, max_pub_seq),
        ).fetchall()
        return [dict(r) for r in rows]

    def verify(self, max_pub_seq: int | None = None) -> list[str]:
        """Published files that are missing or whose content no longer matches the recorded hash."""
        problems = []
        for entry in self.published_manifest(max_pub_seq):
            if not entry["rel_path"]:
                continue
            path = self.parquet_dir / entry["rel_path"]
            if not path.exists():
                problems.append(f"missing: {entry['rel_path']}")
            elif _sha256(path) != entry["sha256"]:
                problems.append(f"hash mismatch: {entry['rel_path']}")
        return problems


def published_sequence(data_dir: Path | str) -> int:
    """The latest publication sequence of a data directory (0 if it has no catalog), read-only."""
    path = Path(data_dir) / CATALOG_FILE
    if not path.exists():
        return 0
    try:
        conn = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True, timeout=5.0)
        try:
            return int(conn.execute("SELECT coalesce(max(pub_seq), 0) FROM batches").fetchone()[0])
        finally:
            conn.close()
    except sqlite3.Error:
        return -1  # unreadable: never equal to a real sequence, so caches reload
