"""Versioned schema migrations for SAT-SA's SQLite databases.

Each database (`satsa.db`, the operational store, and `catalog.db`, the publication catalog of
submitted data) has an ordered list of migrations. A migration runs at most once; the versions
applied are recorded in `schema_migrations` with the time and, when the database already held
data, the path of the backup taken just before the migration ran.

Rules every migration follows (docs/migrations.md):

- It is additive or copy-then-swap. It never drops a column or row that holds historical
  evidence; legacy rows whose provenance cannot be reconstructed are labelled `unknown`.
- It runs in one transaction. A failure rolls the database back to its pre-migration state,
  and the backup taken first is the documented recovery path for anything the transaction
  cannot undo.
- It is followed by checks: `PRAGMA integrity_check`, `PRAGMA foreign_key_check` (no violation
  the database did not already have: a legacy database with old dangling references can still
  be upgraded, but a migration may not add one), and the row count of every table that existed
  before the migration (a migration may add rows, never lose them).
"""

from __future__ import annotations

import datetime as _dt
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    apply: Callable[[sqlite3.Connection], None]


class MigrationError(RuntimeError):
    """A migration failed or a post-migration check did not pass; the database was rolled back."""


def _now() -> str:
    return _dt.datetime.now(_dt.UTC).isoformat(timespec="microseconds")


def _tables(conn: sqlite3.Connection) -> list[str]:
    return [
        r[0]
        for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        )
    ]


def _row_counts(conn: sqlite3.Connection) -> dict[str, int]:
    return {t: int(conn.execute(f'SELECT count(*) FROM "{t}"').fetchone()[0]) for t in _tables(conn)}


def applied_versions(conn: sqlite3.Connection) -> list[int]:
    if "schema_migrations" not in _tables(conn):
        return []
    return [int(r[0]) for r in conn.execute("SELECT version FROM schema_migrations ORDER BY version")]


def backup_database(conn: sqlite3.Connection, dest: Path) -> Path:
    """Consistent copy of a live database with SQLite's online backup API (WAL-safe)."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    target = sqlite3.connect(str(dest))
    try:
        conn.backup(target)
    finally:
        target.close()
    return dest


def apply_migrations(
    conn: sqlite3.Connection,
    migrations: list[Migration],
    db_path: Path | None,
    backup_dir: Path | None = None,
    backup: bool = True,
) -> list[int]:
    """Apply every pending migration in order; return the versions applied.

    `conn` must be in autocommit mode (isolation_level=None). When the database already holds
    rows (and `backup` is true: a database created moments ago has nothing to protect), a backup
    is written to `backup_dir` (default: `<db dir>/backups`) before the first pending migration
    runs.
    """
    versions = [m.version for m in migrations]
    if versions != sorted(set(versions)):
        raise ValueError("migration versions must be unique and ascending")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            applied_at TEXT NOT NULL,
            backup_path TEXT
        )
        """
    )
    done = set(applied_versions(conn))
    pending = [m for m in migrations if m.version not in done]
    if not pending:
        return []

    before = _row_counts(conn)
    backup_path: str | None = None
    has_data = any(n for t, n in before.items() if t != "schema_migrations")
    if backup and has_data and db_path is not None:
        stamp = _dt.datetime.now(_dt.UTC).strftime("%Y%m%dT%H%M%S%fZ")
        folder = backup_dir or (db_path.parent / "backups")
        backup_path = str(
            backup_database(conn, folder / f"{db_path.stem}-pre-v{pending[0].version}-{stamp}{db_path.suffix}")
        )

    applied: list[int] = []
    for migration in pending:
        counts = _row_counts(conn)
        fk_before = _fk_violations(conn)
        conn.execute("BEGIN IMMEDIATE")
        try:
            migration.apply(conn)
            problems = _post_checks(conn, counts, fk_before)
            if problems:
                raise MigrationError(f"migration {migration.version} ({migration.name}): {'; '.join(problems)}")
            conn.execute(
                "INSERT INTO schema_migrations (version, name, applied_at, backup_path) VALUES (?, ?, ?, ?)",
                (migration.version, migration.name, _now(), backup_path),
            )
            conn.execute("COMMIT")
        except BaseException as exc:
            conn.execute("ROLLBACK")
            if isinstance(exc, MigrationError):
                raise
            raise MigrationError(
                f"migration {migration.version} ({migration.name}) failed and was rolled back: {exc}"
                + (f". Pre-migration backup: {backup_path}" if backup_path else "")
            ) from exc
        applied.append(migration.version)
    return applied


def _fk_violations(conn: sqlite3.Connection) -> dict[str, int]:
    out: dict[str, int] = {}
    for row in conn.execute("PRAGMA foreign_key_check"):
        out[row[0]] = out.get(row[0], 0) + 1
    return out


def _post_checks(conn: sqlite3.Connection, counts_before: dict[str, int], fk_before: dict[str, int]) -> list[str]:
    problems: list[str] = []
    integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
    if integrity != "ok":
        problems.append(f"integrity_check: {integrity}")
    for table, n in sorted(_fk_violations(conn).items()):
        if n > fk_before.get(table, 0):
            problems.append(f"foreign_key_check: table {table} has {n} violation(s), {fk_before.get(table, 0)} before")
    after = _row_counts(conn)
    for table, n in counts_before.items():
        if table in after and after[table] < n:
            problems.append(f"table {table} lost rows ({n} -> {after[table]})")
        if table not in after and n:
            # A copy-then-swap migration renames the new table to the old name, so a table
            # with rows that no longer exists at all means data was dropped.
            problems.append(f"table {table} with {n} rows was dropped")
    return problems
