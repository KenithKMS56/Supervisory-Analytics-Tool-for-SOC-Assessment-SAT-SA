"""Shared test setup.

Seeded default accounts must choose a new passphrase at first login (see
tests/test_first_login_password_change.py). The rest of the suite exercises the portals
as operators who have already done that, signing in with the seeded passphrases, so here
the seeding helpers are wrapped to lift the requirement right after seeding. This lives
in the tests only: the application has no switch that turns the requirement off.

The application keeps its state relative to the working directory (`data/`, `reports/`,
`.satsa_salt`). So that the suite never writes to a developer's working database, salt or
reports, it runs from a fresh scratch directory holding copies of the repository inputs that
tests read by relative path (`config/`, `docs/`, `src/` ...). The scratch directory is
bootstrapped the way CI bootstraps a clean checkout (`satsa generate-data`, `satsa ingest`,
`satsa run`), which many tests expect. `SATSA_TESTS_IN_PLACE=1` runs the suite from the current
directory instead, as before, against whatever that directory holds.

Tests of the requirement itself ask for the `first_login_enforced` fixture, which puts
the real behaviour back.
"""

import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from satsa.auth.identities import SEEDED_DEFAULT_PASSPHRASES
from satsa.store.sqlite import SQLiteStore

_SEEDED = tuple(SEEDED_DEFAULT_PASSPHRASES)
_PLACEHOLDERS = ", ".join("?" for _ in _SEEDED)
_REAL = {
    name: getattr(SQLiteStore, name)
    for name in ("seed_default_identities", "seed_default_admin", "flag_unrotated_default_accounts")
}
REPO = Path(__file__).resolve().parent.parent
_INPUT_DIRS = ("config", "demo_data", "docs", "scripts", "src")
_STATE = {".satsa_salt"}  # application state at the top level, never copied
_WORKDIR: Path | None = None
if os.environ.get("SATSA_TESTS_IN_PLACE") != "1":
    _WORKDIR = Path(tempfile.mkdtemp(prefix="satsa-t-"))
    for _name in _INPUT_DIRS:
        if (REPO / _name).is_dir():
            shutil.copytree(REPO / _name, _WORKDIR / _name, ignore=shutil.ignore_patterns("__pycache__"))
    for _entry in REPO.iterdir():
        if _entry.is_file() and _entry.name not in _STATE:
            shutil.copy2(_entry, _WORKDIR / _entry.name)
    os.chdir(_WORKDIR)
    try:
        for _command in (["generate-data"], ["ingest"], ["run"]):
            subprocess.run(
                [sys.executable, "-m", "satsa.cli", *_command],
                check=True,
                capture_output=True,
                env={**os.environ, "PYTHONIOENCODING": "utf-8"},
            )
    except BaseException:
        os.chdir(REPO)
        shutil.rmtree(_WORKDIR, ignore_errors=True)
        raise

# Absolute: by pytest_sessionfinish the working directory is back at the repository, and a
# relative path would then point at the developer's own database instead of this one.
SHARED_DB = Path("data/satsa.db").resolve()


def _lift(conn: sqlite3.Connection) -> None:
    with conn:
        conn.execute(
            f"UPDATE identities SET force_password_change = 0 WHERE username IN ({_PLACEHOLDERS})", _SEEDED
        )


def _seed_default_identities(self: SQLiteStore) -> bool:
    seeded = _REAL["seed_default_identities"](self)
    _lift(self.conn)
    return seeded


def _seed_default_admin(self: SQLiteStore) -> None:
    _REAL["seed_default_admin"](self)
    _lift(self.conn)


SQLiteStore.seed_default_identities = _seed_default_identities  # type: ignore[method-assign]
SQLiteStore.seed_default_admin = _seed_default_admin  # type: ignore[method-assign]
SQLiteStore.flag_unrotated_default_accounts = lambda self: []  # type: ignore[method-assign]

# In place (SATSA_TESTS_IN_PLACE=1), the shared working database may have been seeded by
# the CLI before the tests started.
# Whatever was required there is lifted for the session and put back afterwards.
_shared_db_flagged: list[str] = []
if SHARED_DB.exists():
    _conn = sqlite3.connect(SHARED_DB, timeout=30)
    try:
        _cols = {row[1] for row in _conn.execute("PRAGMA table_info(identities)")}
        if "force_password_change" in _cols:
            _shared_db_flagged = [
                row[0]
                for row in _conn.execute(
                    f"SELECT username FROM identities WHERE force_password_change = 1 "
                    f"AND username IN ({_PLACEHOLDERS})",
                    _SEEDED,
                )
            ]
            _lift(_conn)
    finally:
        _conn.close()


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    if _shared_db_flagged and SHARED_DB.exists():
        conn = sqlite3.connect(SHARED_DB, timeout=30)
        try:
            with conn:
                conn.executemany(
                    "UPDATE identities SET force_password_change = 1 WHERE username = ?",
                    [(u,) for u in _shared_db_flagged],
                )
        finally:
            conn.close()
    if _WORKDIR is not None:
        os.chdir(REPO)
        shutil.rmtree(_WORKDIR, ignore_errors=True)  # plain copies only: nothing links back


@pytest.fixture
def first_login_enforced(monkeypatch: pytest.MonkeyPatch) -> None:
    """Seed and start-up behave as in a real deployment for this test."""
    for name, real in _REAL.items():
        monkeypatch.setattr(SQLiteStore, name, real)
