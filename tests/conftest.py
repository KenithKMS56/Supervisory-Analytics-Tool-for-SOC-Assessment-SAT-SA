"""Shared test setup.

Seeded default accounts must choose a new passphrase at first login (see
tests/test_first_login_password_change.py). The rest of the suite exercises the portals
as operators who have already done that, signing in with the seeded passphrases, so here
the seeding helpers are wrapped to lift the requirement right after seeding. This lives
in the tests only: the application has no switch that turns the requirement off.

Tests of the requirement itself ask for the `first_login_enforced` fixture, which puts
the real behaviour back.
"""

import sqlite3
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
SHARED_DB = Path("data/satsa.db")


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

# The shared working database may have been seeded by the CLI before the tests started.
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
    if not _shared_db_flagged or not SHARED_DB.exists():
        return
    conn = sqlite3.connect(SHARED_DB, timeout=30)
    try:
        with conn:
            conn.executemany(
                "UPDATE identities SET force_password_change = 1 WHERE username = ?",
                [(u,) for u in _shared_db_flagged],
            )
    finally:
        conn.close()


@pytest.fixture
def first_login_enforced(monkeypatch: pytest.MonkeyPatch) -> None:
    """Seed and start-up behave as in a real deployment for this test."""
    for name, real in _REAL.items():
        monkeypatch.setattr(SQLiteStore, name, real)
