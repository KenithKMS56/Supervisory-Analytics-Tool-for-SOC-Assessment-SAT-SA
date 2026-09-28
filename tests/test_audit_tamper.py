"""Audit hash-chain tamper tests, including HONEST tests of what the chain cannot detect.

Each mutation is applied to a fresh temp store holding 10 entries and must make
verification fail while pointing at the affected row. Two further tests confirm
the documented limits (DECISIONS.md ADR-005): truncating the newest rows, or
recomputing the whole chain, still "verifies" -- and a checkpoint recorded
earlier with `satsa audit head` catches both.
"""

import sqlite3
import uuid

import pytest
from typer.testing import CliRunner

from satsa.cli import app as cli_app
from satsa.store.sqlite import (
    HASH_ALG_CURRENT,
    HASH_ALG_LEGACY,
    SQLiteStore,
    compute_chain_hash,
)

N = 10
COLS = "log_id, ts, action, actor, details_json, prev_hash, curr_hash, hash_alg"


@pytest.fixture
def store(tmp_path):
    s = SQLiteStore(tmp_path / "audit.db")
    for i in range(N):
        s.append_audit(action=f"action_{i}", actor=f"actor_{i}", details={"i": i})
    assert s.verify_audit_chain_detailed().ok
    yield s
    s.close()


def _rows(s):
    return [dict(r) for r in s.conn.execute(f"SELECT {COLS} FROM audit_log ORDER BY rowid")]


def _rewrite(s, rows):
    """Replace the table contents with `rows` in the given order."""
    with s.conn:
        s.conn.execute("DELETE FROM audit_log")
        for r in rows:
            s.conn.execute(
                f"INSERT INTO audit_log ({COLS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                tuple(r[c.strip()] for c in COLS.split(",")),
            )


def _set(s, pos, **fields):
    """Update the row at 1-based position `pos`."""
    rows = _rows(s)
    rows[pos - 1].update(fields)
    _rewrite(s, rows)


def _payload(r):
    return ":".join([r["log_id"], r["ts"], r["action"], r["actor"], r["details_json"], r["prev_hash"]])


def mut_details(s):
    _set(s, 5, details_json='{"i": 999}')
    return 5


def mut_actor(s):
    _set(s, 5, actor="mallory")
    return 5


def mut_action(s):
    _set(s, 5, action="nothing_to_see")
    return 5


def mut_ts(s):
    _set(s, 5, ts="2020-01-01T00:00:00.000000+00:00")
    return 5


def mut_swap_curr_hash(s):
    rows = _rows(s)
    rows[4]["curr_hash"], rows[5]["curr_hash"] = rows[5]["curr_hash"], rows[4]["curr_hash"]
    _rewrite(s, rows)
    return 5


def mut_swap_prev_hash(s):
    rows = _rows(s)
    rows[4]["prev_hash"], rows[5]["prev_hash"] = rows[5]["prev_hash"], rows[4]["prev_hash"]
    _rewrite(s, rows)
    return 5


def mut_delete_middle(s):
    rows = _rows(s)
    del rows[4]
    _rewrite(s, rows)
    return 5  # the former 6th row now sits at position 5 with a dangling prev_hash


def mut_insert_forged(s):
    """A forged row with a VALID self-hash, spliced in after row 4."""
    rows = _rows(s)
    forged = {
        "log_id": uuid.uuid4().hex[:16],
        "ts": rows[3]["ts"],
        "action": "grant_admin",
        "actor": "mallory",
        "details_json": "{}",
        "prev_hash": rows[3]["curr_hash"],
        "hash_alg": HASH_ALG_CURRENT,
    }
    forged["curr_hash"] = compute_chain_hash(HASH_ALG_CURRENT, _payload(forged))
    rows.insert(4, forged)
    _rewrite(s, rows)
    return 6  # forged row is self-consistent; the NEXT row no longer links to it


def mut_swap_two_rows_content(s):
    rows = _rows(s)
    for key in ("ts", "action", "actor", "details_json"):
        rows[2][key], rows[6][key] = rows[6][key], rows[2][key]
    _rewrite(s, rows)
    return 3


def mut_relabel_hash_alg(s):
    _set(s, 5, hash_alg=HASH_ALG_LEGACY)
    return 5


def mut_unknown_hash_alg(s):
    _set(s, 5, hash_alg="md5")
    return 5


MUTATIONS = [
    mut_details, mut_actor, mut_action, mut_ts, mut_swap_curr_hash, mut_swap_prev_hash,
    mut_delete_middle, mut_insert_forged, mut_swap_two_rows_content, mut_relabel_hash_alg,
    mut_unknown_hash_alg,
]


@pytest.mark.parametrize("mutate", MUTATIONS, ids=lambda f: f.__name__)
def test_mutation_is_detected_and_located(store, mutate):
    expected_row = mutate(store)
    rows = _rows(store)
    result = store.verify_audit_chain_detailed()
    assert result.ok is False
    assert result.bad_row == expected_row
    assert result.bad_log_id == rows[expected_row - 1]["log_id"]
    ok, msg = store.verify_audit_chain()
    assert ok is False and f"row {expected_row}" in msg


# ---------------------------------------------------------------- documented limits


def test_tail_truncation_is_NOT_detected_by_the_chain_alone(store):
    """Documented limit: dropping the newest rows leaves a consistent, shorter chain."""
    rows = _rows(store)
    _rewrite(store, rows[:-2])
    assert store.verify_audit_chain() == (True, f"Audit chain verified successfully ({N - 2} entries intact).")


def test_recorded_checkpoint_catches_tail_truncation(store):
    head = store.audit_head()
    assert head.count == N and head.hash_alg == HASH_ALG_CURRENT
    # Appending after the checkpoint is fine...
    store.append_audit("later", "actor", {})
    assert store.verify_checkpoint(head.count, head.head_hash)[0] is True
    # ...but truncating below it is caught.
    _rewrite(store, _rows(store)[:-3])
    ok, msg = store.verify_checkpoint(head.count, head.head_hash)
    assert ok is False and "truncated" in msg


def test_full_chain_recompute_is_NOT_detected_but_checkpoint_catches_it(store):
    """Documented limit: an attacker with write access can rebuild every hash."""
    head = store.audit_head()
    rows = _rows(store)
    rows[2]["details_json"] = '{"i": "rewritten"}'
    prev = SQLiteStore.GENESIS_HASH
    for r in rows:
        r["prev_hash"] = prev
        r["curr_hash"] = compute_chain_hash(r["hash_alg"], _payload(r))
        prev = r["curr_hash"]
    _rewrite(store, rows)
    assert store.verify_audit_chain_detailed().ok is True  # chain alone is fooled
    ok, msg = store.verify_checkpoint(head.count, head.head_hash)
    assert ok is False and "mismatch" in msg


def test_audit_head_cli_and_checkpoint_verify(store):
    db = str(store.db_path)
    runner = CliRunner()
    head = store.audit_head()
    out = runner.invoke(cli_app, ["audit", "head", "--db-path", db])
    assert out.exit_code == 0 and head.head_hash in out.output.replace("\n", "")
    ok = runner.invoke(
        cli_app,
        ["audit", "verify", "--db-path", db, "--checkpoint-count", str(head.count),
         "--checkpoint-head", head.head_hash],
    )
    assert ok.exit_code == 0
    _rewrite(store, _rows(store)[:-1])
    bad = runner.invoke(
        cli_app,
        ["audit", "verify", "--db-path", db, "--checkpoint-count", str(head.count),
         "--checkpoint-head", head.head_hash],
    )
    assert bad.exit_code == 1
    # Without a checkpoint the truncated chain still verifies (the documented limit).
    assert runner.invoke(cli_app, ["audit", "verify", "--db-path", db]).exit_code == 0


# ---------------------------------------------------------------- mixed legacy/current chains


def test_mixed_legacy_sha256_and_sha3_chain_verifies(store):
    """Rows keep their own algorithm: old sha256 rows followed by new sha3 rows verify."""
    rows = _rows(store)
    prev = SQLiteStore.GENESIS_HASH
    for r in rows[:5]:  # first half rewritten as genuine legacy sha256 rows
        r["hash_alg"] = HASH_ALG_LEGACY
        r["prev_hash"] = prev
        r["curr_hash"] = compute_chain_hash(HASH_ALG_LEGACY, _payload(r))
        prev = r["curr_hash"]
    for r in rows[5:]:
        r["prev_hash"] = prev
        r["curr_hash"] = compute_chain_hash(r["hash_alg"], _payload(r))
        prev = r["curr_hash"]
    _rewrite(store, rows)
    store.append_audit("after_migration", "actor", {})
    algs = [r["hash_alg"] for r in _rows(store)]
    assert algs[:5] == [HASH_ALG_LEGACY] * 5 and set(algs[5:]) == {HASH_ALG_CURRENT}
    assert store.verify_audit_chain_detailed().ok


def test_pre_migration_database_is_upgraded_in_place(tmp_path):
    """An old audit_log without hash_alg gets the column (default sha256) and keeps verifying."""
    db = tmp_path / "legacy.db"
    conn = sqlite3.connect(db)
    conn.execute(
        "CREATE TABLE audit_log (log_id TEXT PRIMARY KEY, ts TIMESTAMP NOT NULL, action TEXT NOT NULL, "
        "actor TEXT NOT NULL, details_json TEXT NOT NULL, prev_hash TEXT NOT NULL, curr_hash TEXT NOT NULL)"
    )
    prev = SQLiteStore.GENESIS_HASH
    for i in range(3):
        r = {"log_id": f"legacy{i}", "ts": f"2026-01-0{i + 1}T00:00:00+00:00", "action": "run",
             "actor": "system", "details_json": "{}", "prev_hash": prev}
        r["curr_hash"] = compute_chain_hash(HASH_ALG_LEGACY, _payload(r))
        conn.execute("INSERT INTO audit_log VALUES (?, ?, ?, ?, ?, ?, ?)", tuple(r.values()))
        prev = r["curr_hash"]
    conn.commit()
    conn.close()

    s = SQLiteStore(db)
    assert {r[0] for r in s.conn.execute("SELECT hash_alg FROM audit_log")} == {HASH_ALG_LEGACY}
    s.append_audit("post_upgrade", "actor", {})
    assert s.verify_audit_chain_detailed().ok
    assert s.verify_audit_chain_detailed().entries == 4
    s.close()


def test_admin_chain_detects_tampering(tmp_path):
    s = SQLiteStore(tmp_path / "admin.db")
    for i in range(5):
        s.append_admin_audit("USER_CREATED", "nciipc_admin", target=f"user{i}", details={"i": i})
    assert s.verify_admin_audit_chain()[0]
    with s.conn:
        s.conn.execute("UPDATE admin_audit_log SET target = 'someone_else' WHERE rowid = 3")
    ok, msg = s.verify_admin_audit_chain()
    assert not ok and "row 3" in msg
    s.close()
