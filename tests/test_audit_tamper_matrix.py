"""Tamper matrix for the audit chain with signed checkpoints (DECISIONS.md ADR-005, ADR-008).

One test per case. Each records what the hash chain ALONE reports and what a signed checkpoint,
taken before the tampering, reports. Cases 5 and 6 (truncating the newest entries, recomputing
the whole chain) are the documented limits of the chain: it still verifies, and only the
checkpoint catches them. Tamper-evident, not tamper-proof: whoever holds the private key and
the database can still forge both, which is why the key is kept off the supervisory host.
"""

import base64
import json
import os
import subprocess
import uuid

import pytest
from typer.testing import CliRunner

from satsa.audit import checkpoint as cp
from satsa.audit.keys import (
    KeyPermissionError,
    check_private_key_permissions,
    generate_keypair,
    load_signer,
    load_verifier,
    other_readers,
)
from satsa.audit.signing import (
    AlgorithmUnavailableError,
    UnknownAlgorithmError,
    get_backend,
)
from satsa.cli import app as cli_app
from satsa.store.sqlite import HASH_ALG_CURRENT, SQLiteStore, compute_chain_hash

N = 10
COLS = "log_id, ts, action, actor, details_json, prev_hash, curr_hash, hash_alg"


# ------------------------------------------------------------------ fixtures and helpers


@pytest.fixture
def store(tmp_path):
    s = SQLiteStore(tmp_path / "audit.db")
    for i in range(N):
        s.append_audit(action=f"action_{i}", actor=f"actor_{i}", details={"i": i})
    assert s.verify_chain("audit_log").ok
    yield s
    s.close()


@pytest.fixture
def keys(tmp_path):
    return generate_keypair(tmp_path / "keys")


@pytest.fixture
def checkpoint(store, keys, tmp_path):
    """A signed checkpoint of the untouched 10-entry chain, written before any tampering."""
    payload = cp.sign_checkpoint(cp.build_checkpoint(store), load_signer(keys[0]))
    path = tmp_path / "checkpoint.json"
    path.write_text(cp.dumps(payload), encoding="utf-8")
    return path


def _rows(s):
    return [dict(r) for r in s.conn.execute(f"SELECT {COLS} FROM audit_log ORDER BY rowid")]


def _rewrite(s, rows):
    with s.conn:
        s.conn.execute("DELETE FROM audit_log")
        for r in rows:
            s.conn.execute(
                f"INSERT INTO audit_log ({COLS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                tuple(r[c.strip()] for c in COLS.split(",")),
            )


def _payload(r):
    return ":".join([r["log_id"], r["ts"], r["action"], r["actor"], r["details_json"], r["prev_hash"]])


def _rechain(rows):
    """Recompute every prev_hash and curr_hash from the genesis value, as an attacker with
    write access to the database could."""
    prev = SQLiteStore.GENESIS_HASH
    for r in rows:
        r["prev_hash"] = prev
        r["hash_alg"] = HASH_ALG_CURRENT
        r["curr_hash"] = compute_chain_hash(HASH_ALG_CURRENT, _payload(r))
        prev = r["curr_hash"]
    return rows


def _chain_alone(s):
    return s.verify_chain("audit_log")


def _with_checkpoint(s, path, public_key):
    return cp.verify_checkpoint_file(s, path, load_verifier(public_key))


def test_untampered_chain_verifies_against_its_checkpoint(store, keys, checkpoint):
    assert _chain_alone(store).ok
    result = _with_checkpoint(store, checkpoint, keys[1])
    assert result.ok and result.signature_ok and result.chain_ok


# ------------------------------------------------------------------ the matrix, one case each


def test_1_edit_middle_entry_is_detected(store, keys, checkpoint):
    rows = _rows(store)
    rows[4]["details_json"] = '{"i": 999}'
    _rewrite(store, rows)
    alone = _chain_alone(store)
    assert not alone.ok and alone.bad_row == 5
    result = _with_checkpoint(store, checkpoint, keys[1])
    assert not result.ok and result.signature_ok and result.chain_ok is False


def test_2_inserted_entry_is_detected(store, keys, checkpoint):
    rows = _rows(store)
    forged = {"log_id": uuid.uuid4().hex[:16], "ts": rows[3]["ts"], "action": "grant_admin",
              "actor": "mallory", "details_json": "{}", "prev_hash": rows[3]["curr_hash"],
              "hash_alg": HASH_ALG_CURRENT}
    forged["curr_hash"] = compute_chain_hash(HASH_ALG_CURRENT, _payload(forged))
    rows.insert(4, forged)
    _rewrite(store, rows)
    alone = _chain_alone(store)
    assert not alone.ok and alone.bad_row == 6  # the row after the forged one no longer links
    assert not _with_checkpoint(store, checkpoint, keys[1]).ok


def test_3_deleted_middle_entry_is_detected(store, keys, checkpoint):
    rows = _rows(store)
    del rows[4]
    _rewrite(store, rows)
    alone = _chain_alone(store)
    assert not alone.ok and alone.bad_row == 5
    assert not _with_checkpoint(store, checkpoint, keys[1]).ok


def test_4_reordered_entries_are_detected(store, keys, checkpoint):
    rows = _rows(store)
    rows[3], rows[4] = rows[4], rows[3]
    _rewrite(store, rows)
    alone = _chain_alone(store)
    assert not alone.ok and alone.bad_row == 4
    assert not _with_checkpoint(store, checkpoint, keys[1]).ok


def test_5_truncating_the_newest_entries_needs_the_checkpoint(store, keys, checkpoint):
    _rewrite(store, _rows(store)[:7])
    # Documented limit: the shortened chain is internally consistent.
    assert _chain_alone(store).ok
    result = _with_checkpoint(store, checkpoint, keys[1])
    assert not result.ok and result.signature_ok and result.chain_ok is False
    assert "truncated" in result.message


def test_6_full_recompute_of_the_chain_needs_the_checkpoint(store, keys, checkpoint):
    rows = _rows(store)
    rows[2]["actor"] = "mallory"
    _rewrite(store, _rechain(rows))
    # Documented limit: a keyless chain recomputed from genesis verifies.
    assert _chain_alone(store).ok
    result = _with_checkpoint(store, checkpoint, keys[1])
    assert not result.ok and result.chain_ok is False
    assert "history rewritten" in result.message


def test_7_wrong_key_is_rejected(store, keys, checkpoint, tmp_path):
    _, other_public = generate_keypair(tmp_path / "other")
    result = _with_checkpoint(store, checkpoint, other_public)
    assert not result.ok and result.signature_ok is False
    assert "not with the supplied public key" in result.message


def test_7b_wrong_key_with_the_key_id_copied_is_rejected(store, keys, checkpoint, tmp_path):
    """Copying the expected key id into a checkpoint signed by another key still fails."""
    other_private, _ = generate_keypair(tmp_path / "other")
    payload = json.loads(checkpoint.read_text(encoding="utf-8"))
    forged = cp.sign_checkpoint({k: v for k, v in payload.items() if k != "signature"}, load_signer(other_private))
    forged["signature"]["key_id"] = payload["signature"]["key_id"]
    checkpoint.write_text(cp.dumps(forged), encoding="utf-8")
    result = _with_checkpoint(store, checkpoint, keys[1])
    assert not result.ok and result.signature_ok is False


@pytest.mark.parametrize(
    ("field", "value"),
    [("entries", 7), ("head_hash", "0" * 64), ("created_at", "2020-01-01T00:00:00+00:00"),
     ("tool_version", "9.9.9")],
)
def test_8_modified_checkpoint_is_rejected(store, keys, checkpoint, field, value):
    """E.g. lowering `entries` to hide a truncation: the signature no longer matches."""
    payload = json.loads(checkpoint.read_text(encoding="utf-8"))
    payload[field] = value
    checkpoint.write_text(cp.dumps(payload), encoding="utf-8")
    result = _with_checkpoint(store, checkpoint, keys[1])
    assert not result.ok and result.signature_ok is False
    assert "modified checkpoint or wrong key" in result.message


def test_8b_flipped_signature_bytes_are_rejected(store, keys, checkpoint):
    payload = json.loads(checkpoint.read_text(encoding="utf-8"))
    raw = bytearray(base64.b64decode(payload["signature"]["value"]))
    raw[0] ^= 0x01
    payload["signature"]["value"] = base64.b64encode(bytes(raw)).decode()
    checkpoint.write_text(cp.dumps(payload), encoding="utf-8")
    assert not _with_checkpoint(store, checkpoint, keys[1]).ok


# ------------------------------------------------------------------ behaviour around the matrix


def test_appended_entries_extend_the_checkpoint(store, keys, checkpoint):
    store.append_audit(action="later", actor="analyst", details={})
    result = _with_checkpoint(store, checkpoint, keys[1])
    assert result.ok and "1 entries appended since" in result.message


def test_unsigned_checkpoint_is_rejected(store, keys, tmp_path):
    path = tmp_path / "unsigned.json"
    path.write_text(cp.dumps(cp.build_checkpoint(store)), encoding="utf-8")
    result = _with_checkpoint(store, path, keys[1])
    assert not result.ok and "not signed" in result.message


def test_checkpoint_of_a_broken_chain_is_refused(store):
    rows = _rows(store)
    rows[4]["actor"] = "mallory"
    _rewrite(store, rows)
    with pytest.raises(cp.CheckpointError, match="does not verify"):
        cp.build_checkpoint(store)


def test_signer_interface_rejects_an_unknown_algorithm():
    with pytest.raises(UnknownAlgorithmError):
        get_backend("rsa-1024")
    with pytest.raises(UnknownAlgorithmError):
        get_backend("")


def test_ml_dsa_is_reserved_but_not_implemented():
    for name in ("ml-dsa-44", "ml-dsa-65", "ML-DSA-87"):
        with pytest.raises(AlgorithmUnavailableError, match="not implemented"):
            get_backend(name)


def test_checkpoint_naming_an_unknown_algorithm_is_rejected(store, keys, checkpoint):
    payload = json.loads(checkpoint.read_text(encoding="utf-8"))
    payload["signature"]["alg"] = "rsa-1024"
    checkpoint.write_text(cp.dumps(payload), encoding="utf-8")
    with pytest.raises(UnknownAlgorithmError):
        _with_checkpoint(store, checkpoint, keys[1])


def test_keygen_writes_an_owner_only_private_key(keys):
    private_path, public_path = keys
    assert other_readers(private_path) == []
    check_private_key_permissions(private_path)  # does not raise
    assert b"PUBLIC KEY" in public_path.read_bytes()


def test_keygen_never_overwrites_without_force(keys):
    with pytest.raises(FileExistsError):
        generate_keypair(keys[0].parent)
    generate_keypair(keys[0].parent, force=True)


def _grant_everyone_read(path):
    if os.name == "nt":
        subprocess.run(["icacls", str(path), "/grant", "*S-1-1-0:(R)"], check=True, capture_output=True)
    else:
        os.chmod(path, 0o644)


def test_world_readable_private_key_is_refused(keys, store, tmp_path):
    private_path, _ = keys
    _grant_everyone_read(private_path)
    assert other_readers(private_path)
    with pytest.raises(KeyPermissionError, match="Refusing to use private key"):
        load_signer(private_path)
    result = CliRunner().invoke(
        cli_app, ["audit", "checkpoint", "--db-path", str(tmp_path / "audit.db"), "--sign", "--key", str(private_path)]
    )
    assert result.exit_code == 1 and "Refusing to use private key" in result.output


def test_cli_end_to_end_detects_truncation(store, tmp_path):
    runner = CliRunner()
    db = str(tmp_path / "audit.db")
    key_dir = tmp_path / "cli-keys"
    assert runner.invoke(cli_app, ["audit", "keygen", "--out-dir", str(key_dir)]).exit_code == 0
    private_key, public_key = key_dir / "satsa_audit_ed25519.key", key_dir / "satsa_audit_ed25519.pub"
    cp_file = tmp_path / "cli-checkpoint.json"
    made = runner.invoke(cli_app, ["audit", "checkpoint", "--db-path", db, "--sign", "--key", str(private_key), "--out", str(cp_file)])
    assert made.exit_code == 0, made.output
    verify = ["audit", "verify", "--db-path", db, "--checkpoint", str(cp_file), "--pubkey", str(public_key)]
    ok = runner.invoke(cli_app, verify)
    assert ok.exit_code == 0 and "Signed checkpoint verified" in ok.output
    _rewrite(store, _rows(store)[:8])
    assert runner.invoke(cli_app, ["audit", "verify", "--db-path", db]).exit_code == 0  # chain alone
    bad = runner.invoke(cli_app, verify)
    assert bad.exit_code == 1 and "truncated" in bad.output
    # --checkpoint without --pubkey is refused: the signature is always checked.
    assert runner.invoke(cli_app, ["audit", "verify", "--db-path", db, "--checkpoint", str(cp_file)]).exit_code == 2
