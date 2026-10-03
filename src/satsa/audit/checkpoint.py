"""Signed, verifiable audit checkpoints.

A checkpoint records the state of one hash chain (`audit_log` or `admin_audit_log`) at a moment:
entry count, head hash, hash algorithm, time and tool version. Kept off-box, it lets a later
verification detect what the chain alone cannot (DECISIONS.md ADR-005): removal of the newest
entries and a full recomputation of the chain. Signing it (DECISIONS.md ADR-008) binds it to the
examiner's key, so whoever controls the supervisory host cannot produce a different checkpoint
that matches a rewritten chain.

Format (JSON, UTF-8)::

    {
      "format": "satsa-audit-checkpoint/1",
      "chain": "audit", "table": "audit_log",
      "entries": 442, "head_hash": "<64 hex>", "hash_alg": "sha3_256",
      "created_at": "2026-10-01T10:00:00.000000+00:00", "tool_version": "0.1.0",
      "signature": {"alg": "ed25519", "key_id": "<16 hex>", "value": "<base64>"}
    }

The signature covers the canonical encoding of every field except `signature`
(`json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=True)`), so changing any
recorded value, or the key or algorithm named in the signature block, invalidates it.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from satsa import __version__
from satsa.audit.signing import Signer, Verifier, get_backend
from satsa.store.sqlite import SQLiteStore, utc_now_iso

FORMAT = "satsa-audit-checkpoint/1"
CHAIN_TABLES = {"audit": "audit_log", "admin": "admin_audit_log"}


class CheckpointError(ValueError):
    """The checkpoint file is malformed or does not verify."""


@dataclass(frozen=True)
class CheckpointResult:
    ok: bool
    message: str
    signature_ok: bool | None  # None when the chain check never ran far enough to matter
    chain_ok: bool | None


def key_id(public_key_bytes: bytes) -> str:
    """Short fingerprint of a public key: the first 16 hex digits of its SHA-256."""
    return hashlib.sha256(public_key_bytes).hexdigest()[:16]


def canonical_bytes(payload: dict[str, Any]) -> bytes:
    body = {k: v for k, v in payload.items() if k != "signature"}
    sig = payload.get("signature")
    if isinstance(sig, dict):
        # The algorithm and key named in the signature block are covered too.
        body["signature_meta"] = {"alg": sig.get("alg"), "key_id": sig.get("key_id")}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def build_checkpoint(store: SQLiteStore, chain: str = "audit") -> dict[str, Any]:
    """The current head of `chain`, as an unsigned checkpoint."""
    if chain not in CHAIN_TABLES:
        raise CheckpointError(f"chain must be one of {sorted(CHAIN_TABLES)}")
    table = CHAIN_TABLES[chain]
    verification = store.verify_chain(table)
    if not verification.ok:
        raise CheckpointError(f"refusing to checkpoint a chain that does not verify: {verification.message}")
    head = store.audit_head(table=table)
    return {
        "format": FORMAT,
        "chain": chain,
        "table": table,
        "entries": head.count,
        "head_hash": head.head_hash,
        "hash_alg": head.hash_alg,
        "created_at": utc_now_iso(),
        "tool_version": __version__,
    }


def sign_checkpoint(payload: dict[str, Any], signer: Signer) -> dict[str, Any]:
    signed = {k: v for k, v in payload.items() if k != "signature"}
    signed["signature"] = {"alg": signer.algorithm, "key_id": key_id(signer.public_key_bytes())}
    signed["signature"]["value"] = base64.b64encode(signer.sign(canonical_bytes(signed))).decode("ascii")
    return signed


def dumps(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def load(path: Path | str) -> dict[str, Any]:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise CheckpointError(f"cannot read checkpoint {path}: {exc}") from None
    if not isinstance(payload, dict) or payload.get("format") != FORMAT:
        raise CheckpointError(f"{path} is not a {FORMAT} file")
    for field, kind in (("chain", str), ("entries", int), ("head_hash", str)):
        if not isinstance(payload.get(field), kind):
            raise CheckpointError(f"checkpoint field {field!r} is missing or not a {kind.__name__}")
    if payload["chain"] not in CHAIN_TABLES or payload.get("table") != CHAIN_TABLES[payload["chain"]]:
        raise CheckpointError("checkpoint names an unknown chain or a table that does not match it")
    return payload


def verify_signature(payload: dict[str, Any], verifier: Verifier) -> tuple[bool, str]:
    sig = payload.get("signature")
    if not isinstance(sig, dict) or not isinstance(sig.get("value"), str):
        return False, "checkpoint is not signed"
    # Unknown or reserved algorithm names are refused here, before anything is trusted.
    get_backend(str(sig.get("alg")))
    if sig.get("alg") != verifier.algorithm:
        return False, f"checkpoint was signed with {sig.get('alg')!r}, the public key is {verifier.algorithm!r}"
    expected_id = key_id(verifier.public_key_bytes())
    if sig.get("key_id") != expected_id:
        return False, (
            f"checkpoint was signed with key {sig.get('key_id')}, not with the supplied public key "
            f"({expected_id})"
        )
    try:
        raw = base64.b64decode(sig["value"], validate=True)
    except ValueError:
        return False, "signature value is not valid base64"
    if not verifier.verify(raw, canonical_bytes(payload)):
        return False, "signature does not match the checkpoint contents (modified checkpoint or wrong key)"
    return True, f"signature valid ({verifier.algorithm}, key {expected_id})"


def verify_checkpoint_file(
    store: SQLiteStore, checkpoint_path: Path | str, verifier: Verifier
) -> CheckpointResult:
    """Signature first, then the live chain must match or extend the recorded head."""
    payload = load(checkpoint_path)
    sig_ok, sig_msg = verify_signature(payload, verifier)
    if not sig_ok:
        return CheckpointResult(False, f"Checkpoint signature check failed: {sig_msg}", False, None)
    chain_ok, chain_msg = store.verify_checkpoint(
        payload["entries"], payload["head_hash"], table=CHAIN_TABLES[payload["chain"]]
    )
    if not chain_ok:
        return CheckpointResult(False, f"{sig_msg}; chain check failed: {chain_msg}", True, False)
    return CheckpointResult(True, f"{sig_msg}; {chain_msg}", True, True)
