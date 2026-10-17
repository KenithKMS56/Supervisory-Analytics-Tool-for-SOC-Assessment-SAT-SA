"""Consistent backup and verified restore of a whole deployment (docs/backup_restore.md).

A backup holds everything a restored instance needs to reproduce its assessments:

- `satsa.db` (runs, findings, scores, decisions, audit chain, identities, jobs, settings) and
  `catalog.db` (batches and published files), each copied with SQLite's online backup API, which
  is consistent under WAL; the files are never copied raw;
- every **published** Parquet file and the staged files of **held** batches;
- the inputs of jobs still queued or running;
- `secrets/` (pseudonymisation keys: without them, new data would not link to old) but not the
  one-time setup token;
- `config/` (rules, scoring, peers ...);
- `manifest.json`: the SHA-256 and size of every file, schema versions, counts and the
  publication sequence.

**Quiescence.** The catalog's writer lock is held for the whole backup, so no batch can be
published meanwhile, and the operational database is copied while it is held. Every run in the
copy therefore refers only to batches that are in the copy. Runs and jobs proceed; a run being
published at that moment is either wholly in the copy or not at all, because it is one
transaction.

**Encryption** (optional): the backup becomes one file. It is a tar stream encrypted with
AES-256-GCM in 1 MiB chunks, under a key derived from a passphrase with scrypt. Each chunk is
authenticated with its index, and the last one is marked, so reordering, truncation and
tampering are all detected. The passphrase is not stored anywhere; keep it apart from the backup
media.

**Restore** goes into an empty directory only. It checks every file against the manifest
before anything is used, then checks both databases' integrity and every published file's hash
against the restored catalog. It can also replay a run, which proves the restored instance
reproduces it.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import shutil
import sqlite3
import struct
import tarfile
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any, BinaryIO

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from satsa.keys import SECRETS_DIR
from satsa.store.catalog import CATALOG_FILE, Catalog
from satsa.store.migrations import backup_database
from satsa.store.sqlite import SQLiteStore

FORMAT = "satsa-backup/1"
MANIFEST = "manifest.json"
MAGIC = b"SATSABK1"
CHUNK = 1 << 20
SCRYPT_N, SCRYPT_R, SCRYPT_P = 1 << 15, 8, 1
EXCLUDED_SECRETS = {"setup_token"}


class BackupError(RuntimeError):
    """The backup could not be made, or a restore refused it (the message says why)."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _now() -> _dt.datetime:
    return _dt.datetime.now(_dt.UTC)


def _copy(src: Path, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dest)


def _snapshot(data_dir: Path, config_dir: Path, out: Path) -> dict[str, Any]:
    """Write the backup's files into `out` (a fresh directory) and return the manifest."""
    catalog = Catalog(data_dir)
    try:
        with catalog.lock.held():
            backup_database(catalog.conn, out / "data" / CATALOG_FILE)
            manifest_files = catalog.published_manifest()
            for entry in manifest_files:
                if entry["rel_path"]:
                    _copy(catalog.parquet_dir / entry["rel_path"], out / "data" / "parquet" / entry["rel_path"])
            held = [b["batch_id"] for b in catalog.batches(limit=100000) if b["state"] == "held"]
            for batch_id in held:
                src = catalog.staging_dir / batch_id
                if src.is_dir():
                    shutil.copytree(src, out / "data" / "staging" / batch_id)
            pub_seq = catalog.max_pub_seq()
            store = SQLiteStore(data_dir / "satsa.db")
            try:
                backup_database(store.conn, out / "data" / "satsa.db")
                schema = [r[0] for r in store.conn.execute("SELECT version FROM schema_migrations ORDER BY version")]
                counts = {t: store.conn.execute(f"SELECT count(*) FROM {t}").fetchone()[0]
                          for t in ("runs", "findings", "entity_scores", "audit_log", "identities", "jobs")}
                active_jobs = [r[0] for r in store.conn.execute("SELECT job_id FROM jobs WHERE state IN ('queued', 'running')")]
            finally:
                store.close()
    finally:
        catalog.close()
    for job_id in active_jobs:
        src = data_dir / "jobs" / job_id
        if src.is_dir():
            shutil.copytree(src, out / "data" / "jobs" / job_id)
    secrets_src = data_dir / SECRETS_DIR
    if secrets_src.is_dir():
        for f in secrets_src.iterdir():
            if f.is_file() and f.name not in EXCLUDED_SECRETS and not f.name.startswith("."):
                _copy(f, out / "data" / SECRETS_DIR / f.name)
    if config_dir.is_dir():
        shutil.copytree(config_dir, out / "config", ignore=shutil.ignore_patterns("__pycache__"))

    files = {
        p.relative_to(out).as_posix(): {"sha256": _sha256(p), "bytes": p.stat().st_size}
        for p in sorted(out.rglob("*")) if p.is_file()
    }
    from satsa.scoring.fingerprint import environment_identity

    manifest = {
        "format": FORMAT,
        "created_at": _now().isoformat(timespec="seconds"),
        "environment": environment_identity(),
        "operational_schema_versions": schema,
        "publication_sequence": pub_seq,
        "published_files": sum(1 for e in manifest_files if e["rel_path"]),
        "held_batches": held,
        "active_jobs": active_jobs,
        "counts": counts,
        "files": files,
    }
    (out / MANIFEST).write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    return manifest


# ---- encryption (chunked AES-256-GCM) ------------------------------------------------------------


def _key(passphrase: str, salt: bytes) -> bytes:
    if len(passphrase) < 12:
        raise BackupError("A backup passphrase needs at least 12 characters.")
    return Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P).derive(passphrase.encode("utf-8"))


def _nonce(prefix: bytes, index: int) -> bytes:
    return prefix + struct.pack(">I", index)


def _encrypt_stream(src: BinaryIO, dest: BinaryIO, passphrase: str) -> None:
    salt, prefix = os.urandom(16), os.urandom(8)
    aead = AESGCM(_key(passphrase, salt))
    dest.write(MAGIC + salt + prefix)
    index = 0
    chunk = src.read(CHUNK)
    while True:
        nxt = src.read(CHUNK)
        final = not nxt
        aad = struct.pack(">I?", index, final)
        sealed = aead.encrypt(_nonce(prefix, index), chunk, aad)
        dest.write(struct.pack(">I?", len(sealed), final) + sealed)
        if final:
            return
        chunk, index = nxt, index + 1


def _decrypt_stream(src: BinaryIO, dest: BinaryIO, passphrase: str) -> None:
    head = src.read(len(MAGIC) + 24)
    if head[: len(MAGIC)] != MAGIC:
        raise BackupError("This is not an encrypted SAT-SA backup.")
    salt, prefix = head[len(MAGIC): len(MAGIC) + 16], head[len(MAGIC) + 16:]
    aead = AESGCM(_key(passphrase, salt))
    index = 0
    while True:
        frame = src.read(5)
        if len(frame) < 5:
            raise BackupError("The encrypted backup is truncated.")
        length, final = struct.unpack(">I?", frame)
        sealed = src.read(length)
        try:
            dest.write(aead.decrypt(_nonce(prefix, index), sealed, struct.pack(">I?", index, final)))
        except Exception as exc:  # cryptography raises InvalidTag
            raise BackupError("Wrong passphrase, or the backup was altered.") from exc
        if final:
            if src.read(1):
                raise BackupError("Unexpected data after the end of the encrypted backup.")
            return
        index += 1


# ---- public API -------------------------------------------------------------------------------


def create_backup(
    data_dir: Path | str = "data",
    dest_dir: Path | str = "backups",
    *,
    config_dir: Path | str = "config",
    passphrase: str | None = None,
) -> Path:
    """Write a backup into `dest_dir`: a directory, or one `.satsa-backup` file when encrypted."""
    data, dest = Path(data_dir), Path(dest_dir)
    if not (data / "satsa.db").exists():
        raise BackupError(f"{data / 'satsa.db'} does not exist: nothing to back up.")
    dest.mkdir(parents=True, exist_ok=True)
    name = f"satsa-backup-{_now().strftime('%Y%m%dT%H%M%SZ')}"
    if passphrase is None:
        out = dest / name
        if out.exists():
            raise BackupError(f"{out} already exists")
        out.mkdir()
        try:
            _snapshot(data, Path(config_dir), out)
        except BaseException:
            shutil.rmtree(out, ignore_errors=True)
            raise
        return out
    target = dest / f"{name}.satsa-backup"
    with tempfile.TemporaryDirectory(dir=dest) as tmp:
        out = Path(tmp) / name
        out.mkdir()
        _snapshot(data, Path(config_dir), out)
        buffer = Path(tmp) / "plain.tar"
        with tarfile.open(buffer, "w") as tar:
            tar.add(out, arcname=name)
        partial = target.with_suffix(".partial")
        with open(buffer, "rb") as src, open(partial, "wb") as enc:
            _encrypt_stream(src, enc, passphrase)
            enc.flush()
            os.fsync(enc.fileno())
        os.replace(partial, target)
    return target


def _verify_tree(root: Path) -> dict[str, Any]:
    manifest_path = root / MANIFEST
    if not manifest_path.exists():
        raise BackupError("The backup has no manifest.json.")
    manifest: dict[str, Any] = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("format") != FORMAT:
        raise BackupError(f"Unknown backup format {manifest.get('format')!r}.")
    present = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()} - {MANIFEST}
    listed = set(manifest["files"])
    if present - listed:
        raise BackupError(f"Files not in the manifest: {sorted(present - listed)[:10]}")
    if listed - present:
        raise BackupError(f"Files missing from the backup: {sorted(listed - present)[:10]}")
    for rel, entry in manifest["files"].items():
        if _sha256(root / rel) != entry["sha256"]:
            raise BackupError(f"{rel} does not match its recorded SHA-256: the backup was altered or damaged.")
    return manifest


def _safe_members(tar: tarfile.TarFile) -> Iterator[tarfile.TarInfo]:
    for member in tar.getmembers():
        name = Path(member.name)
        if name.is_absolute() or ".." in name.parts or not (member.isfile() or member.isdir()):
            raise BackupError(f"Refusing archive member {member.name!r}.")
        yield member


def restore_backup(source: Path | str, target: Path | str, *, passphrase: str | None = None) -> dict[str, Any]:
    """Restore into the empty directory `target` (creating `target/data` and `target/config`).

    Raises BackupError before anything is written to `target` if the backup fails verification."""
    src, dest = Path(source), Path(target)
    if dest.exists() and any(dest.iterdir()):
        raise BackupError(f"{dest} is not empty: restore only into a new, empty directory.")
    with tempfile.TemporaryDirectory() as tmp:
        if src.is_file():
            if passphrase is None:
                raise BackupError("This backup is encrypted: give its passphrase.")
            plain = Path(tmp) / "plain.tar"
            with open(src, "rb") as fh, open(plain, "wb") as out:
                _decrypt_stream(fh, out, passphrase)
            unpacked = Path(tmp) / "unpacked"
            with tarfile.open(plain, mode="r") as tar:
                members = list(_safe_members(tar))  # no absolute paths, '..' or links
                tar.extractall(unpacked, members=members, filter="data")
            roots = [p for p in unpacked.iterdir() if p.is_dir()]
            if len(roots) != 1:
                raise BackupError("The archive should hold exactly one backup directory.")
            root = roots[0]
        elif src.is_dir():
            root = src
        else:
            raise BackupError(f"{src} does not exist.")
        manifest = _verify_tree(root)
        dest.mkdir(parents=True, exist_ok=True)
        for part in ("data", "config"):
            if (root / part).is_dir():
                shutil.copytree(root / part, dest / part)

    report: dict[str, Any] = {"target": str(dest), "created_at": manifest["created_at"],
                              "files_verified": len(manifest["files"])}
    for db in ("satsa.db", CATALOG_FILE):
        conn = sqlite3.connect(dest / "data" / db)
        try:
            result = conn.execute("PRAGMA integrity_check").fetchone()[0]
        finally:
            conn.close()
        if result != "ok":
            raise BackupError(f"Restored {db} failed its integrity check: {result}")
    catalog = Catalog(dest / "data")
    try:
        problems = catalog.verify()
        report["publication_sequence"] = catalog.max_pub_seq()
    finally:
        catalog.close()
    if problems:
        raise BackupError(f"Restored published files do not match the catalog: {problems[:10]}")
    if report["publication_sequence"] != manifest["publication_sequence"]:
        raise BackupError("The restored catalog's publication sequence differs from the manifest.")
    store = SQLiteStore(dest / "data" / "satsa.db")
    try:
        report["counts"] = {t: store.conn.execute(f"SELECT count(*) FROM {t}").fetchone()[0]
                            for t in manifest["counts"]}
    finally:
        store.close()
    if report["counts"] != manifest["counts"]:
        raise BackupError(f"Row counts differ from the manifest: {report['counts']} vs {manifest['counts']}")
    return report


def prune_backups(dest_dir: Path | str, keep: int) -> list[Path]:
    """Delete all but the newest `keep` backups in `dest_dir` (only SAT-SA backups). Returns what went."""
    dest = Path(dest_dir)
    if keep < 1 or not dest.is_dir():
        return []
    found = sorted(p for p in dest.iterdir() if p.name.startswith("satsa-backup-")
                   and (p.is_dir() or p.suffix == ".satsa-backup"))
    removed = found[:-keep] if len(found) > keep else []
    for p in removed:
        if p.is_dir():
            shutil.rmtree(p)
        else:
            p.unlink()
    return removed
