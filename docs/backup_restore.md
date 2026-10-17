# Backup and restore

## What a backup contains

`satsa backup` writes one self-describing backup:

| Part | Copied how |
|---|---|
| `data/satsa.db`: runs, findings, scores, rule results, decisions, audit chain, identities, jobs, settings | SQLite online backup API (consistent under WAL) |
| `data/catalog.db`: batches and published files | SQLite online backup API |
| Every published Parquet file | file copy, listed in the catalog |
| Staged files of held batches | file copy, so they can still be published or discarded after a restore |
| Inputs of queued or running jobs | file copy |
| `data/secrets/`: pseudonymisation keys | file copy. The one-time setup token is excluded. |
| `config/` | file copy |
| `manifest.json` | SHA-256 and size of every file; schema versions; row counts; publication sequence; code revision |

**Consistency.**
- The catalog's writer lock is held for the whole backup, so no batch is published meanwhile.
  The operational database is copied while that lock is held, so every run in the backup refers
  only to batches in the backup.
- Each run is published in one transaction, so it is either in the copy or not.
- Imports wait for the lock while a backup runs. Reads are unaffected.

## Making one

```bash
satsa backup --dest /mnt/backup-disk                     # a directory
SATSA_BACKUP_PASSPHRASE='...' satsa backup --dest /mnt/backup-disk --encrypt --keep 7
```

- **Encrypted backups.** With `--encrypt` the backup is one `.satsa-backup` file: AES-256-GCM in
  1 MiB chunks, under a key derived from the passphrase with scrypt (N=2^15, r=8, p=1).
  Tampering, reordering or truncation are detected at restore. The passphrase is at least 12
  characters, is not stored anywhere, and **cannot be recovered**. Keep it, under separate
  custody, away from the backup media.
- **Secrets in backups.** A backup holds the pseudonymisation keys. An unencrypted backup must
  therefore be protected like the data volume itself.
- **Where to keep backups.** Write them to a different disk or host from `data/`. `--keep N`
  removes all but the newest N backups in `--dest`.

## Restoring

```bash
satsa restore /mnt/backup-disk/satsa-backup-<time>[.satsa-backup] --target /srv/satsa-new --replay RUN-...
```

`--target` must be a new or empty directory; a restore never overwrites a deployment. In order,
restore:
1. decrypts an encrypted backup, if needed;
2. checks every file against the manifest, and refuses missing, extra or altered files;
3. copies `data/` and `config/` into the target;
4. runs `PRAGMA integrity_check` on both databases;
5. verifies every published file against the restored catalog;
6. compares row counts and the publication sequence with the manifest;
7. with `--replay`, re-evaluates that run in the restored instance and reports whether it
   reproduces (docs/migrations.md, `satsa replay`).

Then start the platform with `/srv/satsa-new` as its working directory: point the Compose data and
config mounts there.

## Recovery objectives

No RPO or RTO is claimed.
- The local drill in `tests/test_backup_restore.py` restores and replays a full demonstration
  deployment in seconds on a laptop.
- Measured objectives on the declared reference hardware come from the Phase 5 drills
  (docs/release_readiness.md).
- The achieved RPO is the interval between scheduled backups.

## Limits

- **Online, not incremental.** Every backup is a full copy.
- **Host-level threats.** Volume encryption, off-host copies and custody of backup passphrases
  are deployment controls.
