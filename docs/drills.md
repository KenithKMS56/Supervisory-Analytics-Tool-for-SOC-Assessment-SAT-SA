# Operational drills (Phase 5)

Each drill below was executed on 2026-10-19 on the development machine described in
`docs/benchmarks.md` (Windows 11, Python 3.13.2), against synthetic data in scratch directories.
None used a real deployment's data. The commands are those that were run; the figures are what
they printed. "Not executed" says so.

## 1. Offline installation into a clean environment

```
# online build preparation (downloads the pinned wheels; SATSA_AUDIT=1 would also run pip-audit)
set PYTHON=C:\Program Files\Python313\python.exe
scripts\build_wheelhouse.bat build\wheelhouse            # 37 wheels incl. satsa-0.1.0

# install, with no package index
python -m venv build/oi/.venv
build/oi/.venv/Scripts/python -m pip install --no-index --find-links=build/wheelhouse --require-hashes -r build/wheelhouse/requirements.txt
build/oi/.venv/Scripts/python -m pip install --no-index --no-deps --find-links=build/wheelhouse satsa
build/oi/.venv/Scripts/python -m pip check               # No broken requirements found.
build/oi/.venv/Scripts/satsa version                     # SAT-SA version 0.1.0 (Air-gapped, No AI/ML)
```

- Install time: **64 s**, every wheel hash checked; SAT-SA imported from the new environment's
  `site-packages`, not the source tree.
- From a fresh directory holding only `config/`: `satsa generate-data -n 300`, `satsa ingest`,
  `satsa run --period 2026-H1` completed in **14 s**. `uvicorn satsa.api:app` then answered
  `/healthz` `{"status":"ok"}`, `/readyz` ready (schema version 10 of 10, catalog, disk), and
  served the sign-in page.
- **Not an independent target machine**: same laptop, same OS. That gate stays blocked.

## 2. Backup and verified restore

On the deployment of drill 1 (one run, 10 entities):

```
satsa backup --dest ../backups
satsa restore ../backups/satsa-backup-20261019T160104Z --target ../restored --replay RUN-20261019160045707069-c7eaf1f2
```

| Step | Result |
|---|---|
| Backup (SQLite backup API, Parquet, catalog, secrets, checksum manifest) | 2.9 s, 2.3 MB |
| Restore into a new directory, verify every hash, replay the run | 5.8 s, `Replay of RUN-...: reproduced` |
| Encrypted backup (`--encrypt`, AES-256-GCM), restore with `--replay` | reproduced |
| Encrypted backup with one bit flipped | `Restore refused: Wrong passphrase, or the backup was altered.`; target directory not created |
| Encrypted backup, wrong passphrase | refused the same way; nothing written |

Measured recovery time at this size is under 10 s from backup file to a verified, replayed
instance. It grows with data (backup is a copy of `data/`); no recovery objective is claimed
beyond what was measured.

## 3. Worker killed in the middle of an assessment

`scripts/drill_worker_kill.py`, from a 2,000,000-alert deployment (40 entities), lease 30 s:

```
[    1.4s] queued JOB-20261019160208-7b361da0ea; runs before: 4
[    2.9s] job is running, stage 'assessing'; letting it work for 20 s
[   23.0s] worker 1 killed (exit 1); job: ('running', 'assessing', 1, '2026-10-19T16:02:54...')
[   23.0s] runs now: 4 (a killed assessment must leave none)
[   23.0s] worker 2 started
[  179.1s] job finished: state=succeeded attempts=2; 156 s after the kill
[  179.1s] runs added: [('RUN-JOB-20261019160208-7b361da0ea', 'completed')]
[  179.1s] DRILL PASSED: one completed run, no partial or duplicate run
```

The killed attempt published nothing (a run is written in one transaction at its end). The second
worker took the job once its lease expired and ran it to completion under the same run id.
`tests/test_jobs.py::test_a_killed_worker_process_loses_no_job_and_duplicates_nothing` checks the
same at test scale.

## 4. Full disk and low memory

**Not executed on a real full volume.** The preflight checks are tested by simulating the free
space and free memory the job sees (`tests/test_preflight.py`): an import that could fill the
data volume, or an import or assessment larger than free memory, is refused before it starts,
stages nothing and keeps its upload for a retry.

## 5. Migration of an existing deployment

Migrations v1–v10 are applied and checked on copies of older databases in
`tests/test_migrations.py` (backup taken first, every row kept). Running `satsa migrate` on a real
deployment's data is the owner's step (docs/migrations.md); it was not run here.
