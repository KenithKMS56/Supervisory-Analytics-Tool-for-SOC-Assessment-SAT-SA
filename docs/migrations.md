# Data-model migrations and recovery

Every change to stored data goes through a numbered migration. A migration keeps historical
evidence, takes a backup before it runs, and checks its own result. This page lists each
migration, what it changes, and how to recover.

## How migrations run

SAT-SA has three stores. They are always backed up and restored together:

| Store | File | Holds | Migrations |
|---|---|---|---|
| Operational store | `data/satsa.db` | runs, findings, scores, rule results, review queue, feedback, DQ issues, audit chain, identities | `satsa.store.sqlite_migrations.OPERATIONAL_MIGRATIONS` |
| Publication catalog | `data/catalog.db` | submission batches, the Parquet files each batch published, how each table was declared | `satsa.store.catalog.CATALOG_MIGRATIONS` |
| Submitted data | `data/parquet/<table>/entity_id=<E>/b-<batch>-<n>.parquet` | canonical rows, one immutable file per batch, table and entity | none: files are never rewritten |

Migrations run automatically when a store is opened, or explicitly with
`satsa migrate` (below). For each pending migration:

1. If the database already holds data, a consistent copy is written first with SQLite's
   online backup API (safe under WAL) to `data/backups/<db>-pre-v<N>-<UTC time>.db`.
2. The migration runs in one `BEGIN IMMEDIATE` transaction.
3. Before it commits, it is checked:
   - `PRAGMA integrity_check` must pass.
   - `PRAGMA foreign_key_check` must show no violation the database did not already have.
     A legacy database with old dangling references can still be upgraded, but a migration
     may not add one.
   - No table that existed before may lose a row, and no table with rows may disappear.
4. On any failure the transaction is rolled back and the error names the backup. The version
   is recorded in `schema_migrations(version, name, applied_at, backup_path)` only on success.

Migrations are additive or copy-then-swap. A legacy row keeps every value it had. Columns
the row never had are `NULL`, which the UI and reports show as "not recorded", never as a
value.

## Operational store (`satsa.db`)

Version 0 is the layout of commit `47f10c9`, created by `SQLiteStore._init_tables` and the
idempotent `_ensure_migrations`.

### v1: evidence coverage and rule results

- New table `rule_results(run_id, entity_id, rule_id, rule_version, domain, state, reason,
  missing_inputs_json, population, min_sample, findings_count)`. It has one row per run,
  entity and rule. `state` is one of `finding`, `assessed_clear`, `insufficient_evidence`,
  `degraded` or `not_applicable`.
- `domain_scores.score` becomes nullable. A domain that no rule could assess is unknown, not
  0. The table is rebuilt copy-then-swap with new columns `rules_applicable`, `rules_assessed`
  and `coverage_status`. Every legacy row and score is copied unchanged.
- New nullable columns on `entity_scores`: `classification_status`, `rules_applicable`,
  `rules_assessed`, `rules_degraded`, `rules_insufficient`, `rules_not_applicable`,
  `coverage`, `data_request_priority`, `missing_inputs_json`.
- New table `applicability_decisions`. A rule becomes `not_applicable` for an entity only
  through one of these audited decisions, which carry a reason, author, rule version,
  optional expiry, and revocation.

Legacy runs have no rule results and no coverage. The UI shows their coverage as "not
recorded". They are never reclassified after the fact.

### v2: run snapshots and analytical fingerprint

- New nullable columns on `runs`:
  - `fingerprint`
  - `selection_json`: mode, window, source snapshot and reference date
  - `source_snapshot`: the catalog publication sequence the run read
  - `data_fingerprint_json`
  - `environment_json`: code revision, `uv.lock` hash, Python/DuckDB/Polars versions
  - `published_at`
- New table `run_config_snapshots(run_id, key, path, sha256, content)`. It holds the full text
  of every configuration file a run read, so the finding page and reports can show the
  parameters that produced a result. Legacy runs have no snapshot, and pages say so instead
  of showing the current configuration as if it applied.

### v3: durable jobs and worker heartbeats (Phase 2)

- New table `jobs`: state, stage, parameters, input fingerprint, attempts, lease and heartbeat,
  cancellation flag, result or structured error.
  - A unique partial index keeps at most one queued or running job per input fingerprint.
- New table `worker_heartbeats`: which worker processes are alive and what they run.
- Both tables are new and empty. No existing row changes.
- To undo: the previous release ignores both tables. Drop them, or restore the pre-v3 backup.
- Jobs still queued when downgrading are not run by the previous release. Their uploaded files
  stay in `data/jobs/` and can be uploaded again.

### v4: deployment settings and mode (Phase 2)

- New key-value table `deployment_settings`: mode (`production` or `demo`), how the mode was
  chosen, deployment name, time zone, retention, and setup state.
- A database created before v4 is recorded as `production`, with `mode_origin` saying so. It
  gets `setup_completed_at = "before deployment modes"`, because its accounts already exist.
  Nothing else changes, and existing accounts keep their passphrases.
- Behaviour change in the same release:
  - `seed_default_admin` no longer re-promotes and re-activates the `admin` account on every
    start.
  - Production databases are no longer seeded with demonstration accounts.
  - Neither change touches existing rows.
- To undo: the previous release ignores the table.

### v5: service credentials, session idle timeout, entity retirement (Phase 2)

- New table `service_credentials`: name, verifier, scopes, entity scope, created, expires,
  revoked, last used and use count (docs/api_credentials.md).
- New nullable column `last_seen_at` on `sessions` and `admin_sessions`. Existing sessions count
  idle time from their creation, so a session older than the idle timeout ends at its next use.
- New table `entity_retirements`. The "Delete" action on the upload page now retires an entity
  instead of deleting it:
  - **Before:** it erased the entity's findings and scores from every run and removed its Parquet
    files.
  - **Now:** nothing is erased. The entity is left out of future runs, and each run records the
    excluded ids in `selection.retired_entities`, so replay reproduces it.
  - **To undo a retirement:** `satsa entity reinstate <id>`.
- To undo the migration: the previous release ignores the new table and columns.

### v6: administrator MFA (Phase 2)

- New tables:
  - `mfa_factors`: TOTP secret, enrolment, last step used;
  - `mfa_recovery_codes`: SHA-256 hashes and when each was used.
- New nullable column `admin_sessions.mfa_verified_at`.
- Behaviour change: in production deployments (`SATSA_ADMIN_MFA` unset), administrators must
  enrol a second factor at their next sign-in before the Admin Portal opens.
- Existing administrator sessions have no verification, so they are sent to enrolment too.
- To undo: the previous release ignores the tables. Or set `SATSA_ADMIN_MFA=optional` to stop
  enforcing MFA without removing the factors.

### v7: examiner workflow (Phase 3)

- New tables (docs/examiner_workflow.md):
  - `cases`: one row per supervisory concern (entity x rule), with state, owner, outcome and
    `version` for concurrent edits. A partial unique index allows one open case per entity
    and rule.
  - `case_events`: the immutable history. Triggers refuse `UPDATE` and `DELETE`.
  - `case_attachments`: evidence files, content-addressed under `data/case_files/`. Immutable,
    by trigger.
  - `corrective_actions`: what the entity must do, by when, and how it will be verified.
  - `case_packages`: explanation requests exported and responses imported.
  - `blind_samples`, `blind_tasks`: assigned blind-review samples with seed and provenance.
- Existing rows are untouched. Review-queue dispositions (`feedback`) are record-level triage and
  are not turned into cases: no case is invented from a past click. Blind reviews made before
  this version (`blind_reviews`) are kept and listed for analysts as not blinded to the
  selection.
- Behaviour changes:
  - The review-queue labels "Escalated to Statutory Notice" and "CSE Explanation Requested"
    are now "Confirmed concern" and "More data needed". The stored values `confirmed` and
    `needs_more_data` are unchanged.
  - `POST /blind-review/submit` and `/blind-review?entity_id=` are gone. Blind review works
    through assigned tasks.
- To undo: the previous release ignores the new tables. Cases and blind tasks recorded since
  then are not visible to it, but they remain in the database and in backups.

### v8: maintenance windows, rule exceptions, peer comparisons, saved views (Phase 4)

- New tables (docs/analytics_context.md):
  - `maintenance_windows`: approved maintenance for an entity (all assets or one asset) over
    inclusive dates, with requester, approver (a `CHECK` refuses self-approval) and revocation.
  - `rule_exceptions`: a documented, time-limited exception for one entity and rule: scope,
    reason, evidence reference, mandatory expiry, approver (`CHECK`: not the requester),
    revocation.
  - `peer_comparisons`: per run and entity, the cohort the run used: members, excluded entities
    with their reason, fallback level, denominator, minimum support and strength.
  - `saved_views`: a user's named portfolio filters.
- New columns:
  - `findings.exception_id` and `rule_results.exception_id`: the exception a finding was
    recorded under.
  - `systemic_findings.assessable_count`, `group_size`, `comparison_affected`,
    `comparison_assessable`, `p_value`, `q_value`: the provider-level lead's figures.
- Existing rows are untouched. Runs recorded before v8 have no `peer_comparisons` rows; the
  entity and finding pages say "not recorded for this run" and label any peer median derived
  from today's data as such. Their findings have no exception and their provider leads show
  "not recorded" for the new figures.
- Analytical tables (DuckDB, rebuilt in memory from the published Parquet files on every
  start) gain the optional asset columns `in_service_from` and `in_service_to`. Files published
  before this version have neither and load with both empty, which means "in service
  throughout". No Parquet file is rewritten.
- Behaviour changes:
  - NS03 v1.1.0 reads hours in the entity's own time zone, NS01 v1.1.0 does not count approved
    maintenance or out-of-service days as silence, and NS06 v1.1.0 does not count an asset
    outside its in-service dates as a ghost. Rule versions changed, so case verification (which
    compares the same rule version) does not treat a v1.0.0 result as comparable evidence for
    a v1.1.0 result.
  - Applicability decisions, maintenance windows and exceptions resolve "as of" the run's start
    time, and a replay uses the recorded run's time, so revoking one later does not change
    what a replay of an older run sees.
  - The HTML reports and CSV exports take `run_id` (default: the latest run). The findings CSV
    holds one run's findings, as the UI does; it used to hold every run's. `satsa export`
    writes the latest run's.
- To undo: the previous release ignores the new tables and columns. Context recorded since
  then has no effect under it; it remains in the database and in backups.

### v9: pilot evaluation (Phase 5)

- New columns:
  - `blind_samples.replica_of`: the sample this one repeats for a second, independent
    examiner (same entities, kinds and provenance; its own seeded order).
  - `blind_tasks.opened_at`: when the task's examiner first opened it; with `submitted_at` it
    is the reviewer's time.
- New tables (satsa.validate.pilot, docs/shadow_pilot_runbook.md Part B):
  - `pilot_protocols`: a frozen evaluation protocol: the run and configuration hash the
    thresholds were frozen at, the seeded calibration / held-out split of entities, the review
    budget. Never edited; a new protocol has a new name.
  - `pilot_adjudications`: a third examiner's label for an entity two reviewers disagreed on
    (one per protocol, run and entity).
- Existing rows are untouched. Samples drawn before v9 have no replica; tasks opened before v9
  have no opening time, so the evaluation counts their review time as "not recorded".
- To undo: the previous release ignores the new columns and tables; blind review works as
  before. Protocols and adjudications remain in the database and in backups.

## Publication catalog (`catalog.db`)

### v1: publication catalog

Two tables. `batches` holds one row per submission with state, entity, source, transport,
declared period, content hash, idempotency key, parent batch, submitter, and received and
published times. `batch_tables` records each published file with its SHA-256 and row count,
and each table a batch declared `declared_empty` or `rejected`.

### v2: pseudonymisation key per batch (Phase 2)

Adds the nullable column `batches.pseudonym_key_id`. It holds the id of the key a batch was
pseudonymised with (docs/key_management.md). Batches published before v2 keep `NULL`, which
means "not recorded". This is additive: no existing row changes.

### Pseudonymisation key moved into `data/secrets/` (Phase 2)

This is not a schema change, but it is a change to deployment state. The first ingestion or
`satsa migrate` imports a legacy `.satsa_salt` from the working directory into
`data/secrets/pseudonym_keys.json` as key version 1, byte for byte. The legacy file is left in
place.

To undo: delete `data/secrets/pseudonym_keys.json`. The previous release reads `.satsa_salt`
again.

If data exists but neither file does, ingestion stops instead of generating a key. See
docs/key_management.md.

### Adopting Parquet files written before the catalog

Before the catalog, each entity's rows lived in one `data.parquet` per table, rewritten in
place on every ingest. When a store is opened, any such file is adopted once:

1. The originals are copied to `data/backups/legacy-parquet-<UTC time>/`, keeping their
   relative paths.
2. Each file is renamed to `b-LEGACY-<time>-<id>-<n>.parquet`. Its content is not changed.
3. One published batch lists the files, with `provenance = legacy-unknown`: who submitted
   them, when, and for which period was never recorded. Its source is `canonical`, so a later
   corrected submission of the same records replaces them by business key.

If adoption fails part-way, the renamed files are moved back to `data.parquet` and the batch
is marked `failed`, so nothing is lost.

The legacy manifest in `satsa.db` (`submitted_tables`) still says which tables an entity
declared before the catalog existed. The runner uses it for batches the catalog does not know.

## Running the migration on an existing deployment

Do this on a copy first. The development work for this change ran only on temporary copies,
never on a deployment's own `data/`.

```
# 1. stop the web app, the Admin Portal and any CLI job
# 2. take a full copy of the data directory
cp -r data data.before-migration
# 3. migrate explicitly (also happens on the next start); prints what was done
uv run satsa migrate --data-dir data --db-path data/satsa.db
# 4. check the result
uv run satsa verify-data --data-dir data
```

`satsa migrate` applies pending migrations to both databases, adopts legacy Parquet files,
quarantines anything an interrupted writer left behind, and verifies the hash of every
published file. It prints the versions applied and the backup paths.

## Recovery

| Situation | Recovery |
|---|---|
| A migration failed | Nothing was applied: the transaction was rolled back. Fix the cause in the error, then start again. The pre-migration backup is in `data/backups/`. |
| The migrated database is wrong | Stop SAT-SA. Replace `data/satsa.db` (or `catalog.db`) with `data/backups/<db>-pre-v<N>-<time>.db`, delete its `-wal` and `-shm` files, and run the previous release. |
| Legacy Parquet adoption must be undone | Stop SAT-SA. Delete `data/parquet` and `data/catalog.db`, then copy `data/backups/legacy-parquet-<time>/` back to `data/parquet/`. |
| A writer crashed mid-submission | Nothing to do. Staged files are discarded and orphan batch files are moved to `data/quarantine/<batch>/` the next time anything publishes, or with `satsa recover`. Readers never saw them. |
| `PseudonymKeyMissing` at ingestion or migration | `data/secrets/` was not restored or `.satsa_salt` was lost. Restore it from a backup (docs/key_management.md). Do not create a new key unless the old one is truly gone. |
| A published file is missing or altered | `satsa verify-data` lists it. The loader skips a missing or unreadable file with a logged warning and does not drop the rest of the table. Restore the file from a backup; its SHA-256 is in `batch_tables`. |

## Developer rules for a new migration

- Append a `Migration(version, name, apply)` with the next version number. Never edit or
  reorder one that has shipped.
- Use `conn.execute` only. Do not use `executescript`, which commits and would escape the
  migration's transaction.
- Do not drop a column or table that holds evidence. Copy-then-swap instead.
- Add a test that builds the previous layout with data, opens it, and checks that the
  migration ran, a backup exists, and every legacy row is still there
  (`tests/test_migrations.py`).
- Document it here with its recovery path.
