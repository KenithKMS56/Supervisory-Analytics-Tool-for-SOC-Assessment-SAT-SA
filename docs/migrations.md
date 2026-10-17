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
