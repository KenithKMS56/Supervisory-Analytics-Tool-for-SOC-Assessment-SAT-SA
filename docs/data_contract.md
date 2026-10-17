# Submission data contract

This page says how SAT-SA accepts, binds, versions and selects submitted SOC data. The column
template of each table is in `docs/data_requirements.md`. Migrations and recovery are in
`docs/migrations.md`.

## One ingestion service for every transport

| Transport | Entry point | Policy |
|---|---|---|
| File upload (web) | `POST /upload` | `if_clean` |
| JSON batch API | `POST /api/v1/submissions` | `strict` |
| CLI | `satsa ingest` | `auto` |
| Local REST connector | `satsa ingest --api-config` | `auto` |

All four go through `IngestionPipeline.ingest_directory`. The pipeline:

1. reads each file;
2. maps the columns to the canonical layout, using the source mapping for product exports;
3. pseudonymises people: alert closers, workflow actors and case owners;
4. redacts closure free text and keeps only its hash, length and shingles;
5. keeps canonical columns only, so a stray `analyst_phone` column is never stored;
6. validates timestamps exactly as the store reads them;
7. runs the DQ checks;
8. publishes one immutable batch.

There is no second write path.

### Publication policy

| Policy | A submission with rejected rows, unreadable files or unreadable timestamps |
|---|---|
| `auto` | Rows that pass are published. The rest are reported as DQ issues. |
| `strict` | Nothing is stored. The response is HTTP 422 with `errors`, one entry per problem: `table`, `field`, `row` (1-based record number in that table's section), `value` and `reason`, plus an exact `error_count`. |
| `if_clean` | The batch is staged but held unpublished. An analyst then chooses **Publish as is** (rejected rows stay out) or **Discard** under *Upload → Held submissions*. Both decisions are audited. |

A held batch is invisible to every assessment until it is published.

## Entity binding

A submission bound to an entity takes its entity from the API batch's `entity_id`, or from
the upload's target entity. In a bound submission:

- a row without `entity_id` is given the bound entity;
- a row naming another entity is rejected (`entity_mismatch`) and never stored under either
  entity. Under `strict` the whole batch is rejected.

An unbound upload with no target entity, or a CLI ingest, takes each row's own `entity_id`.
A row without one is rejected, never stored outside the entity partitions.

## Periods, idempotency and corrections

- A submission may name the review period it covers: `2026`, `2026-Q1`, `2026-H1` or
  `2026-03`. The API requires one. Labels are normalised to a half-open UTC range
  `[start, end)`, so `2026-02` and `2026-Q1` are known to overlap.
- **Idempotency**: an API batch's key is the client's `idempotency_key`, or
  `sha256(entity | period start | period end | revision_of)`.
  - The same key with the same canonical content returns HTTP 200 with
    `idempotent_replay: true` and the original `batch_id`. Nothing is stored twice.
  - The same key with different content returns HTTP 409.
- **Overlap**: a new API batch whose period overlaps a published batch of the same entity
  and source returns HTTP 409, unless `revision_of` names the batch it corrects.
- **Corrections**: a correction is a new batch with `parent_batch_id`. The earlier batch is
  never modified; see "Record versions".

## Declaring what was submitted

How each table stands for an entity in an assessment decides whether a rule can be
assessed:

| Status | Meaning | Rules that need the table |
|---|---|---|
| present | rows in the assessed selection | run |
| declared empty | submitted with no rows: a header-only file, or `declared_empty` in the API | run; absence is a real signal (`rule_dependency_empty` notes it) |
| omitted | never submitted | `insufficient_evidence` |
| rejected | submitted but could not be stored | `insufficient_evidence` |
| stale | windowed assessment; the table has no rows for the window and no batch whose period covers the window declared it | `insufficient_evidence` |

A batch that states no period is taken as a complete, undated export of what the entity
had. It counts for every period.

## Record versions

Each published batch is a set of immutable Parquet files. A later batch replaces an earlier
batch's version of a record by business key, within one entity and source system:

| Table | Business key |
|---|---|
| alert | alert_id |
| case | case_id |
| asset | asset_id |
| escalation | esc_id |
| closure | ref_id |
| remediation | ticket_id |
| detection_rule | rule_id |
| case_alert_link | case_id, alert_id |
| external_report | incident_id, reported_to |
| log_source_daily | asset_id, source_type, date |
| declared_kpi | period, metric, severity |
| sla_policy | severity |
| workflow_event | none: each distinct event is kept once |

Rows of one batch that share a key are all kept as submitted, and ingestion reports them as
duplicate ids. The `entity` record keeps the newest non-null value per attribute.

Earlier versions stay on disk. An assessment records the publication sequence it read (its
source snapshot), so it can be replayed exactly after corrections arrive.

## Assessment selection

See `satsa.scoring.selection`. A period assessment reads:

- alerts created in the window;
- cases open in it (the backlog is carried in);
- events in the window or about a selected record.

What happened after the window ends is masked: an alert closed after the quarter is open at
the end of the quarter. Records with no timestamp in a time-anchored table are left out and
counted in the run manifest (`selection_report.undated_excluded`).

An assessment without a period, or with a label that names none (`GOLDEN`), reads all
submitted data and says so: "all submitted data (cumulative, no period filter)".

## Limits (web upload)

| Limit | Default | Setting |
|---|---|---|
| Total upload size | 1024 MiB | `SATSA_MAX_UPLOAD_MB` |
| ZIP members | 2000 | `SATSA_MAX_ZIP_ENTRIES` |
| ZIP expanded size | 4096 MiB | `SATSA_MAX_ZIP_UNCOMPRESSED_MB` |
| Compression ratio per member over 1 MiB | 200× | fixed |

Member names are validated before anything is extracted.
