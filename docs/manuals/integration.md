# Integration manual

For engineers who deliver a CSE's SOC data to SAT-SA, by API, by file upload, or from a
product export. The contracts behind this page:

| Contract | Page |
|---|---|
| Columns and meaning of every table | `docs/data_requirements.md` |
| Binding, periods, idempotency, corrections, versions, limits | `docs/data_contract.md` |
| Service credentials | `docs/api_credentials.md` |
| Product mappings (Splunk ES, ServiceNow SIR, TheHive 5, Cortex XSIAM) | `docs/connectors.md` |
| What each connector has been verified against | `docs/connector_compatibility.md` |
| Machine-readable API schema | `/openapi.json` and `/docs` on a running instance (signed-in session; served offline) |

SAT-SA is a periodic supervisory tool, not a feed. A CSE submits **one batch per review
period**, after the fact. Corrections are new batches that name the batch they correct.

## 1. The submission API (`POST /api/v1/submissions`, API version 1.1)

**Authenticate with a service credential**, never a browser session:

```
Authorization: Bearer satsa_sc_<id>_<secret>
```

An administrator issues it for named entities, with an expiry of 1–365 days
(`docs/api_credentials.md`). It is shown once; SAT-SA keeps only a verifier. A batch for an
entity outside the credential's scope gets `403`.

**Body** (JSON, at most `SATSA_MAX_API_BODY_MB`, default 64 MiB; the cap is enforced on the
bytes received, with or without a `Content-Length`):

```json
{
  "entity_id": "CSE-01",
  "period": "2026-Q3",
  "alerts": [{"alert_id": "A-1", "rule_id": "R-7", "category": "malware", "severity_orig": "high",
              "severity_final": "high", "asset_id": "HOST-9", "created_at": "2026-07-02T10:00:00Z"}],
  "cases": [], "assets": [], "closures": [], "escalations": [], "workflow_events": [],
  "case_alert_links": [], "remediations": [], "external_reports": [], "log_source_daily": [],
  "detection_rules": [], "declared_kpis": [], "sla_policies": [],
  "declared_empty": ["escalations"],
  "revision_of": null,
  "idempotency_key": "cse01-2026-q3-v1",
  "run_assessment_now": true
}
```

- `period`: `2026`, `2026-Q1`..`Q4`, `2026-H1`/`H2` or `2026-01`..`12`. It is normalised to a
  UTC range, so overlapping labels (`2026-02` inside `2026-Q1`) are recognised.
- Every row's `entity_id`, if present, must equal the batch's. Otherwise the whole batch is
  rejected.
- A section that is neither submitted nor in `declared_empty` is treated as **not submitted**,
  and the rules that need it report *insufficient evidence* rather than a clean result. Declare
  a section empty only when the CSE really had no such records in the period.
- Timestamps: ISO 8601, stored in UTC. In the canonical layout a value without an offset is
  taken as UTC; a product mapping states its source's zone (`timezone:`) for such values.

**Responses**

| Status | Meaning | What to do |
|---|---|---|
| 200, `idempotent_replay: false` | Stored as `batch_id`; with `run_assessment_now`, an assessment is queued as `assessment_job_id` | Poll `GET /api/v1/jobs/{assessment_job_id}`; the run id is in `result.run_id` once it has succeeded |
| 200, `idempotent_replay: true` | The same batch was already received; nothing stored again | Nothing; safe to retry after a timeout |
| 401 | Credential missing, wrong, expired or revoked | Get a new credential |
| 403 | Entity outside the credential's scope | Use the entity's own credential |
| 409 | Same idempotency key with different content, or the period overlaps a published batch | For a correction, set `revision_of` to the batch being corrected |
| 413 | Body too large | Split the period, or ask for a higher cap |
| 422 | Validation failed; **nothing was stored** | Fix every entry in `errors` (`table`, `field`, `row`, `value`, `reason`; for a blocking data-quality check also `check`, `count` and sample `records`) and resend |

The API is versioned in `docs/data_contract.md` ("API change log"). A field is never removed or
reinterpreted without a new version and a stated migration path.

## 2. File upload

Analysts upload CSV, TSV, Excel, JSON or a ZIP of them on the **Upload** page (`/upload`),
choosing the **target entity** and the **period**. The upload is an import job:

- a clean submission is published and assessed;
- one with rejected rows, unreadable files or unreadable values, or a problem a blocking
  data-quality check finds (a missing required field, a repeated alert id, a severity, status or
  disposition the taxonomy does not list: `docs/data_contract.md`, "Blocking checks"), is
  **held**. The analyst sees why, and publishes it as is (the rejected rows stay out) or
  discards it.

Tick **Check only** to see what a submission would give before sending it for real (per file:
rows that would be stored, filtered or rejected; the data-quality issues; which rules the
entity could be assessed on). Nothing is published. From the shell: `satsa ingest --check-only`.

Limits: 1024 MiB in total; at most 2000 ZIP members; 4096 MiB expanded; no member compressed
more than 200× (if over 1 MiB). A member path that leaves the archive is refused before
anything is extracted. Stored file names keep only portable characters.

## 3. Product exports and connectors

A product export does not need reshaping. Pick its mapping and name the entity, because an
export does not say which CSE it belongs to:

```
satsa ingest --data-dir <export dir> --source splunk --entity CSE-07
satsa ingest --data-dir <export dir> --mapping my_mapping.yaml --entity CSE-07
```

On the Upload page, an export is recognised by its columns where its mapping declares them.
**Every shipped mapping is verified only against hand-built fixtures**
(`docs/connector_compatibility.md`). Check the ingest report of the first real export: it names
every column and table that did not map, and the rules that therefore cannot be assessed.

A new mapping is a YAML file in `config/mappings/`. The conformance suite
(`tests/test_connector_conformance.py`) states what any mapping must do: load, ingest its
fixture into one published batch, keep only UTC timestamps, store no personal identifier, and
account for every row.

## 4. Privacy at ingestion

People (alert closers, workflow actors, case owners) are pseudonymised with the deployment's
key. Closure free text is redacted: only its hash, its length and hashed word shingles are
kept, never the text. Columns outside the canonical layout are dropped. This happens in one
ingestion service for every transport.
