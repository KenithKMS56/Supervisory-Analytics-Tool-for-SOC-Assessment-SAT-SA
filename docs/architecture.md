# SAT-SA Architecture & System Design

> **Supervisory Notice:** *Indicators requiring supervisory review; not a compliance determination.*

The **Supervisory Analytics Tool for SOC Assessment (SAT-SA)** is an offline, deterministic analytical tool built for the **National Critical Information Infrastructure Protection Centre (NCIIPC)** use case in PS SIH26157. It assesses how Critical Sector Entities (CSEs) ran their Security Operations Centres (SOCs) over a review period, using the periodic batch submissions the CSEs provide. It uses no machine learning.

Every statement below was checked against the code in the quality pass of October 2026 (mismatches and their resolution: `docs/CHANGES_quality_pass.md`) and again on 2026-10-20, after the product brief's five phases (`docs/release_notes.md`): storage, jobs, run records and roles were rewritten then.

---

## 1. Core Principles

1. **No AI/ML.** Findings come from SQL queries over DuckDB tables and deterministic rule predicates with configurable thresholds, some compared against a peer cohort. NS03 and EG11 flag robust z-score (median/MAD) outliers against the peer cohort; IQR and CUSUM/EWMA exist in `satsa/peers/` but no rule uses them (DECISIONS.md ADR-001).
2. **Offline operation and data minimisation.**
   - Both portals bind to `127.0.0.1` unless `SATSA_HOST` (or `--host`) says otherwise (`satsa/serving.py`). Inside the container they listen on `0.0.0.0` so Docker can publish the ports; `docker-compose.yml` publishes them on the host's `127.0.0.1` unless `SATSA_BIND_ADDRESS` is set. `Containerfile` (the single-portal image) hard-codes `--host 0.0.0.0` for the same reason; publish it with `-p 127.0.0.1:8000:8000`.
   - SAT-SA makes no outbound network calls. As **best-effort defence in depth**, `satsa/netguard.py` installs an in-process egress guard when either portal starts (FastAPI lifespan, so `satsa serve`, `satsa admin`, `entrypoint.py` and a bare `uvicorn satsa.api:app` are all covered): Python socket connections to anything other than loopback raise `EgressBlockedError`. It is **not** a sandbox: native code that bypasses Python's `socket` module is not covered, and DNS lookups are not blocked. `SATSA_ALLOW_EGRESS=1` turns it off (logged). The host firewall and the physical air gap remain the real controls. Separately, `SourceAdapter.read_api` refuses any non-loopback URL before opening a socket.
   - Analyst handles, closers and case owners are pseudonymised with HMAC-SHA256 under a versioned local 32-byte key (`data/secrets/pseudonym_keys.json`, `satsa/keys.py`, `ingest/pseudonymise.py`; docs/key_management.md). Free text is regex-redacted (e-mail, IPv4, full-form IPv6, host names, digit runs of 8 or more; `ingest/redact.py`), closure comments are kept only as a normalised hash and hashed 3-word shingles, and unknown source columns are dropped.
3. **Tamper-evident audit trail.** Ingests, assessment runs, configuration changes and examiner actions are appended to `audit_log` (and administrative actions to `admin_audit_log`) in SQLite, each entry hash-chained to the previous one (SHA3-256 for new entries, legacy SHA-256 entries still verify). The chain detects an edited, inserted, deleted or reordered entry anywhere except the end. Removal of the newest entries, or a full recomputation of the chain by someone with write access, is only detectable against a checkpoint kept off-box: `satsa audit checkpoint --sign` writes one signed with Ed25519 and `satsa audit verify --checkpoint --pubkey` checks it (DECISIONS.md ADR-004, ADR-005, ADR-008). The trail is tamper-evident, not tamper-proof.

---

## 2. Component Architecture

```mermaid
flowchart TD
    subgraph Sources [CSE periodic submission]
        S1[Canonical CSVs or ZIP bundle]
        S2[JSON batch: POST /api/v1/submissions]
        S3[Product exports: Splunk ES, ServiceNow SIR, TheHive 5]
    end

    subgraph Ingest [Ingestion: satsa.ingest]
        AD[SourceAdapter: csv, json/ndjson, sqlite, loopback REST]
        MAP[SourceMapping: config/mappings/*.yaml]
        NORM[TaxonomyNormaliser]
        PSEUDO[Pseudonymiser: HMAC-SHA256]
        REDACT[Redactor: regex masks, hashed shingles]
        DQ[DQ checks: blocking ones hold or reject]
    end

    subgraph Jobs [Job worker: satsa worker]
        JOBQ[Durable job queue: leases, heartbeats, retries]
    end

    subgraph Storage [Storage]
        PQ[(Parquet: immutable batch files, table/entity_id=ID/b-BATCH-n.parquet)]
        CAT[(Publication catalog data/catalog.db: batches staged, held, published)]
        SQLITE[(SQLite data/satsa.db: runs, per-rule results, config snapshots, cases, hash-chained audit)]
    end

    subgraph Core [Assessment: satsa.rules, satsa.scoring]
        DUCK[In-memory DuckDB, threads=1]
        PEERS[PeerResolver cohorts]
        RULES[20 rules EG01-EG12, NS01-NS08 + systemic detector]
        SCORER[ScoringEngine: noisy-OR domains, risk index]
        QUEUE[ReviewPrioritiser: cited records + random controls]
        SCAN[Anomaly scan: unscored leads]
        PRIO[Control and process ranking]
    end

    subgraph Present [Presentation]
        API[FastAPI :8001 SAT-SA, :8000 Admin Portal]
        UI[Jinja2 UI + vendored ECharts]
        REP[HTML, PDF, CSV reports]
    end

    S1 --> JOBQ
    S2 --> AD
    S3 --> MAP --> AD
    JOBQ --> AD
    AD --> NORM --> PSEUDO --> REDACT --> DQ
    DQ --> PQ
    DQ --> CAT
    DQ --> SQLITE
    CAT --> DUCK
    PQ --> DUCK --> PEERS --> RULES --> SCORER --> QUEUE --> SQLITE
    PEERS --> SCAN --> SQLITE
    SCORER --> PRIO --> API
    SQLITE --> API
    DUCK --> API
    API --> UI
    API --> REP
```

---

## 3. Data Flow and Storage

1. **Ingestion and privacy** (`satsa/ingest/`):
   - `SourceAdapter` reads CSV (via Polars), JSON or NDJSON, a table from an SQLite export, or a **loopback-only** REST endpoint. `satsa ingest` reads every table of an SQLite database export (`.db`, `.sqlite`, `.sqlite3`) as if it were a file named after the table, and `satsa ingest --api-config` stages loopback REST endpoints as files and ingests them through the same checks. There are no product-specific adapter classes: product exports (Splunk ES, ServiceNow SIR, TheHive 5) are translated by a YAML `SourceMapping` (`ingest/mapper.py`, `config/mappings/cse_splunk.yaml`, `cse_servicenow.yaml`, `cse_thehive.yaml`), selected with `satsa ingest --source splunk|servicenow|thehive --entity <id>`. What each export can and cannot supply is in `docs/connectors.md`.
   - `TaxonomyNormaliser` maps severity and disposition labels into the canonical vocabulary of `satsa/models/canonical.py` (15 tables: `entity`, `asset`, `log_source_daily`, `detection_rule`, `alert`, `case`, `case_alert_link`, `workflow_event`, `escalation`, `closure`, `remediation`, `external_report`, `declared_kpi`, `sla_policy`, `submission_batch`).
   - A canonical CSV table is normalised column by column (`ingest/columnar.py`): column aliases, the entity-ID checks, pseudonymisation, taxonomy mapping and comment redaction are Polars expressions, and the per-value functions (HMAC, taxonomy lookup, redaction) run once per distinct value. Anything that path cannot reproduce exactly (a column of mixed types, two alias columns for one field, JSON, product exports through a mapping) is normalised row by row in chunks of 100,000 (`CHUNK_ROWS`), as before. `tests/test_columnar_ingest.py` checks that both give identical stored tables, ingest results and DQ issues. Pseudonymisation and redaction are described in Section 1.
   - Every transport (web upload, JSON API, CLI, connectors) goes through this one ingestion service. A submission bound to an entity (the upload's target, the API batch's `entity_id`) refuses rows naming another entity; its period label is normalised to a UTC range so overlapping labels (`2026-02`, `2026-Q1`) are recognised; an idempotency key makes a resent batch a no-op and a different one with the same key a conflict (`docs/data_contract.md`).
   - The data-quality checks (`ingest/dq_checks.py`; `FrameDQ` during ingest, with the same results as `DQValidator`) record required-field gaps, duplicate IDs, values the taxonomy does not recognise, alert-ID sequence gaps, null rates and orphaned references in `dq_issues`. The checks named in `config/data_quality.yaml` (shipped: format errors only) hold a web upload for an analyst to publish or discard and reject an API submission; the others are reported and kept as evidence (`docs/data_contract.md`, "Blocking checks"). The close-before-create check reads text timestamps (CSV and JSON submissions) the way the store loads them (`text_timestamp_sql` in `store/duckdb.py`: a UTC offset is applied, text without one is taken as UTC), so it reports exactly the alerts the rules see as closed before they were created. A submission manifest records which tables each entity sent, so a rule whose table was never submitted is reported as not assessed.

2. **Parquet store and publication catalog** (`satsa/store/duckdb.py`, `satsa/store/catalog.py`):
   - Submitted data is **never rewritten**. Each submission is an immutable *batch*: its tables are staged, checked, moved into the Parquet tree as new files named after the batch (`data/parquet/{table}/entity_id={entity_id}/b-{batch}-{n}.parquet`) and marked `published` in one short transaction in `data/catalog.db`. Readers load only files of published batches, so nobody sees half a submission; files left by a crash are moved to `data/quarantine/`. A held batch stays staged until an analyst publishes or discards it.
   - A correction is a new batch naming the one it revises. Record versions are kept side by side and the store selects the latest published version of each business record, so a revised alert is counted once and older runs can still be replayed on the data they saw.
   - For an assessment, the published records of the assessment window are loaded into an in-memory DuckDB database (`scoring/selection.py` selects by period; the period is not just a label). The web app keeps one loaded store in `AnalyticsCache`, refreshed when a publication or a run completes (checked at most every 2 s).
   - DuckDB is pinned to **one thread** (`PRAGMA threads=1`): parallel floating-point aggregation can differ in the last bits between runs and flip a threshold comparison, which would break the reproducibility guarantee. More cores therefore do not shorten an assessment. Measured timings are in `docs/benchmarks.md`.

3. **State store** (`satsa/store/sqlite.py`, `data/satsa.db`, WAL mode, numbered migrations v1-v10 with a backup first: `docs/migrations.md`):
   - Runs, findings and evidence, domain and entity scores, review queues, examiner dispositions, blind-review verdicts, identities and sessions, the admin activity feed (`live_events`, not chained; ADR-006) and the two hash-chained audit logs.
   - Per run: one result per entity and rule (`rule_results`: finding, assessed clear, degraded, insufficient evidence or not applicable), the peer cohorts used, and a full snapshot of the configuration (`run_config_snapshots`). The run's analytical fingerprint covers every configuration file, the published batches it read, the window and the code version, so `satsa replay <run_id>` re-runs it and reports whether it reproduces.
   - Supervisory cases (state machine, immutable history, second-examiner sign-off, corrective actions), rule-configuration versions (draft, approved by another person, active, retired), pilot protocols and labels.

4. **Jobs** (`satsa/jobs/`): imports and assessments are queued as durable jobs and run by one `satsa worker` process, not inside web requests. A job holds a lease renewed by a heartbeat; a worker that dies leaves an expired lease, and the next worker retries or fails the job, so nothing runs twice. Before starting, a job checks free disk and memory against the measured need.

---

## 4. Analytical Method

- **Execution Gaps (EG01–EG12):** fast closures, closures without investigation, missing escalations, template closures, repeat alerts without root cause, metric gaming and SLA hugging, implausible analyst throughput, unacknowledged escalations, stale cases, KPI reconciliation gaps, disposition extremes, skipped containment.
- **Negative Space (NS01–NS08):** silent critical assets, missing alert categories, low night-time activity, high/critical true positives with no case, dormant detection rules, ghost inventory, missing external reports, missing months.
- **Systemic detector** (`rules/systemic.py`): the same rule firing on 3 or more entities that share a third-party SOC provider in one run.
- **Scoring** (`scoring/scorer.py`):
  - Rule score: strength beyond the threshold × rule weight × sample-size factor (shown as *evidence support*), $\text{Score} = \text{strength} \times \text{weight} \times \min(1, n / n_{\min})$.
  - Domain score: noisy-OR over the rule scores in each of 8 capability domains, $S_d = 100 \times \left(1 - \prod (1 - s_i/100)\right)$. A domain none of whose rules could be assessed has an **unknown** score, not zero.
  - Evidence coverage: an entity whose submission lets too few rules run is classed *Insufficient Evidence*, never *Low*; a critical finding still sets its band.
  - Entity risk index: $(1 - w_b) \times$ the weighted mean of the 8 domain scores $+\ w_b \times$ a breadth score (10 points per distinct rule triggered, capped at 100), with $w_b$ = `breadth_weight` in `config/scoring.yaml` (default 0.10).
  - Review queue (`scoring/prioritiser.py`): per entity, records cited by findings (highest accumulated score first, up to 70% of the queue size) plus a severity-stratified random control sample.
  - Controls and processes (`scoring/control_priorities.py`): rules ranked by how many entities failed them, then severity; the eight domains ranked by how many entities score 50 or more.
- **Exploratory anomaly scan** (`peers/anomaly_scan.py`, `config/anomaly.yaml`): about 40 operational rates per entity, flagged as peer outliers (robust z of 3.5 or more against the cohort) or time shifts (CUSUM against the entity's first three months). Leads are stored per run and shown, but **not scored**: no severity, no effect on the risk index or review queue (DECISIONS.md ADR-007).

Full rule logic: `docs/analytics_methodology.md`.

---

## 5. Deployment and Security Topology

```mermaid
graph LR
    subgraph Host [Supervisory host, offline]
        CLI["CLI: satsa"]
        ADMIN["Admin Portal: uvicorn satsa.admin.app, 127.0.0.1:8000"]
        SATSA["SAT-SA: uvicorn satsa.api, 127.0.0.1:8001"]
        WORKER["Job worker: satsa worker"]
        FILES["data/parquet, data/catalog.db, data/satsa.db, data/secrets, reports/"]
    end

    ADMINUSER["NCIIPC administrator"] -->|local browser| ADMIN
    OPERATOR["NCIIPC analyst / examiner"] -->|local browser| SATSA
    CLI --> FILES
    ADMIN --> FILES
    SATSA --> FILES
    WORKER --> FILES
```

- **Processes and ports:** the Admin Portal serves on `:8000`, SAT-SA on `:8001`, and the job worker has no port (`entrypoint.py` starts all three; `satsa admin`, `satsa serve` and `satsa worker` start one each). A production deployment starts empty and is set up once with a one-time token; demo data and default accounts exist only in an isolated, labelled demo mode. Keys and configuration live under `data/`, so `satsa backup` / `satsa restore` move a deployment whole. Optional TLS via `SATSA_TLS_CERT` + `SATSA_TLS_KEY` (`docs/deployment_ops.md` Section 1.3).
- **No CDN:** all front-end assets (Apache ECharts, CSS) are vendored in `satsa/ui/static` and `satsa/admin/static`; `tests/test_offline_hardening.py` scans every template and static file and requests every GET route under a socket guard.
- **Roles:** SAT-SA admits two roles, `analyst` (ingest, runs, tuning, raw alerts, audit ledger) and `examiner` (review decisions, cases, blind review, dossiers, rule-change approval). Administrators use the Admin Portal only, with offline TOTP MFA (`docs/functional_design.md` Section 2). Separation of duties is between accounts: a case decision is signed off, and a rule change approved, by someone other than its author. The JSON API takes scoped, expiring, revocable service credentials. Every cookie-authenticated change is CSRF-checked, and every response carries a content-security policy.
- **Rule changes:** a threshold change is a draft until someone other than its author approves it, then an analyst puts it in force and the previous version is retired (`docs/rule_governance.md`). A signed rule pack (a `.tar.gz` of configuration files, a manifest of their SHA-256 hashes and an HMAC-SHA256 signature; key from `SATSA_RULEPACK_SECRET`, no built-in key; `bundle/rules_signer.py`) is recorded as approved by its signature.
