![CI](https://github.com/KenithKMS56/Supervisory-Analytics-Tool-for-SOC-Assessment-SAT-SA/actions/workflows/test.yml/badge.svg?branch=hardening/sih26157)
# SAT-SA: Supervisory Analytics Tool for SOC Assessment:
**National Critical Information Infrastructure Protection Centre (NCIIPC)**

**SAT-SA** is an offline, deterministic analytical tool with its own identity management, built for regulatory oversight of Security Operations Centres (SOCs) across Critical Sector Entities (CSEs) in power, banking, telecom, transport, and oil & gas.

The platform provides a unified dual-application architecture:
- **NCIIPC Administration Portal (`http://localhost:8000`)**: Authoritative governance, centralized identity provisioning, critical sector entity and organisation registries, an admin activity feed (operator session monitor of SAT-SA's own users), and administrative cryptographic audit chaining.
- **SAT-SA Supervisory Tool (`http://localhost:8001`)**: Supervisory execution gap detection (**EG01–EG12**), negative space inference (**NS01–NS08**), peer benchmarking, blinded review studios, and statutory compliance dossier exports. It has exactly two operator roles, the **NCIIPC Analyst** and the **NCIIPC Examiner** (see [Two-Role Workflow](#two-role-workflow-analyst--examiner-8001)). Administrators work on `:8000` only.

---

## Architectural Differentiators & Why It Stands Out

Unlike generic dashboards or black-box machine-learning prototypes, SAT-SA is built around explainability, auditability and offline operation:

```
┌───────────────────────────────────────────────────────────────────────────────────┐
│               UNIFIED REGULATORY SUPERVISORY & IDENTITY CONTROL                   │
├─────────────────────────────────────────┬─────────────────────────────────────────┤
│    NCIIPC ADMIN PORTAL (:8000)          │       SAT-SA SUPERVISORY (:8001)        │
│  • Authoritative Identity Provisioning  │  • Deterministic Analytics Engine       │
│  • Org & Critical Sector Registries     │  • 12 Execution Gaps (EG01–EG12)        │
│  • Dynamic Scoping & Role Assignment    │  • 8 Negative Space Inferences (NS)     │
│  • Admin Activity Feed (Operators)      │  • Blinded Review Studio & Bias Defense │
│  • Cryptographic Admin Audit Log        │  • PDF Dossiers & Peer Benchmarking     │
├─────────────────────────────────────────┴─────────────────────────────────────────┤
│                      SHARED PERSISTENT LOCAL BACKEND                              │
│   SQLite Database (Autocommit + WAL)  •  DuckDB Columnar Parquet  •  WebSockets   │
└───────────────────────────────────────────────────────────────────────────────────┘
```

1. **Authoritative Identity & Governance Layer:**
   Centralized administrative control plane where users cannot self-register or select their own role, organisation, or scoped CSE. All identities are authoritatively provisioned by NCIIPC administrators before credentials are issued.
2. **Offline Operation & Data Minimisation:**
   Binds to loopback (`127.0.0.1`) by default. No CDN dependencies or external script calls; Apache ECharts is vendored. SAT-SA makes no outbound network calls, and as **best-effort defence in depth** each portal installs an in-process egress guard (`satsa/netguard.py`) that refuses Python socket connections to anything but loopback. It does not cover native code that bypasses Python sockets and does not block DNS lookups; the host firewall and the air gap remain the real controls. Ingested analyst identities are pseudonymised with HMAC-SHA256 under a local secret salt (`.satsa_salt`; anyone holding the salt can re-derive a known name's pseudonym), and IP addresses, e-mail addresses and host names are masked by deterministic regexes.
3. **Cryptographic Tamper-Evidence:**
   Every batch upload, schema validation, assessment run, rule configuration change, administrative provisioning action, and human examiner disposition is recorded into append-only SQLite logs hash-chained (SHA3-256 for new entries; legacy SHA-256 entries still verify). Editing, inserting, deleting or reordering an entry in the middle of the chain breaks verification; removal of the newest entries or a full recomputation is only caught against an off-box checkpoint, signed with Ed25519 by `satsa audit checkpoint --sign` (DECISIONS.md ADR-005, ADR-008). Tamper-evident, not tamper-proof.
4. **Columnar Analytics, Measured at Scale:**
   DuckDB over Parquet, no database server. On one 4-core / 8-thread laptop (AMD Ryzen 5 7235HS, 23.7 GB RAM) with uniform synthetic data, 5,000,000 alerts (21.4M rows) took **46.6 s to ingest** (5.7 GB peak memory) and **124 s to assess** (3.9 GB peak; assessment time varies widely between runs), recorded 2026-10-02 in [`docs/benchmarks.md`](docs/benchmarks.md). A single in-memory aggregation query is much faster than that (7.6M rows/s at 1M rows, `satsa benchmark`), but scan speed is not end-to-end time.
5. **Cognitive Bias Mitigation (Blinded Review Studio):**
   Includes a double-blind supervisory mode that presents raw operational metrics without showing pre-calculated risk scores, helping examiners reach unbiased conclusions before revealing inter-rater concordance.
6. **Admin Activity Feed (Operator Session Monitor):**
   The NCIIPC Admin Portal shows what SAT-SA's *own operators* are doing -- sign-ins, report downloads, assessment runs, account blocks -- via an admin-only WebSocket (`/ws/activity`) with a polling fallback, plus instant session revocation. This monitors the tool's internal users; it does **not** collect or monitor any CSE security data (SAT-SA only assesses periodic batch submissions, after the fact).

---

## Regulatory Detection Catalog: 20 Detection Rules

SAT-SA evaluates each periodic CSE submission against **12 Execution Gaps** (malfunctions in active workflows) and **8 Negative Space Inferences** (anomalies revealed by what is absent or missing).

### Execution Gaps (EG01–EG12)
| ID | Rule Name | Operational Defect Identified | Severity |
| :--- | :--- | :--- | :--- |
| **EG01** | Fast Closures Without Investigation | $>15\%$ of human High/Critical closures faster than the peer cohort's 5th-percentile close time with $\le 1$ workflow event. | Critical |
| **EG02** | Acknowledged Without Investigation | $>15\%$ of human closures with no investigation event and a closure comment $<25$ characters. | High |
| **EG03** | Missing Escalations | Any Critical True Positive alert with no escalation record (zero tolerance). | Critical |
| **EG04** | Template / Low-Effort Closures | $>25\%$ of human closures in a comment-hash group repeated $\ge 10$ times. | Medium |
| **EG05** | Repeat Alerts Without Root Cause | $\ge 2$ (asset, rule) pairs firing $\ge 8$ times (more where the entity's volume makes 8 repeats likely by chance), always closed benign, with no remediation ticket. | Medium |
| **EG06** | Metric Gaming & SLA Hugging | $\ge 8$ closures by one analyst in one minute, or $>25\%$ of closures in the last 10% of the SLA window. | High |
| **EG07** | Analyst Implausibility | One analyst closing $\ge 30$ alerts in a single hour. | High |
| **EG08** | Escalation Without Follow-Through| $\ge 3$ escalations never acknowledged by Tier-2. | High |
| **EG09** | Backlog & Aging Accumulation | $\ge 3$ cases still open more than 14 days after opening. | Medium |
| **EG10** | KPI Reconciliation Gap | Empirical High/Critical MTTR $>60\%$ above the declared MTTR for the same severities. | Critical |
| **EG11** | Disposition Extremes | 0 true positives, or a false positive/benign rate $\ge 3.5$ robust standard deviations above the peer cohort (fixed $>98\%$ if under 3 comparable peers), given $\ge 200$ alerts. | High |
| **EG12** | Workflow Non-Conformance | $\ge 2$ Critical cases with no containment stage. | High |

### Negative Space Inferences (NS01–NS08)
| ID | Rule Name | Operational Defect Identified | Severity |
| :--- | :--- | :--- | :--- |
| **NS01** | Silent Critical Assets | Monitored assets of criticality $\ge 3$ with $\ge 3$ days (not necessarily consecutive) of zero log events. | Critical |
| **NS02** | Missing Alert Categories | Alert categories reported by $\ge 60\%$ of the peer cohort but completely absent from the entity's alerts. | High |
| **NS03** | Unexpectedly Low / Flat Activity| Night-time (20:00–08:00) share of alerts $\ge 3.5$ robust standard deviations below the peer cohort (fixed $<3\%$ if under 3 comparable peers), given $\ge 100$ alerts. | High |
| **NS04** | Missing Records | $\ge 3$ High/Critical True Positive alerts with no linked case. (ID sequence gaps are an ingest data-quality check.) | High |
| **NS05** | Inactive Rule Coverage | $>40\%$ (and $\ge 5$) of enabled detection rules never fired in the period. | Medium |
| **NS06** | Inventory Reconciliation Gap | $\ge 2$ inventory assets with no log events and no alerts (ghost assets). | High |
| **NS07** | Absent Regulatory Reporting | Any Critical case with no external (NCIIPC/CERT-In) report record; presence only, timeliness not checked. | Critical |
| **NS08** | Submission Completeness Deficit | Alerts cover fewer months than the review period (the months the portfolio submitted, up to 6). | High |

All thresholds except EG03, NS07 and NS08 are configurable in `config/rules.yaml` and on the Tuning page; the values above are the defaults. Full logic: [`docs/analytics_methodology.md`](docs/analytics_methodology.md) Section 3.

### Cross-Entity Systemic Correlation (beyond the 20 per-entity rules)
Unlike EG01-EG12 and NS01-NS08, which each evaluate one entity in isolation, `satsa.rules.systemic`
runs once per assessment and looks ACROSS the whole portfolio: if 3 or more entities sharing the same
third-party SOC provider all trigger the identical rule in the same run, that is surfaced as its own
"systemic gap, possible shared-vendor issue" finding on the portfolio dashboard, separate from any
individual entity's finding cards. See [`docs/analytics_methodology.md`](docs/analytics_methodology.md) Section 3A.

### Exploratory Leads and Review Priorities (beyond the 20 rules)
To surface indicators no rule tests, `satsa.peers.anomaly_scan` computes about 40 operational rates per entity across the eight domains and flags **peer outliers** (robust z $\ge 3.5$ against the peer cohort) and **time shifts** (CUSUM against the entity's first three months). Leads appear on the entity profile and portfolio and at `GET /api/v1/anomalies`; they are **not scored** (no severity, no effect on the risk index or review queue; DECISIONS.md ADR-007). The portfolio also ranks **controls** (rules) and **processes** (domains) for review (`GET /api/v1/priorities`). Method: [`docs/analytics_methodology.md`](docs/analytics_methodology.md) Sections 3B and 4.5.

---

## Interactive Dashboard Views

The application provides a fully server-rendered, responsive web interface:

```
[ Upload & Ingest ]  [ Portfolio Overview ]  [ Alert Explorer ]  [ Blinded Review ]
[ Review Queue ]     [ Rules Catalog ]       [ Rule Calibration] [ Runs & Audit ]
```

1. **Upload & Ingest (`/upload`)**:
   - Onboard new Critical Sector Entities (with custom critical sector support).
   - Permanent database persistence (SQLite entity store) with instant entity deletion.
   - Drag-and-drop periodic batch upload supporting individual CSVs or full submission `.zip` bundles.
   - Schema validation, HMAC pseudonymisation, regex redaction, and automatic Parquet partitioning.
   - Canonical template downloads (pre-formatted CSVs and sample bundles).
2. **Supervisory Portfolio League (`/`)**:
   - Ranked national entity league table sorted by Composite Risk Index (CRI, 0–100).
   - Interactive filtering (e.g. click *"Entities Require Action"* to isolate outlier CSEs).
   - 8-domain capability heatmap: the problem statement's eight capabilities (Threat Detection, Investigation, Escalation, Incident Response, Security Operations, Governance and Oversight, Operational Discipline, Cyber Resilience).
   - HTML and PDF executive dossier export.
3. **National Alert Explorer (`/alerts`)**:
   - Server-side paginated browser of submitted alert records (25 records/page).
   - Cross-filtering by entity, severity, disposition, and search query with live duration tracking.
4. **Blinded Review Studio (`/blind-review`)**:
   - Cognitive debiasing workspace: presents raw empirical metrics (MTTR, SOAR volume, true-positive rates) without scores.
   - Allows examiners to formulate independent assessments before revealing the Inter-Rater Concordance Matrix.
5. **Stratified Supervisory Review Queue (`/queue`)**:
   - Per-entity review queue: records cited by findings (up to 70% of the queue size) plus a severity-stratified random control sample.
   - Examiner disposition logging (`Confirmed`, `Not an Issue`, `Needs More Data`) with persistent record keeping.
6. **Regulatory Rules Catalog (`/rules`)**:
   - Comprehensive interactive directory of all 20 detection rules (EG01–EG12 & NS01–NS08).
   - Filter by rule category, capability domain, and severity with full mathematical logic definitions.
7. **Rule Calibration & Studio (`/tuning`)**:
   - Live threshold tuning sliders for parameters like Fast Closure Threshold ($s$) or Max Inactivity Days.
   - Real-time SHA-256 configuration hash calculation and signed rule-pack export/import (`.tar.gz`).
8. **Entity Deep-Dive Profile (`/entity/{entity_id}`)**:
   - Radar capability chart contrasting the entity against the national peer median.
   - Self-declared vs. empirically computed KPI reconciliation tables.
9. **Transparent Finding Card (`/finding/{finding_id}`)**:
   - Full explainability card displaying rule rationale, exact parameter values, benign explanations, a suggested examiner check (what to verify or request from the entity), and evidentiary drill-down tables.
10. **Audit Trail & Cryptographic Verification (`/audit`)**:
    - Live verification of the tamper-evident audit hash chain (SHA3-256; legacy SHA-256 entries still verify).
    - Run history, configuration hashes, record counts, and execution metrics.

---

## Two-Role Workflow: Analyst → Examiner (`:8001`)

SAT-SA follows the operating model of real regulators: one person operates the pipeline and another makes the regulatory call. Both use the same app at `:8001`, and the interface adapts to the role.

```
[ CSE submits periodic batch ]
              │
              ▼
  1. NCIIPC ANALYST (technical operator)
     • Ingests CSV/ZIP bundles (/upload) or JSON batches (/api/v1/submissions)
     • Runs the DuckDB assessment, calibrates rules (/tuning), signs rule packs
     • Explores raw alerts (/alerts), data quality (/dq), runs & audit ledger (/runs)
              │   findings, scores and review queue stored in the shared database
              ▼
  2. NCIIPC EXAMINER (decision maker)
     • Portfolio heatmap, entity radar vs peer median, plain-language findings
     • Review queue: Escalate to Statutory Notice / Mark as Justified / Request CSE Explanation
     • Blinded review studio; one-click Executive Regulatory Dossier (PDF)
```

| | Analyst | Examiner |
| :--- | :---: | :---: |
| Portfolio, entity profiles, findings, PDF/HTML dossiers | ✔ | ✔ |
| Upload & ingest, assessment runs, rule tuning & rule packs | ✔ | ✘ (403) |
| Alert explorer, data quality, runs & audit ledger, raw CSV exports | ✔ | ✘ (403) |
| Review-queue decisions and blind-review verdicts | ✘ (403) | ✔ |

Separation of duties is deliberate: whoever tunes the rules can't also sign off the findings. Every other role, including NCIIPC administrators and CSE-scoped accounts, is refused at SAT-SA's login.

## NCIIPC Administration & Identity Control (`:8000`)

The **NCIIPC Administration Portal** (`http://localhost:8000`) is a dedicated supervisory governance and identity control plane operating alongside SAT-SA:

```
[ NCIIPC Admin Console ] ──► Authoritative RBAC ──► SAT-SA Supervisory Tool (:8001)
     │
     ├── Users Table (PBKDF2-HMAC-SHA256, Scoped Org & CSE, Status: ACTIVE/BLOCKED)
     ├── Critical Sector Organisation Registry (Sector classification, Status)
     ├── Critical Sector Entity (CSE) Registry (Parent Org mapping)
     ├── Administrative Audit Log (hash-chained prev_hash, SHA3-256)
     └── Admin Activity Feed (Operator Session Monitor) & Remote Session Revocation
```

1. **Authoritative Centralized User Provisioning (`/users`, `/users/create`)**:
   - SAT-SA users cannot self-register or select their own role, organisation, or scoped CSE.
   - The NCIIPC Administrator authoritatively assigns:
     - **Role**: `NCIIPC Super Administrator` (Admin Portal only), `NCIIPC Analyst` or `NCIIPC Examiner` (the two SAT-SA operators), or a CSE-side role (`CSE Administrator`, `SOC Manager`, `SOC Analyst`, `CSE Viewer`).
     - **Organisation**: Parent critical infrastructure authority (e.g. `ORG-POWER`, `ORG-FIN`, `ORG-TELECOM`).
     - **Scoped CSE**: Critical Sector Entity assigned to the user (e.g. `CSE-01 Northern Power Grid`).
   - Dynamic validation ensures the chosen CSE strictly belongs to the assigned organisation.

2. **User Lifecycle & Session Control (`/users/{username}/edit`, `/users/{username}/reset-password`)**:
   - Status toggling (`ACTIVE` vs. `BLOCKED`): Immediately terminates all active sessions across both portals.
   - Credential Reset: Generates random salt, hashes passphrase with 200,000 PBKDF2 iterations, revokes old sessions, and enforces a mandatory `force_password_change` flag.

3. **Critical Sector Entity & Organisation Registries (`/organisations`, `/cses`)**:
   - Authoritative registry for national critical information infrastructure bodies.
   - Registry view showing active CSE count and provisioned analyst count per entity.

4. **Independent Administrative Audit Log (`/audit`)**:
   - Append-only log recording every administrative action (`USER_CREATED`, `ROLE_CHANGED`, `CSE_CHANGED`, `ACCOUNT_BLOCKED`, `PASSWORD_RESET`, `ORGANISATION_CREATED`, etc.).
   - Hash-chained (`prev_hash`; SHA3-256 for new entries) and verifiable on demand via the UI; a signed off-box checkpoint (`satsa audit checkpoint`) also catches removal of the newest entries.

---

## Admin Activity Feed / Operator Session Monitor (`:8000` ↔ `:8001`)

The Admin Portal monitors SAT-SA's own operators (not CSE data). Both applications share one local database:

- **Operational Event Tracking**:
  Records meaningful high-value events into `live_events`:
  - Authentication: `USER_LOGIN`, `USER_LOGOUT`, `LOGIN_FAILED`, `ACCOUNT_BLOCKED`
  - Assessments: `ASSESSMENT_UPLOAD`, `ASSESSMENT_STARTED`, `ASSESSMENT_COMPLETED`
  - Supervisory Investigation: `FINDING_VIEWED`, `REPORT_GENERATED`, `REPORT_DOWNLOADED`
  - Governance: `ROLE_CHANGED`, `CSE_CHANGED`, `ORGANISATION_CREATED`, `CSE_CREATED`
- **Admin-only feed delivery** (both require an administrator session):
  - WebSocket (`ws://localhost:8000/ws/activity`) pushing new operator events.
  - Polling fallback (`/api/activity/stream?since_id=...&limit=...`, limit capped at 200).
  - The feed is supplementary and not hash-chained; security-relevant events are also recorded in the hash-chained audit logs (DECISIONS.md ADR-006).
- **Live Active Operators Widget**:
  Indicator showing signed-in examiners/analysts, their active session start times, assigned CSE scope, and an instant **Revoke & Block** button for incident response.

---

## Detector-Implementation Correctness Check & Benchmarks

> **What this table is:** Section 0 of [`docs/validation.md`](docs/validation.md) explains this in
> full. The rows below (other than throughput and test count) are a **correctness check**, not an
> empirical real-world accuracy benchmark: the synthetic defects are deliberately built to clearly
> exceed each rule's own threshold, so near-100% scores are expected by construction and mainly
> confirm the code implements its documented logic. A scenario with a borderline threshold, an
> ambiguous dual-rule case and a noisy clean entity is run via `satsa validate-stress` -- see
> [`docs/validation.md`](docs/validation.md) Section 2A. Every one of the 20 rules has at least
> one injected defect (enforced by a test). Every tunable threshold (18 rules) is also moved ±20%
> to measure margin: on the primary seed no such move turns a clean entity into a finding. NS03 and EG11 judge
> entities by robust z-score against their peer cohort, and EG05's repeat threshold rises to each
> entity's chance level (Section 4A). Neither scenario is a substitute for the Shadow-Pilot mode
> (Section 5) against real historical examiner findings, which has not yet been run against real
> NCIIPC/CSE data.
>
> **Correction (September 2026):** earlier versions of this table reported 100% precision on the
> primary dataset and ~60% on the stress scenario. The harness only counted false positives on the
> three clean entities and exempted NS05/EG12/EG10; counted honestly, that run's precision was 38%
> (13/34 findings). The stress figure came from generator artifacts. The causes (generator bugs and
> an EG10 severity-mismatch defect) are fixed and precision now counts every finding -- see
> [`docs/validation.md`](docs/validation.md) Section 0.1.

| Metric | Result | Target | Status |
| :--- | :--- | :--- | :--- |
| **Injected Defect Recall** (primary, unambiguous dataset) | **100.0%** (21/21 defects caught) | $\ge 90.0\%$ | Meets target |
| **Entity Rank Precision@7** (primary, unambiguous dataset) | **100.0%** (top-7 entities ranked accurately) | $\ge 90.0\%$ | Meets target |
| **Defect Precision** (primary, unambiguous dataset; every finding counted) | **100.0%** (21 of 21 findings; 0 false positives on any entity) | $\ge 85.0\%$ | Meets target |
| **Stress Scenario Defect Precision** (borderline/ambiguous/noisy, synthetic) | **100.0%** (3 of 3 findings) on the published seed | n/a -- reported for transparency | Synthetic; thresholds known when built |
| **Hard set** (8 other seeds x 3 volumes, and the stress scenario under 20 seeds; `docs/validation_hard_report.md`) | Portfolio: recall **100%** (503/503), precision **100%** (503/503), 0 of 72 clean entities flagged (before three generator faults were fixed: 99.6% and 98.0%). Stress: recall 60/60, precision **93.8%** (60/64); the noisy clean entity trips EG05 in 4 of 20 seeds. | n/a -- reported for transparency | Synthetic. Shows what one seed hides; see `docs/validation_summary.md` |
| **Independent generator** (20 seeds, decoys just under each threshold; `docs/validation_independent_report.md`) | Recall **100%** (487/487), precision **100%**, 0 of 245 decoys flagged; one-line baselines: 6.7-87% precision on the same data | n/a -- reported for transparency | Synthetic; same authors, who knew the thresholds |
| **Review-Effort Lift** (primary dataset) | **19.5x** for the top 25 queue alerts, **12.0x** for the top 50, **5.19x** for the whole 130-alert queue, vs random sampling. (Every 1%/2%/5% budget exceeds the queue, so those all equal 5.19x.) *See docs/validation_report.md Section 4.* | $\ge 5.00x$ | Meets target |
| **Ranking Stability ($\rho$)** (primary dataset) | Spearman $\rho = \mathbf{1.0000}$ ($\pm 20\%$ domain-weight perturbations) | $\ge 0.8500$ | Meets target |
| **Rule Threshold Sensitivity** (primary dataset) | **4 of 66** single-threshold ±20% moves change an outcome, all injected defects built just over their threshold (EG05 pairs, EG07, NS05, NS08's review period). None creates a false alarm on a clean entity on this seed; across the hard set, lowering EG05's pair threshold does. | n/a -- reported for transparency | Margins are synthetic; real calibration needs the pilot |
| **DuckDB Scan Throughput** (one in-memory query, one thread; not an assessment time) | **7,570,338 rows/second** at 1,000,000 rows (`satsa benchmark`, 2026-10-01) | n/a | Scan only; end-to-end figures in the next row |
| **Scale, end to end** (`docs/benchmarks.md`, recorded 2026-10-02) | 5,000,000 alerts (50 entities, 21.4M rows): ingest **46.6 s** (5.7 GB peak), assessment **124 s** (3.9 GB peak); first page after a run 17.4 s, repeats under 0.5 s | n/a | Measured on a 4-core / 24 GB laptop, uniform synthetic data |
| **Automated Test Suite** | **1,130 passed, 0 failed, 33 skipped** (skips: public routes in the RBAC matrix are exercised once, anonymously), incl. property-based tests, Python 3.11 (Windows), 2026-10-02. Statement-and-branch coverage **89.3%**; rules 94-100%, scoring 83-100%, audit-chain store 91%. Linux and CI not run. | 100% passing | Verified locally |

---

## Getting Started & Installation

### Prerequisites
- Docker & Docker Compose (for containerized deployment) **OR** Python **`>=3.11`** (for local CLI development)
- A current web browser

---

### Method 1: One-Click Docker Deployment (Demo; the image has not been built in this project's recorded evidence)

Runs both portals (Admin Portal and SAT-SA, shared RBAC and activity feed) without a local Python environment:

1. **Start the platform:**
   - **Windows One-Click**:
     Double-click `start.bat` or run:
     ```cmd
     start.bat
     ```
   - **Linux / macOS**:
     ```bash
     docker compose up -d --build
     ```

2. **Access the Portals:**
   - **NCIIPC Admin Portal**: [http://localhost:8000](http://localhost:8000)
   - **SAT-SA Supervisory Tool**: [http://localhost:8001](http://localhost:8001)

3. **Default Seeded Credentials:**
   | Username | Assigned Role | Default Passphrase | Accessible Interfaces |
   | :--- | :--- | :--- | :--- |
   | `nciipc_admin` | NCIIPC Super Administrator | `ChangeMe-NCIIPC#2026` | Admin Portal (`:8000`) only |
   | `admin` | Administrator | `ChangeMe-Admin#2026` | Admin Portal (`:8000`) only |
   | `analyst` | NCIIPC Analyst | `ChangeMe-Analyst#2026` | SAT-SA (`:8001`): technical operator workspace |
   | `examiner` | NCIIPC Examiner | `ChangeMe-Examiner#2026` | SAT-SA (`:8001`): executive review workspace |

   > **Upgrading:** the former `supervisor` role becomes `analyst` on startup; the untouched demo account `supervisor` is renamed `analyst` (`ChangeMe-Analyst#2026`), a rotated one keeps its name.

   > **First login:** every seeded account must choose a new passphrase the first time it signs in. Until it does, its session can open the change-password page and nothing else (pages redirect there; APIs and mutating requests return HTTP 403). The new passphrase must be at least 12 characters and cannot be one of the defaults above. Accounts an administrator creates or resets with "force password change" ticked are held to the same rule.

   > **Network exposure:** `docker compose` publishes both ports on `127.0.0.1` only. To reach the portals from another machine, opt in with `SATSA_BIND_ADDRESS=0.0.0.0 docker compose up -d`, and turn on TLS first (`python scripts/generate_selfsigned_cert.py`, then `SATSA_TLS_CERT` / `SATSA_TLS_KEY`). See `docs/deployment_ops.md` Section 1.3.

4. **Stop the platform:**
   - **Windows**: `stop.bat`
   - **Linux / macOS**: `docker compose down`

---

### Method 2: Local Setup with [`uv`](https://github.com/astral-sh/uv)

For an air-gapped machine, install from a wheelhouse instead: [`docs/offline_install.md`](docs/offline_install.md).

1. **Install `uv` (if not already installed):**
   ```bash
   # Linux / macOS:
   curl -LsSf https://astral.sh/uv/install.sh | sh

   # Windows (PowerShell):
   powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
   ```

2. **Clone the repository and sync dependencies:**
   ```bash
   git clone <your-repo-url> satsa
   cd satsa
   uv sync
   ```

3. **Run the full test suite:**
   ```bash
   uv run pytest
   ```

4. **Launch the demo in 4 commands:**
   ```bash
   # 1. Generate synthetic SOC data with ground-truth anomalies
   uv run satsa generate-data --output-dir data/generated --seed 42 --alerts 1500

   # 2. Ingest datasets into local columnar Parquet and SQLite
   uv run satsa ingest --data-dir data/generated/csv --parquet-dir data --db-path data/satsa.db

   # 3. Execute the supervisory assessment engine
   uv run satsa run --period 2026-Q1

   # 4. Launch the web interface
   uv run satsa serve --host 127.0.0.1 --port 8001
   ```

5. **Open your browser:** Navigate to [http://127.0.0.1:8001](http://127.0.0.1:8001).

---

### Method 3: Standard Python `pip` & `venv`

```bash
git clone <your-repo-url> satsa && cd satsa
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install --upgrade pip
pip install -e . --group dev     # dev tools are a dependency group (pip >= 25.1)
pytest
```
Then run the four commands of Method 2 without `uv run`.

---

## Command-Line Interface (CLI) Reference

The `satsa` command provides a complete command suite powered by Typer and Rich:

```bash
Usage: satsa [OPTIONS] COMMAND [ARGS]...

Commands:
  generate-data   Generate a synthetic periodic SOC submission with ground-truth defects.
  ingest          Ingest CSV/JSON/SQLite exports (or --api-config local APIs), apply HMAC masking, build Parquet
                  (--source splunk|servicenow|thehive --entity <id> for a product export).
  run             Execute the supervisory assessment across all entities.
  seed-history    Seed genuine multi-period historical runs for the trend chart.
  serve           Launch the air-gapped web dashboard and REST API (loopback; optional TLS).
  admin           Launch the NCIIPC Administration Portal.
  tls-cert        Create a self-signed TLS certificate offline.
  report          Export supervisory dossiers (HTML, ReportLab PDF, and CSV).
  validate        Run the detector-implementation correctness harness (primary dataset).
  validate-stress Run the harder stress-scenario validation (borderline/ambiguous/noisy).
  validate-independent  Validate on a separately written generator, many seeds, vs naive baselines.
  benchmark       Benchmark DuckDB columnar scan throughput and query latency.
  audit keygen / checkpoint / verify   Key pair; signed chain checkpoint; verify chain (+ checkpoint).
  offline-bundle  Package self-contained offline distribution archive.
  rules export    Export and sign versioned rule-pack archive (.tar.gz).
  rules import    Verify cryptographic signature and import rule-pack.
  users list      List local RBAC identities and their roles.
  users set-password  Create/rotate a local identity's passphrase.
```

### Example Commands:
```bash
# Verify cryptographic audit chain integrity:
satsa audit verify --db-path data/satsa.db

# Run throughput benchmarks on local dataset:
satsa benchmark --data-dir data

# Generate comprehensive PDF dossiers for all entities:
satsa report --entity all --format pdf --output-dir reports/2026-Q1

# Export signed rule configuration pack (requires SATSA_RULEPACK_SECRET, >= 32 chars;
# there is no built-in key -- see docs/deployment_ops.md Section 3):
satsa rules export -c config -o dist/nciipc_rules_v1.tar.gz
```

---

## Directory Structure

```
satsa/
├── Dockerfile                   # Hardened multi-portal container definition (Python 3.11-slim)
├── docker-compose.yml           # Unified orchestration for ports 8000 and 8001
├── entrypoint.py                # Dual-portal concurrent process launcher & volume seeder
├── entrypoint.sh                # Container shell wrapper
├── start.bat                    # One-click Windows startup & automated healthcheck launcher
├── stop.bat                     # Clean Windows shutdown script
├── config/                      # Human-readable YAML rule configurations
│   ├── rules.yaml               # Thresholds for all 20 rules (EG01-12, NS01-08)
│   ├── scoring.yaml             # Domain weights, severity multipliers, CRI bands
│   ├── peers.yaml               # Critical sector peer groupings
│   ├── expected.yaml            # Mandated MITRE tactics & lifecycle sequences
│   └── mappings/                # Source schemas (Splunk, ServiceNow, TheHive)
├── docs/                        # Complete technical and regulatory documentation
│   ├── architecture.md          # System architecture, data flow, security model
│   ├── analytics_methodology.md # Mathematical specs for all 20 rules & robust stats
│   ├── data_requirements.md     # Canonical schemas & per-rule dependency matrix
│   ├── infrastructure.md        # Hardware sizing and measured scale figures
│   ├── validation.md            # Empirical precision/recall & lift methodology
│   └── deployment_ops.md        # Air-gapped operations, backup & rule update guide
├── src/satsa/                   # Core Python package
│   ├── admin/                   # NCIIPC Administration Portal (:8000)
│   │   ├── app.py               # FastAPI admin application definition & lifespan
│   │   ├── routes.py            # Administrative HTTP handlers, user CRUD, & WebSockets
│   │   ├── rbac.py              # Administrative role-based access control rules
│   │   ├── static/              # Admin CSS stylesheets & 0xZenith branding assets
│   │   └── templates/           # Dedicated Jinja2 templates for admin control tabs
│   ├── api/routes.py            # SAT-SA Supervisory Tool (:8001) endpoints
│   ├── auth/                    # Local PBKDF2 identity store & session tokens
│   ├── cli.py                   # Typer CLI application entry point
│   ├── ingest/ scoring/ validate/ # Ingestion & pseudonymisation; scoring; validation harness
│   ├── rules/                   # Deterministic DuckDB SQL rule definitions (EG/NS)
│   ├── store/                   # DuckDB columnar engine & SQLite store (autocommit + WAL)
│   └── ui/                      # Server-rendered Jinja2 templates & static assets
│       ├── static/              # SAT-SA CSS stylesheets and vendored echarts.min.js
│       └── templates/           # Clean, responsive HTML templates for all 10 tabs
├── tests/                       # pytest suite: rules, scoring, RBAC, audit, ingest, offline, property tests
├── pyproject.toml               # PEP 621 package metadata, CLI, & dependencies
└── README.md                    # Standard repository readme
```

---

## Regulatory Compliance & Statutory Boundary

1. **Supervisory Framework:** SAT-SA supports NCIIPC's review of SOC records. NCIIPC is the agency designated under Section 70A of the Information Technology Act, 2000; the problem statement itself cites no law, and SAT-SA claims no statutory force for its output. What the Act and its rules empower is marked for legal review in [`docs/legal_traceability.md`](docs/legal_traceability.md).
2. **Review Priority Support:** Outputs represent empirical indicators requiring human review; they are not automated compliance determinations or final legal adjudications.
3. **Data Integrity Boundary:** Mathematical reconciliation identifies internal discrepancies across independent logs. Deliberately falsified timestamps across all logging tiers require physical forensic inspection.
4. **Air-Gap Assurance:** Designed to operate without internet access. Local host security and operating system hardening remain the responsibility of the supervisory examiner.

---

## Known Limitations & Supervisory Boundary Conditions

1. **Supervisory Scope:** SAT-SA identifies anomalies and evidentiary gaps in periodic submissions; it does not replace on-site forensic inspection or legal examination.
2. **Data Truthfulness:** If an entity falsifies all raw event timestamps consistently across independent systems before submission, mathematical reconciliation will reflect the falsified data.
3. **Third-Party MSSP Visibility:** If an entity outsources Tier-1 triage to an external MSSP that does not share workflow event logs, rules dependent on `workflow_event` are not assessed for that entity, and the DQ view and the ingest report say so (`rule_not_assessed`).
4. **Offline Assumption:** SAT-SA assumes local host security. The air-gap boundary protects against remote exfiltration, but physical and operating-system security of the supervisory host remains the examiner's responsibility.

---

## Project Documentation Index

**All validation data is synthetic; a real-data pilot is pending.** Start with [`docs/validation_summary.md`](docs/validation_summary.md).

- [`docs/architecture.md`](docs/architecture.md): Components, data flow and security model.
- [`docs/functional_design.md`](docs/functional_design.md): RBAC roles and examiner workflows.
- [`docs/analytics_methodology.md`](docs/analytics_methodology.md): All 20 rules, the systemic detector, robust statistics.
- [`docs/threshold_rationale.md`](docs/threshold_rationale.md): Why the most fragile thresholds sit where they do (proposals only; none changed).
- [`docs/data_requirements.md`](docs/data_requirements.md): Canonical schemas, ingest sources, per-rule data needs.
- [`docs/connectors.md`](docs/connectors.md): Splunk ES, ServiceNow SIR and TheHive 5 exports.
- [`docs/validation.md`](docs/validation.md): Validation methodology and what each set does and does not prove.
- Validation reports: [primary](docs/validation_report.md), [stress](docs/validation_stress_report.md), [hard set](docs/validation_hard_report.md), [independent generator](docs/validation_independent_report.md).
- [`docs/shadow_pilot_runbook.md`](docs/shadow_pilot_runbook.md): Measuring accuracy against historical examiner workpapers.
- [`docs/benchmarks.md`](docs/benchmarks.md) and [`docs/infrastructure.md`](docs/infrastructure.md): Measured ingest, assessment, page-load times and memory; hardware sizing.
- [`docs/deployment_ops.md`](docs/deployment_ops.md) and [`docs/offline_install.md`](docs/offline_install.md): Air-gapped deployment, wheelhouse install, rule packs, backups.
- [`docs/ps_traceability.md`](docs/ps_traceability.md) and [`docs/legal_traceability.md`](docs/legal_traceability.md): Requirement to code, test and evidence; statutory context for legal review.
- [`docs/usability_protocol.md`](docs/usability_protocol.md): Timed examiner tasks (no session run yet).
- [`docs/slides_outline.md`](docs/slides_outline.md), [`docs/demo_script.md`](docs/demo_script.md): Presentation outline and demo click-path.
- [`EVIDENCE.md`](EVIDENCE.md) and [`docs/CHANGES_quality_pass.md`](docs/CHANGES_quality_pass.md): Commands and results, open items, doc/code mismatches found and fixed.
