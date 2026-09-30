![CI](https://github.com/KenithKMS56/Supervisory-Analytics-Tool-for-SOC-Assessment-SAT-SA/actions/workflows/test.yml/badge.svg?branch=hardening/sih26157)
# SAT-SA: Supervisory Analytics Tool for SOC Assessment:
**National Critical Information Infrastructure Protection Centre (NCIIPC)**

**SAT-SA** is an air-gapped, fully deterministic analytical tool and sovereign identity management platform designed for regulatory oversight of Security Operations Centres (SOCs) across Critical Sector Entities (CSEs) in power, banking, telecom, transport, and oil & gas.

The platform provides a unified dual-application architecture:
- **NCIIPC Administration Portal (`http://localhost:8000`)**: Authoritative governance, centralized identity provisioning, critical sector entity and organisation registries, an admin activity feed (operator session monitor of SAT-SA's own users), and administrative cryptographic audit chaining.
- **SAT-SA Supervisory Tool (`http://localhost:8001`)**: Supervisory execution gap detection (**EG01–EG12**), negative space inference (**NS01–NS08**), peer benchmarking, blinded review studios, and statutory compliance dossier exports. It has exactly two operator roles, the **NCIIPC Analyst** and the **NCIIPC Examiner** (see [Two-Role Workflow](#two-role-workflow-analyst--examiner-8001)). Administrators work on `:8000` only.

---

## Architectural Differentiators & Why It Stands Out

Unlike generic dashboards or black-box machine-learning prototypes, SAT-SA is engineered to meet strict regulatory and forensic standards:

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
│                      SHARED PERSISTENT SOVEREIGN BACKEND                          │
│   SQLite Database (Autocommit + WAL)  •  DuckDB Columnar Parquet  •  WebSockets   │
└───────────────────────────────────────────────────────────────────────────────────┘
```

1. **Authoritative Identity & Governance Layer:**
   Centralized administrative control plane where users cannot self-register or select their own role, organisation, or scoped CSE. All identities are authoritatively provisioned by NCIIPC administrators before credentials are issued.
2. **100% Air-Gapped & Sovereign Data Security:**
   Binds strictly to local interfaces. Zero CDN dependencies, zero external script calls, and locally vendored Apache ECharts. Socket-level egress is blocked. Ingested analyst identities are irreversibly pseudonymised using HMAC-SHA256 (`.satsa_salt`), and IP addresses/PII are redacted using deterministic regex masks.
3. **Cryptographic Tamper-Evidence:**
   Every batch upload, schema validation, assessment run, rule configuration change, administrative provisioning action, and human examiner disposition is recorded into append-only SQLite logs hash-chained (SHA3-256 for new entries; legacy SHA-256 entries still verify). Editing, inserting, deleting or reordering an entry in the middle of the chain breaks verification; removal of the newest entries or a full recomputation of the chain is only caught by comparing against a checkpoint recorded off-box with `satsa audit head` (see DECISIONS.md ADR-005).
4. **Extreme Columnar Analytics Performance:**
   Built on DuckDB and PyArrow columnar storage, achieving scan speeds exceeding **10.6 Million rows/second** on standard x86 CPU hardware—enabling multi-gigabyte periodic supervisory submissions to be evaluated in seconds with zero external database dependencies.
5. **Cognitive Bias Mitigation (Blinded Review Studio):**
   Includes a double-blind supervisory mode that presents raw operational metrics without showing pre-calculated risk scores, helping examiners reach unbiased conclusions before revealing inter-rater concordance.
6. **Admin Activity Feed (Operator Session Monitor):**
   The NCIIPC Admin Portal shows what SAT-SA's *own operators* are doing -- sign-ins, report downloads, assessment runs, account blocks -- via an admin-only WebSocket (`/ws/activity`) with a polling fallback, plus instant session revocation. This monitors the tool's internal users; it does **not** collect or monitor any CSE security data (SAT-SA only assesses periodic batch submissions, after the fact).

---

## Regulatory Detection Catalog: 20 Production Rules

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
   - 8-domain capability heatmap (Detection, Triage, Escalation, Hygiene, Compliance, etc.).
   - Instant HTML and PDF executive dossier export buttons.
3. **National Alert Explorer (`/alerts`)**:
   - Server-side paginated browser of submitted alert records (25 records/page) handling thousands of alerts smoothly.
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
   - Full explainability card displaying rule rationale, exact parameter values, benign explanations, suggested examiner interview questions, and evidentiary drill-down tables.
10. **Audit Trail & Cryptographic Verification (`/audit`)**:
    - Live cryptographic verification of the SHA-256 tamper-evident log chain.
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

## NCIIPC Administration & Sovereign Identity Control (`:8000`)

The **NCIIPC Administration Portal** (`http://localhost:8000`) is a dedicated supervisory governance and identity control plane operating alongside SAT-SA:

```
[ NCIIPC Admin Console ] ──► Authoritative RBAC ──► SAT-SA Supervisory Tool (:8001)
     │
     ├── Users Table (PBKDF2-HMAC-SHA256, Scoped Org & CSE, Status: ACTIVE/BLOCKED)
     ├── Critical Sector Organisation Registry (Sector classification, Status)
     ├── Critical Sector Entity (CSE) Registry (Parent Org mapping)
     ├── Administrative Cryptographic Audit Log (Chained SHA-256 prev_hash)
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
   - Hash-chained (`prev_hash`; SHA3-256 for new entries) and verifiable on demand via the UI; `satsa audit head` records an off-box checkpoint that also catches removal of the newest entries.

5. **Modern Government Aesthetic & Floating Navigation Bar**:
   - Orange accent palette (`#ea580c`), glassmorphism card surfaces, and 0xZenith national cyber defense branding.
   - Fixed floating bottom navigation bar matching the SAT-SA ergonomics with integrated dark/light theme switching.

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
| **Review-Effort Lift** (primary dataset) | **19.5x** for the top 25 queue alerts, **12.0x** for the top 50, **5.19x** for the whole 130-alert queue, vs random sampling. (Every 1%/2%/5% budget exceeds the queue, so those all equal 5.19x.) *See docs/validation_report.md Section 4.* | $\ge 5.00x$ | Meets target |
| **Ranking Stability ($\rho$)** (primary dataset) | Spearman $\rho = \mathbf{1.0000}$ ($\pm 20\%$ domain-weight perturbations) | $\ge 0.8500$ | Meets target |
| **Rule Threshold Sensitivity** (primary dataset) | **4 of 66** single-threshold ±20% moves change an outcome, all injected defects built just over their threshold (EG05 pairs, EG07, NS05, NS08's review period). None creates a false alarm on a clean entity on this seed; across the hard set, lowering EG05's pair threshold does. | n/a -- reported for transparency | Margins are synthetic; real calibration needs the pilot |
| **DuckDB Scan Throughput** | **10,623,549 rows/second** (single aggregation query, in memory) | $\ge 1,000,000$ | Measured, exceeds target |
| **Scale, end to end** (`docs/benchmarks.md`) | 5,000,000 alerts (50 entities, 21.4M rows): ingest **603 s** (13.2 GB peak), assessment **310 s** (3.3 GB peak); repeat page loads under 0.7 s | n/a | Measured on a 4-core / 24 GB laptop, uniform synthetic data |
| **Automated Test Suite** | **871 passed, 0 failed, 33 skipped** (skips: public routes in the RBAC matrix are exercised once, anonymously), from freshly generated data on Python 3.13 (Windows). Statement-and-branch coverage **89%** overall; rules 94-100%, scoring 83-100%, audit-chain store 91%. Not re-run on Python 3.11 or Linux in this pass. | 100% passing | Verified locally |

---

## Getting Started & Installation

### Prerequisites
- Docker & Docker Compose (for containerized deployment) **OR** Python **`>=3.11`** (for local CLI development)
- Modern web browser (Chrome, Firefox, Safari, Edge)

---

### Method 1: One-Click Docker Deployment (Production & Demo — Recommended)

The easiest way to run the entire unified platform (NCIIPC Admin Portal + SAT-SA + Shared RBAC + Admin Activity Feed) without configuring local Python environments:

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

   > **Upgrading an existing database:** the former `supervisor` role is migrated to `analyst` automatically on startup. The untouched demo account `supervisor` / `ChangeMe-Supervisor#2026` becomes `analyst` / `ChangeMe-Analyst#2026`; an account whose passphrase was rotated keeps its username.

   > **First login:** every seeded account must choose a new passphrase the first time it signs in. Until it does, its session can open the change-password page and nothing else (pages redirect there; APIs and mutating requests return HTTP 403). The new passphrase must be at least 12 characters and cannot be one of the defaults above. Accounts an administrator creates or resets with "force password change" ticked are held to the same rule.

   > **Network exposure:** `docker compose` publishes both ports on `127.0.0.1` only. To reach the portals from another machine, opt in with `SATSA_BIND_ADDRESS=0.0.0.0 docker compose up -d`, and turn on TLS first (`python scripts/generate_selfsigned_cert.py`, then `SATSA_TLS_CERT` / `SATSA_TLS_KEY`). See `docs/deployment_ops.md` Section 1.3.

4. **Stop the platform:**
   - **Windows**: `stop.bat`
   - **Linux / macOS**: `docker compose down`

---

### Method 2: Fast Local Setup with `uv` (Under 1 Minute)

[`uv`](https://github.com/astral-sh/uv) is a fast Python package manager written in Rust.

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
   uv run satsa serve --host 127.0.0.1 --port 8000
   ```

5. **Open your browser:** Navigate to [http://127.0.0.1:8000](http://127.0.0.1:8000).

---

### Method 3: Standard Python `pip` & `venv`

If you prefer standard Python virtual environments:

1. **Clone the repository:**
   ```bash
   git clone <your-repo-url> satsa
   cd satsa
   ```

2. **Create and activate a virtual environment:**
   ```bash
   python3 -m venv .venv

   # Linux / macOS:
   source .venv/bin/activate

   # Windows (PowerShell):
   .venv\Scripts\Activate.ps1
   # Windows (CMD):
   .venv\Scripts\activate.bat
   ```

3. **Install dependencies:**
   ```bash
   pip install --upgrade pip
   pip install -e ".[dev]"
   ```

4. **Run the test suite:**
   ```bash
   pytest
   ```

5. **Initialize data and run:**
   ```bash
   satsa generate-data --output-dir data/generated --seed 42 --alerts 1500
   satsa ingest --data-dir data/generated/csv --parquet-dir data --db-path data/satsa.db
   satsa run --period 2026-Q1
   satsa serve --host 127.0.0.1 --port 8001
   ```

---

## Command-Line Interface (CLI) Reference

The `satsa` command provides a complete command suite powered by Typer and Rich:

```bash
Usage: satsa [OPTIONS] COMMAND [ARGS]...

Commands:
  generate-data   Generate a synthetic periodic SOC submission with ground-truth defects.
  ingest          Ingest CSVs, apply HMAC masking, and build Parquet stores
                  (--source splunk|servicenow|thehive --entity <id> for a product export).
  run             Execute the supervisory assessment across all entities.
  seed-history    Seed genuine multi-period historical runs for the trend chart.
  serve           Launch the air-gapped web dashboard and REST API (loopback; optional TLS).
  admin           Launch the NCIIPC Administration Portal.
  tls-cert        Create a self-signed TLS certificate offline.
  report          Export supervisory dossiers (HTML, ReportLab PDF, and CSV).
  validate        Run the detector-implementation correctness harness (primary dataset).
  validate-stress Run the harder stress-scenario validation (borderline/ambiguous/noisy).
  benchmark       Benchmark DuckDB columnar scan throughput and query latency.
  audit verify    Cryptographically verify the SHA-256 audit log hash chain.
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
│   ├── infrastructure.md        # Hardware sizing, benchmark data, 5M alert projection
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
│   ├── auth/                    # Sovereign PBKDF2 identity store & session tokens
│   ├── cli.py                   # Typer CLI application entry point
│   ├── core/                    # Ingestion, validation, pseudonymisation, scoring
│   ├── rules/                   # Deterministic DuckDB SQL rule definitions (EG/NS)
│   ├── store/                   # DuckDB columnar engine & SQLite store (autocommit + WAL)
│   └── ui/                      # Server-rendered Jinja2 templates & static assets
│       ├── static/              # SAT-SA CSS stylesheets and vendored echarts.min.js
│       └── templates/           # Clean, responsive HTML templates for all 10 tabs
├── tests/                       # pytest suite (871 passing tests)
│   ├── test_admin_portal.py     # NCIIPC Admin Portal routes & CRUD verification
│   ├── test_admin_satsa_integration.py # E2E Admin-to-SATSA provisioning & scoping
│   ├── test_admin_activity_feed.py # Admin activity feed (operator session monitor) verification
│   ├── test_api.py              # REST API and UI view testing
│   ├── test_auth.py             # RBAC and session isolation testing
│   ├── test_rules.py            # Rule predicate and execution testing
│   ├── test_scoring.py          # CRI score & Noisy-OR logic verification
│   └── test_offline.py          # Air-gap verification (zero outbound connections)
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

- [`docs/architecture.md`](file:///docs/architecture.md): 2-page system architecture with Mermaid diagrams, data flow, and security model.
- [`docs/functional_design.md`](file:///docs/functional_design.md): Functional design, RBAC user roles, and examiner workflows.
- [`docs/shadow_pilot_runbook.md`](docs/shadow_pilot_runbook.md): Step-by-step procedure for measuring real-world accuracy against historical examiner workpapers.
- [`docs/analytics_methodology.md`](file:///docs/analytics_methodology.md): Mathematical specifications for all 20 rules plus the cross-entity systemic correlation detector, robust statistics, and SPC.
- [`docs/data_requirements.md`](file:///docs/data_requirements.md): Canonical schemas, ingestion sources (CSV/JSON/DB/API), and per-rule data dependency matrix.
- [`docs/infrastructure.md`](file:///docs/infrastructure.md): Hardware sizing and storage estimates (scale figures are measured in `docs/benchmarks.md`).
- [`docs/validation.md`](file:///docs/validation.md): Detector-implementation correctness methodology, the harder "stress scenario," and shadow pilot adapter -- and what each does and does not prove.
- [`docs/deployment_ops.md`](file:///docs/deployment_ops.md): Air-gapped deployment, signed rule-pack updates, and backup procedures.
- [`docs/ps_traceability.md`](file:///docs/ps_traceability.md): PS SIH26157 functional-requirement-to-component traceability matrix.
- [`docs/slides_outline.md`](file:///docs/slides_outline.md): 5-slide executive presentation outline.
- [`docs/demo_script.md`](file:///docs/demo_script.md): 2-minute live examiner demonstration script.
- [`EVIDENCE.md`](EVIDENCE.md): What was changed and measured in the feasibility pass, with commands, results, open items and ratings.
- [`docs/validation_summary.md`](docs/validation_summary.md): What was tested, that it is all synthetic, what the numbers do and do not prove.
- [`docs/validation_hard_report.md`](docs/validation_hard_report.md): Hard set: other seeds, lower volumes, stress under 20 seeds (`python scripts/validate_hard.py`).
- [`docs/benchmarks.md`](docs/benchmarks.md): Measured ingest, assessment, page-load times and peak memory up to 5,000,000 alerts.
- [`docs/connectors.md`](docs/connectors.md): Splunk ES, ServiceNow SIR and TheHive 5 exports: what maps, what does not, which rules each supports.
- [`docs/legal_traceability.md`](docs/legal_traceability.md): Problem-statement requirements to component and test; statutory context and what needs legal review.
- [`docs/validation_report.md`](file:///docs/validation_report.md): Output of the detector-implementation correctness run (`satsa validate`).
- [`docs/validation_stress_report.md`](file:///docs/validation_stress_report.md): Output of the harder stress-scenario run (`satsa validate-stress`).
