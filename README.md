![CI](https://github.com/KenithKMS56/Supervisory-Analytics-Tool-for-SOC-Assessment-SAT-SA/actions/workflows/test.yml/badge.svg?branch=hardening/sih26157)
# SAT-SA: Supervisory Analytics Tool for SOC Assessment
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
| **EG01** | Fast Closures Without Investigation | Human analyst closes alert in $<120$s without viewing logs or running triage. | Critical |
| **EG02** | Triage Without Action | Alert acknowledged but untouched past contractual/supervisory SLA limit. | High |
| **EG03** | Missing Escalations | Critical/High True Positive alert resolved without opening a formal case. | Critical |
| **EG04** | Template / Low-Effort Closures | $>40\%$ identical closure comment hashes or remarks $<15$ characters. | Medium |
| **EG05** | Repeat Alerts Without Root Cause | $\ge 5$ identical alerts within 30 days without detection engineering tuning. | Medium |
| **EG06** | Metric Gaming & SLA Hugging | Closures unnaturally clustered in the final 5% of SLA window or at shift handoffs. | High |
| **EG07** | Analyst Implausibility | Analyst exceeds physiological limit ($>25$ complex investigations/hour). | High |
| **EG08** | Escalation Without Follow-Through| Formal escalation tickets left unacknowledged or uninvestigated by tier-2. | High |
| **EG09** | Backlog & Aging Accumulation | Open cases aging past $3\times$ target SLA or dormant for $\ge 14$ consecutive days. | Medium |
| **EG10** | KPI Reconciliation Gap | $>10\%$ discrepancy between self-declared KPI reports and raw audit timestamps. | Critical |
| **EG11** | Disposition Extremes | Pathological outcomes ($>98\%$ false positive rate or 0 true positives over 6 months). | High |
| **EG12** | Workflow Non-Conformance | Skipped triage stages or reversed status timestamps (resolved before open). | High |

### Negative Space Inferences (NS01–NS08)
| ID | Rule Name | Operational Defect Identified | Severity |
| :--- | :--- | :--- | :--- |
| **NS01** | Silent Critical Assets | Crown-jewel production servers with $\ge 3$ consecutive days of zero alert activity. | Critical |
| **NS02** | Missing Alert Categories | Sector-prevalent MITRE ATT&CK tactics completely absent from the entity's submitted alerts. | High |
| **NS03** | Unexpectedly Low / Flat Activity| CUSUM volume collapse or total absence of weekend/off-hours alert generation. | High |
| **NS04** | Missing Sequence Gaps | Non-contiguous alert/case ID numbers indicating withheld or purged records. | High |
| **NS05** | Inactive Rule Coverage | Mandated detection signatures enabled in SIEM that have never triggered in 180 days. | Medium |
| **NS06** | Inventory Reconciliation Gap | Discrepancy between declared asset registers and the assets that actually emit log events or alerts. | High |
| **NS07** | Absent Regulatory Reporting | Critical True Positive incidents resolved without statutory regulatory notification. | Critical |
| **NS08** | Submission Completeness Deficit | High null-rates ($>5\%$) or unparseable timestamps indicating compromised evidence. | High |

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
   - 70% risk-stratified / 30% random control sampling mechanism to optimize supervisory review hours.
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
> confirm the code implements its documented logic. A genuinely harder scenario (borderline
> threshold, ambiguous dual-rule case, noisy clean entity) is run via `satsa validate-stress` and
> reports real, imperfect numbers (currently ~60% precision on that harder set) -- see
> [`docs/validation.md`](docs/validation.md) Section 2A. Neither is a substitute for the
> Shadow-Pilot mode (Section 5) against real historical examiner findings, which has not yet been
> run against real NCIIPC/CSE data.

| Metric | Result | Target | Status |
| :--- | :--- | :--- | :--- |
| **Injected Defect Recall** (primary, unambiguous dataset) | **100.0%** (13/13 defects caught) | $\ge 90.0\%$ | Meets target |
| **Entity Rank Precision@7** (primary, unambiguous dataset) | **100.0%** (top-7 entities ranked accurately) | $\ge 85.0\%$ | Meets target |
| **False-Alarm Precision** (primary, unambiguous dataset) | **100.0%** (0 false hits on clean entities) | $\ge 95.0\%$ | Meets target |
| **Stress Scenario Defect Precision** (harder, ambiguous dataset) | **~60.0%** (2 false positives on noisy clean entity) | n/a -- reported for transparency | Genuinely imperfect |
| **Review-Effort Lift** (primary dataset) | **5.97x** at a 1% audit budget (4.13x at 2%, 1.65x at 5%). *Corrected from a stale 16.60x -- see docs/hardening_log.md.* | $\ge 5.00x$ | Meets target at the 1% budget only |
| **Ranking Stability ($\rho$)** (primary dataset) | Spearman $\rho = \mathbf{1.0000}$ ($\pm 20\%$ perturbations) | $\ge 0.9000$ | Meets target |
| **DuckDB Scan Throughput** | **10,623,549 rows/second** | $\ge 1,000,000$ | Measured, exceeds target |
| **Automated Test Suite** | **596 passed, 0 failed, 33 skipped** (skips: public routes in the RBAC matrix are exercised once, anonymously), on Python 3.11 and 3.13 from a clean clone | 100% passing | Verified |

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

   > **Note on Security:** As documented in Section 2 of `docs/functional_design.md`, default credentials are intentionally seeded CHANGE-ME credentials for immediate offline evaluation. NCIIPC administrators should rotate these in production.

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
  ingest          Ingest CSVs, apply HMAC masking, and build Parquet stores.
  run             Execute the supervisory assessment across all entities.
  seed-history    Seed genuine multi-period historical runs for the trend chart.
  serve           Launch the air-gapped web dashboard and REST API.
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
├── tests/                       # Complete pytest test suite (596 passing tests)
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

1. **Supervisory Framework:** SAT-SA is designed in alignment with supervisory responsibilities under Section 70A of the Information Technology Act, 2000 (National Critical Information Infrastructure Protection Centre).
2. **Review Priority Support:** Outputs represent empirical indicators requiring human review; they are not automated compliance determinations or final legal adjudications.
3. **Data Integrity Boundary:** Mathematical reconciliation identifies internal discrepancies across independent logs. Deliberately falsified timestamps across all logging tiers require physical forensic inspection.
4. **Air-Gap Assurance:** Designed to operate without internet access. Local host security and operating system hardening remain the responsibility of the supervisory examiner.

---

## Known Limitations & Supervisory Boundary Conditions

1. **Supervisory Scope:** SAT-SA identifies anomalies and evidentiary gaps in periodic submissions; it does not replace on-site forensic inspection or legal examination.
2. **Data Truthfulness:** If an entity falsifies all raw event timestamps consistently across independent systems before submission, mathematical reconciliation will reflect the falsified data.
3. **Third-Party MSSP Visibility:** If an entity outsources Tier-1 triage to an external MSSP that does not share workflow event logs, rules dependent on `workflow_event` may be skipped or flagged under NS08.
4. **Offline Assumption:** SAT-SA assumes local host security. The air-gap boundary protects against remote exfiltration, but physical and operating-system security of the supervisory host remains the examiner's responsibility.

---

## Project Documentation Index

- [`docs/architecture.md`](file:///docs/architecture.md): 2-page system architecture with Mermaid diagrams, data flow, and security model.
- [`docs/functional_design.md`](file:///docs/functional_design.md): Functional design, RBAC user roles, and examiner workflows.
- [`docs/analytics_methodology.md`](file:///docs/analytics_methodology.md): Mathematical specifications for all 20 rules plus the cross-entity systemic correlation detector, robust statistics, and SPC.
- [`docs/data_requirements.md`](file:///docs/data_requirements.md): Canonical schemas, ingestion sources (CSV/JSON/DB/API), and per-rule data dependency matrix.
- [`docs/infrastructure.md`](file:///docs/infrastructure.md): Hardware sizing, measured benchmarks, and 5M alerts scaling analysis.
- [`docs/validation.md`](file:///docs/validation.md): Detector-implementation correctness methodology, the harder "stress scenario," and shadow pilot adapter -- and what each does and does not prove.
- [`docs/deployment_ops.md`](file:///docs/deployment_ops.md): Air-gapped deployment, signed rule-pack updates, and backup procedures.
- [`docs/ps_traceability.md`](file:///docs/ps_traceability.md): PS SIH26157 functional-requirement-to-component traceability matrix.
- [`docs/slides_outline.md`](file:///docs/slides_outline.md): 5-slide executive presentation outline.
- [`docs/demo_script.md`](file:///docs/demo_script.md): 2-minute live examiner demonstration script.
- [`docs/validation_report.md`](file:///docs/validation_report.md): Output of the detector-implementation correctness run (`satsa validate`).
- [`docs/validation_stress_report.md`](file:///docs/validation_stress_report.md): Output of the harder stress-scenario run (`satsa validate-stress`).
