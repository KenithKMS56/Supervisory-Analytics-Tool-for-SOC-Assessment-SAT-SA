# SAT-SA: Supervisory Analytics Tool for SOC Assessment

![CI](https://github.com/KenithKMS56/Supervisory-Analytics-Tool-for-SOC-Assessment-SAT-SA/actions/workflows/test.yml/badge.svg?branch=main)

**National Critical Information Infrastructure Protection Centre (NCIIPC)**

SAT-SA is an offline, deterministic analytical tool with its own identity management, built for
regulatory oversight of Security Operations Centres (SOCs) across Critical Sector Entities (CSEs)
in power, banking, telecom, transport, and oil & gas. It runs as two applications on one machine:

| Application | Address | Who uses it | What it does |
| :--- | :--- | :--- | :--- |
| **NCIIPC Administration Portal** | `http://localhost:8000` | Administrators | User provisioning, organisation and CSE registries, admin activity feed, hash-chained admin audit log |
| **SAT-SA Supervisory Tool** | `http://localhost:8001` | NCIIPC Analyst, NCIIPC Examiner | Execution gaps (**EG01–EG12**), negative space inferences (**NS01–NS08**), peer benchmarking, blinded review, supervisory cases, dossier exports |

Administrators work on `:8000` only; SAT-SA has exactly two operator roles (see
[Two-Role Workflow](#two-role-workflow-analyst--examiner-8001)).

## Contents

- [Getting Started](#getting-started)
- [First sign-in on a production deployment](#first-sign-in-on-a-production-deployment)
- [Key Features](#key-features)
- [Detection Catalogue: 20 Rules](#detection-catalogue-20-rules)
- [Web Interface](#web-interface-8001)
- [Two-Role Workflow](#two-role-workflow-analyst--examiner-8001)
- [Administration Portal](#administration-portal-8000)
- [Validation & Benchmarks](#validation--benchmarks)
- [CLI Reference](#cli-reference)
- [Directory Structure](#directory-structure)
- [Scope & Limitations](#scope--limitations)
- [Documentation](#documentation)

---

## Getting Started

**Prerequisites:** Docker & Docker Compose, **or** Python `>=3.11`; a current web browser.

A new deployment is a **production** deployment: it starts empty, with no accounts and no data
(see [First sign-in on a production deployment](#first-sign-in-on-a-production-deployment)). To
look around first, run the demonstration deployment.

### Quick demo

Double-click `start-demo.bat` (Windows; it uses Docker if installed, otherwise this project's
Python), or run `python entrypoint.py --demo`. Then open [http://localhost:8001](http://localhost:8001)
and click **Analyst** or **Examiner** under the login form.

The demo keeps everything in `demo-run/` and never touches `data/`. Stop it with `stop-demo.bat`
(or Ctrl+C); delete `demo-run/` to start afresh. It loads synthetic data, labels every page as a
demonstration, and has these accounts with published passphrases. Both login pages have
**one-click buttons** for them (*Analyst* and *Examiner* on `:8001`, *nciipc_admin* and *admin* on
`:8000`). A production deployment never has them.

| Username | Role | Passphrase | Interface |
| :--- | :--- | :--- | :--- |
| `nciipc_admin` | NCIIPC Super Administrator | `ChangeMe-NCIIPC#2026` | Admin Portal (`:8000`) only |
| `admin` | Administrator | `ChangeMe-Admin#2026` | Admin Portal (`:8000`) only |
| `analyst` | NCIIPC Analyst | `ChangeMe-Analyst#2026` | SAT-SA (`:8001`): technical operator workspace |
| `examiner` | NCIIPC Examiner | `ChangeMe-Examiner#2026` | SAT-SA (`:8001`): executive review workspace |

> **Upgrading:** the former `supervisor` role becomes `analyst` on startup; the untouched demo
> account `supervisor` is renamed `analyst` (`ChangeMe-Analyst#2026`), a rotated one keeps its name.

### Method 1: Docker

The image has not been built in this project's recorded evidence.

| | Windows | Linux / macOS |
| :--- | :--- | :--- |
| Start | `start.bat` | `docker compose up -d --build` |
| Stop | `stop.bat` (demo: `stop-demo.bat`) | `docker compose down` (demo: `docker compose -p satsa-demo down`) |

Then open the Admin Portal at [http://localhost:8000](http://localhost:8000) and SAT-SA at
[http://localhost:8001](http://localhost:8001). On first run the console prints a one-time setup
token: continue with [First sign-in on a production deployment](#first-sign-in-on-a-production-deployment).

> **Network exposure:** `docker compose` publishes both ports on `127.0.0.1` only. To reach the
> portals from another machine, opt in with `SATSA_BIND_ADDRESS=0.0.0.0 docker compose up -d`, and
> turn on TLS first (`python scripts/generate_selfsigned_cert.py`, then `SATSA_TLS_CERT` /
> `SATSA_TLS_KEY`). See `docs/deployment_ops.md` Section 1.3.

### Method 2: Local setup with [`uv`](https://github.com/astral-sh/uv)

For an air-gapped machine, install from a wheelhouse instead: [`docs/offline_install.md`](docs/offline_install.md).

```bash
# Install uv (if needed)
curl -LsSf https://astral.sh/uv/install.sh | sh                          # Linux / macOS
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"   # Windows

git clone <your-repo-url> satsa && cd satsa
uv sync
uv run pytest                    # full test suite
```

**Demo in four commands.** Set `SATSA_DEMO=1` first, in the same terminal, and use a data
directory that does not exist yet (here `data/`, in a fresh clone). A deployment's mode is fixed
when its database is first created; without `SATSA_DEMO=1` it is a production deployment, which has
no accounts until first-run setup.

```bash
export SATSA_DEMO=1              # Windows PowerShell: $env:SATSA_DEMO = "1"
uv run satsa generate-data --output-dir data/generated --seed 42 --alerts 1500   # synthetic data with known defects
uv run satsa ingest --data-dir data/generated/csv --parquet-dir data --db-path data/satsa.db
uv run satsa run --period 2026-Q1                                                # assessment
uv run satsa serve --host 127.0.0.1 --port 8001                                  # web interface
```

Open [http://127.0.0.1:8001](http://127.0.0.1:8001) and click **Analyst** or **Examiner**. Uploads
and assessments started from the web pages run as jobs: start the worker in a second terminal
(same `SATSA_DEMO=1`) with `uv run satsa worker`, or start everything at once with
`uv run python entrypoint.py`. Or skip all of this: `uv run python entrypoint.py --demo` starts both
portals and the worker in `demo-run/` and loads the demonstration data itself.

On Windows, install under a short path (or enable long paths): a deep directory can exceed the
260-character path limit when Parquet files are written.

### Method 3: `pip` and `venv`

```bash
git clone <your-repo-url> satsa && cd satsa
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install --upgrade pip
pip install -e . --group dev     # dev tools are a dependency group (pip >= 25.1)
pytest
```

Then run Method 2's four commands without `uv run`, with `SATSA_DEMO=1` set as described there.

---

## First sign-in on a production deployment

No portal shows or sends a ready-made passphrase. The first administrator chooses their own with a
one-time token; analysts and examiners receive an initial passphrase from an administrator and
replace it at their first sign-in. Start the platform without `SATSA_DEMO` (Method 1, or
`python entrypoint.py`).

1. **Copy the setup token.** The console prints `PRODUCTION deployment, not set up yet` followed
   by a one-time token, also saved in `data/secrets/setup_token`. A restart prints the same token
   until setup is done.
2. **Create the first administrator** (Admin Portal, `:8000`). Before setup, the portal's sign-in
   leads to `/setup`. Enter the token, then choose the administrator's username and passphrase
   (at least 12 characters, not a published demo passphrase), the deployment name and time zone.
   The token is then deleted and `/setup` returns 404. Headless alternative:
   `satsa setup --admin-username ... --deployment-name ...` (`docs/first_run_setup.md`).
3. **Sign in and enrol the second factor.** In production every administrator needs an
   authenticator app (any TOTP app; it works offline). Add the key the portal shows, enter the
   6-digit code, and keep the **10 recovery codes** shown once afterwards, apart from the device.
   Each later admin sign-in asks for a code. See `docs/security/mfa.md`.
4. **Create the analyst and examiner accounts.** *Users → Create New User*: enter a username and
   choose *Analyst* or *Examiner*. The **Initial Passphrase** box is filled with a random
   16-character passphrase (**Generate** makes another). Leave **Require Password Reset on Initial
   Login** ticked.
5. **Hand over the initial passphrase.** Give the username and initial passphrase to the person
   yourself, over a channel you trust. The portal does not e-mail or display it anywhere else, and
   stores only a salted hash.
6. **First sign-in to SAT-SA** (`:8001`). The person signs in with the initial passphrase and is
   sent to *Set a New Passphrase*. Until they choose their own (at least 12 characters, not one of
   the demo passphrases), pages redirect there and APIs and mutating requests return HTTP 403.
7. **Forgotten passphrase.** An administrator clicks **Reset** on the user's row in *Users*. The
   reset page suggests a new random passphrase and requires a change at the next sign-in. A lost
   authenticator is reset by another administrator: **Edit** on that user's row, then
   **Reset second factor**.

A database created before deployment modes existed is treated as production but keeps its old
accounts and has no setup token: sign in with them, and any account still on its published demo
passphrase must change it first.

---

## Key Features

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

- **Authoritative identity.** Users cannot self-register or choose their own role, organisation or
  scoped CSE; NCIIPC administrators provision every identity before credentials are issued.
- **Offline operation & data minimisation.** Binds to loopback (`127.0.0.1`) by default. No CDN or
  external script calls (Apache ECharts is vendored), and SAT-SA makes no outbound network calls.
  As **best-effort defence in depth**, each portal installs an in-process egress guard
  (`satsa/netguard.py`) that refuses Python socket connections to anything but loopback; it does
  not cover native code that bypasses Python sockets or block DNS lookups, so the host firewall and
  the air gap remain the real controls. Ingested analyst identities are pseudonymised with
  HMAC-SHA256 under a versioned local key kept with the data (`data/secrets/pseudonym_keys.json`,
  see `docs/key_management.md`; anyone holding the key can re-derive a known name's pseudonym), and
  IP addresses, e-mail addresses and host names are masked by deterministic regexes.
- **Tamper evidence.** Every batch upload, schema validation, assessment run, rule configuration
  change, administrative action and examiner disposition is recorded in append-only SQLite logs,
  hash-chained (SHA3-256 for new entries; legacy SHA-256 entries still verify). Editing, inserting,
  deleting or reordering an entry in the middle of the chain breaks verification; removal of the
  newest entries or a full recomputation is only caught against an off-box checkpoint, signed with
  Ed25519 by `satsa audit checkpoint --sign` (DECISIONS.md ADR-005, ADR-008). Tamper-evident, not
  tamper-proof.
- **Columnar analytics, measured at scale.** DuckDB over Parquet, no database server. On one
  4-core / 8-thread laptop (AMD Ryzen 5 7235HS, 23.7 GB RAM) with uniform synthetic data,
  5,000,000 alerts (21.4M rows) took **46.6 s to ingest** (5.7 GB peak memory) and **124 s to
  assess** (3.9 GB peak; assessment time varies widely between runs), recorded 2026-10-02 in
  [`docs/benchmarks.md`](docs/benchmarks.md). A single in-memory aggregation query is much faster
  (7.6M rows/s at 1M rows, `satsa benchmark`), but scan speed is not end-to-end time.
- **Bias mitigation (blinded review).** Assigned blind-review tasks present raw operational metrics
  without risk scores, so examiners reach their own conclusion before the system's assessment and
  the agreement score are revealed.
- **Admin activity feed.** The Admin Portal shows what SAT-SA's *own operators* are doing, with
  instant session revocation. It does **not** collect or monitor any CSE security data; SAT-SA only
  assesses periodic batch submissions, after the fact.

---

## Detection Catalogue: 20 Rules

SAT-SA evaluates each periodic CSE submission against **12 Execution Gaps** (malfunctions in active
workflows) and **8 Negative Space Inferences** (anomalies revealed by what is absent or missing).

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

All thresholds except EG03, NS07 and NS08 are configurable in `config/rules.yaml` and on the Tuning
page; the values above are the defaults. Full logic: [`docs/analytics_methodology.md`](docs/analytics_methodology.md) Section 3.

### Beyond the 20 rules

- **Cross-entity systemic correlation.** `satsa.rules.systemic` runs once per assessment across the
  whole portfolio: if 3 or more entities sharing the same third-party SOC provider all trigger the
  identical rule in the same run, the portfolio dashboard shows a possible shared-provider pattern,
  separate from each entity's finding cards. Each lead shows affected, assessable and total
  clients, the rate among other providers' clients and a Fisher-exact / Benjamini-Hochberg bound.
  It is a hypothesis to examine, not proof of shared-vendor causation, and it is never scored
  ([`docs/analytics_methodology.md`](docs/analytics_methodology.md) Section 3A).
- **Entity context and peer comparisons.** Hours are read in each entity's own time zone. Approved
  maintenance windows and in-service dates keep planned downtime from counting as monitoring
  silence. Documented, expiring rule exceptions, approved by a second examiner, keep a finding
  visible but out of the score. Every run records the peer cohort it used and whether the
  comparison is established or only exploratory ([`docs/analytics_context.md`](docs/analytics_context.md)).
- **Exploratory leads and review priorities.** `satsa.peers.anomaly_scan` computes about 40
  operational rates per entity across the eight domains and flags **peer outliers** (robust
  z $\ge 3.5$ against the peer cohort) and **time shifts** (CUSUM against the entity's first three
  months). Leads appear on the entity profile and portfolio and at `GET /api/v1/anomalies`; they are
  **not scored** (no severity, no effect on the risk index or review queue; DECISIONS.md ADR-007).
  The portfolio also ranks **controls** (rules) and **processes** (domains) for review
  (`GET /api/v1/priorities`). Method: [`docs/analytics_methodology.md`](docs/analytics_methodology.md)
  Sections 3B and 4.5.

---

## Web Interface (`:8001`)

Server-rendered pages; what each role may do on them is in the [Two-Role Workflow](#two-role-workflow-analyst--examiner-8001).

| Page | Route | What it shows |
| :--- | :--- | :--- |
| **Portfolio** | `/portfolio` | Entities ranked by Composite Risk Index (CRI, 0–100), with filters (e.g. *Entities Require Action*); a heatmap of the problem statement's eight capabilities (Threat Detection, Investigation, Escalation, Incident Response, Security Operations, Governance and Oversight, Operational Discipline, Cyber Resilience); HTML and PDF executive dossiers. |
| **Entity profile** | `/entity/{entity_id}` | Radar chart against the national peer median; self-declared vs. computed KPI reconciliation. |
| **Finding card** | `/finding/{finding_id}` | Rule rationale, exact parameter values, benign explanations, a suggested examiner check (what to verify or request from the entity), and evidence tables. |
| **Review queue** | `/queue` | Per-entity queue: records cited by findings (up to 70% of the queue) plus a severity-stratified random control sample. Examiner dispositions: *Confirmed concern*, *Marked as justified*, *More data needed*. |
| **Supervisory cases** | `/cases` | One case per concern (entity × rule), opened from a finding: assignment, explanation request and offline response package, decision, second-examiner review and adjudication, corrective action, and verification on next-period evidence. Immutable history with superseding decisions; concurrent edits are detected. A confirmed concern is not a notice: SAT-SA issues and sends nothing. |
| **Blind review** | `/blind-review` | An analyst draws a seeded sample of flagged, control and random entities from a run and assigns it to an examiner, who judges each task from raw operational signals. Scores, findings and the reason for selection are served only after submission and an explicit, recorded reveal ([`docs/examiner_workflow.md`](docs/examiner_workflow.md)). |
| **Upload & ingest** | `/upload` | Onboard entities (custom sectors allowed); upload CSVs or a submission `.zip`; schema validation, pseudonymisation, redaction and Parquet partitioning; canonical templates and a sample bundle to download. Retiring an entity leaves it out of future assessments and keeps its history. |
| **Alert explorer** | `/alerts` | Paginated submitted alerts (25 per page), filtered by entity, severity, disposition and search text. |
| **Rules catalogue** | `/rules` | All 20 rules, filtered by category, capability domain and severity, with their logic. |
| **Rule calibration** | `/tuning` | Threshold sliders, the configuration hash, and signed rule-pack export and import (`.tar.gz`). |
| **Data quality** | `/dq` | Data-quality issues found at ingest, including rules that could not be assessed. |
| **Runs & audit** | `/runs`, `/audit` | Run history, configuration hashes, record counts and timings; on-demand verification of the audit hash chain. |

---

## Two-Role Workflow: Analyst → Examiner (`:8001`)

One person operates the pipeline and another makes the regulatory call, as at real regulators.
Both use the same app at `:8001`, and the interface adapts to the role.

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
     • Review queue: Confirm concern / Mark as justified / Needs more data
     • Supervisory cases (/cases): request explanations, decide, require and verify remediation
     • Assigned blind-review tasks; one-click Executive Regulatory Dossier (PDF)
```

| | Analyst | Examiner |
| :--- | :---: | :---: |
| Portfolio, entity profiles, findings, PDF/HTML dossiers | ✔ | ✔ |
| Upload & ingest, assessment runs, rule catalogue, tuning & rule packs | ✔ | ✘ (403) |
| Alert explorer, data quality, runs & audit ledger, raw CSV exports | ✔ | ✘ (403) |
| Review-queue decisions, case actions, blind-review verdicts | ✘ (403) | ✔ |
| Read supervisory cases | ✔ | ✔ |
| Draw and assign blind-review samples | ✔ | ✘ (403) |

Separation of duties is deliberate: whoever tunes the rules can't also sign off the findings. Every
other role, including NCIIPC administrators and CSE-scoped accounts, is refused at SAT-SA's login.

---

## Administration Portal (`:8000`)

```
[ NCIIPC Admin Console ] ──► Authoritative RBAC ──► SAT-SA Supervisory Tool (:8001)
     │
     ├── Users Table (PBKDF2-HMAC-SHA256, Scoped Org & CSE, Status: ACTIVE/BLOCKED)
     ├── Critical Sector Organisation Registry (Sector classification, Status)
     ├── Critical Sector Entity (CSE) Registry (Parent Org mapping)
     ├── Administrative Audit Log (hash-chained prev_hash, SHA3-256)
     └── Admin Activity Feed (Operator Session Monitor) & Remote Session Revocation
```

**User provisioning (`/users`, `/users/create`).** The administrator assigns each user:
- **Role:** `NCIIPC Super Administrator` (Admin Portal only), `NCIIPC Analyst` or `NCIIPC Examiner`
  (the two SAT-SA operators), or a CSE-side role (`CSE Administrator`, `SOC Manager`,
  `SOC Analyst`, `CSE Viewer`).
- **Organisation:** the parent critical infrastructure authority (e.g. `ORG-POWER`, `ORG-FIN`, `ORG-TELECOM`).
- **Scoped CSE:** the entity assigned to the user (e.g. `CSE-01 Northern Power Grid`), which must
  belong to that organisation.

**User lifecycle (`/users/{username}/edit`, `/users/{username}/reset`).**
- Blocking an account (`ACTIVE` → `BLOCKED`) ends all its sessions on both portals at once.
- Credential reset suggests a random 16-character passphrase (browser CSPRNG), stores it with a
  fresh salt and 200,000 PBKDF2 iterations, revokes old sessions, and sets `force_password_change`
  (ticked by default) so the user picks their own at next sign-in.
- Administrators enrol a TOTP authenticator (`/mfa/setup`, 10 one-time recovery codes), required in
  production; another administrator can reset a lost one. The first administrator is created once
  at `/setup` ([First sign-in on a production deployment](#first-sign-in-on-a-production-deployment)).

**Registries (`/organisations`, `/cses`).** Organisations and Critical Sector Entities, with the
active CSE count and provisioned analyst count per entity.

**Administrative audit log (`/audit`).** Append-only record of every administrative action
(`FIRST_RUN_SETUP`, `USER_CREATED`, `ROLE_CHANGED`, `CSE_CHANGED`, `ACCOUNT_BLOCKED`,
`CREDENTIAL_RESET`, `MFA_RESET`, `ORGANISATION_CREATED`, etc.), hash-chained (`prev_hash`; SHA3-256
for new entries) and verifiable on demand in the UI. A signed off-box checkpoint
(`satsa audit checkpoint`) also catches removal of the newest entries.

### Admin activity feed (operator session monitor)

The Admin Portal monitors SAT-SA's own operators, not CSE data. Both applications share one local
database, and meaningful events are recorded in `live_events`:

| Group | Events |
| :--- | :--- |
| Authentication | `USER_LOGIN`, `USER_LOGOUT`, `LOGIN_FAILED`, `ACCOUNT_BLOCKED` |
| Assessments | `ASSESSMENT_UPLOAD`, `ASSESSMENT_STARTED`, `ASSESSMENT_COMPLETED` |
| Investigation | `FINDING_VIEWED`, `REPORT_GENERATED`, `REPORT_DOWNLOADED` |
| Governance | `ROLE_CHANGED`, `CSE_CHANGED`, `ORGANISATION_CREATED`, `CSE_CREATED` |

- **Delivery** (both require an administrator session): a WebSocket (`ws://localhost:8000/ws/activity`)
  pushes new events, with a polling fallback (`/api/activity/stream?since_id=...&limit=...`, limit
  capped at 200).
- **Active operators:** signed-in analysts and examiners, their session start times and CSE scope,
  with a **Revoke & Block** button for incident response.
- The feed is supplementary and not hash-chained; security-relevant events are also recorded in the
  hash-chained audit logs (DECISIONS.md ADR-006).

---

## Validation & Benchmarks

**All validation data is synthetic; a real-data pilot is pending.** Start with
[`docs/validation_summary.md`](docs/validation_summary.md).

> **What this table is:** apart from throughput and the test count, these rows are a
> **correctness check** of the detector implementation, not a real-world accuracy benchmark. The
> synthetic defects are built to clearly exceed each rule's own threshold, so near-100% scores are
> expected by construction and mainly confirm the code implements its documented logic. Every one
> of the 20 rules has at least one injected defect (enforced by a test). Every tunable threshold
> (18 rules) is also moved ±20% to measure margin: on the primary seed no such move turns a clean
> entity into a finding. NS03 and EG11 judge entities by robust z-score against their peer cohort,
> and EG05's repeat threshold rises to each entity's chance level (Section 4A). A borderline,
> ambiguous and noisy scenario runs via `satsa validate-stress` (Section 2A). None of this replaces
> the Shadow-Pilot mode (Section 5) against real historical examiner findings, which has not yet
> been run against real NCIIPC/CSE data. Sections refer to [`docs/validation.md`](docs/validation.md).
>
> **Correction (September 2026):** earlier versions reported 100% precision on the primary dataset
> and ~60% on the stress scenario. The harness only counted false positives on the three clean
> entities and exempted NS05/EG12/EG10; counted honestly, that run's precision was 38% (13/34
> findings), and the stress figure came from generator artifacts. The causes (generator bugs and an
> EG10 severity-mismatch defect) are fixed and precision now counts every finding
> ([`docs/validation.md`](docs/validation.md) Section 0.1).

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
| **Automated Test Suite** | **1,755 passed, 0 failed, 54 skipped** (skips: public routes in the RBAC matrix are exercised once, anonymously), incl. property-based and browser tests, Python 3.11 (Windows), 2026-10-28. Statement-and-branch coverage **88.4%**; rules 89-100%, scoring 80-100%, audit-chain store 90%. CI runs the suite on Linux (browser tests skipped there). | 100% passing | Verified locally |

---

## CLI Reference

`satsa <command> --help` lists each command's options.

| Area | Commands |
| :--- | :--- |
| Setup | `version`; `setup` (first-run setup from the shell, instead of the Admin Portal's `/setup`); `deployment` (mode and settings, `docs/first_run_setup.md`) |
| Data | `generate-data` (synthetic submission with ground-truth defects); `ingest` (CSV/JSON/SQLite exports or `--api-config` local APIs, HMAC masking, Parquet; `--source splunk\|servicenow\|thehive --entity <id>` for a product export); `seed-history` (multi-period runs for the trend chart) |
| Assessment | `run` (assess all entities); `replay` (re-run a recorded assessment with its own configuration and source snapshot, and compare); `report` (HTML, PDF and CSV dossiers) |
| Serving | `serve` (SAT-SA, loopback, optional TLS); `admin` (Admin Portal); `worker` (job worker: imports, assessments, demo seeding); `jobs` (inspect and cancel jobs); `tls-cert` (self-signed certificate, offline) |
| Validation | `validate` (primary dataset); `validate-stress` (borderline/ambiguous/noisy); `validate-independent` (separately written generator, many seeds, naive baselines); `pilot` (pilot evaluation from blinded reviews, `docs/shadow_pilot_runbook.md` Part B); `benchmark` (DuckDB scan throughput and query latency) |
| Integrity | `audit verify` / `head` / `keygen` / `checkpoint` (verify the chain, record its head off-box, signing key pair, signed checkpoint); `verify-data` (Parquet files against their recorded SHA-256); `recover` (quarantine what an interrupted writer left behind) |
| Operations | `backup` / `restore` (`docs/backup_restore.md`); `migrate` (`docs/migrations.md`); `ops` (readiness, retention, diagnostics; `docs/deployment_ops.md`); `keys` (pseudonymisation keys, `docs/key_management.md`); `entity` (retire or reinstate; nothing is erased) |
| Distribution | `offline-bundle` (self-contained offline archive); `release` (sign and verify bundles, `docs/offline_install.md`); `rules export` / `rules import` (signed rule packs) |
| Accounts | `users list`; `users set-password`; `service-credential` (submission API, `docs/api_credentials.md`) |

```bash
satsa audit verify --db-path data/satsa.db                         # verify the audit chain
satsa benchmark --data-dir data                                    # scan throughput
satsa report --entity all --format pdf --output-dir reports/2026-Q1   # PDF dossiers for all entities
# Signed rule pack: needs SATSA_RULEPACK_SECRET (>= 32 chars); there is no built-in key
# (docs/deployment_ops.md Section 3).
satsa rules export -c config -o dist/nciipc_rules_v1.tar.gz
```

---

## Directory Structure

```
satsa/
├── Dockerfile / Containerfile   # Hardened multi-portal container definition (Python 3.11-slim)
├── docker-compose.yml           # Orchestration for ports 8000 and 8001
├── Makefile                     # make check (lint, typecheck, test), format, offline-bundle
├── entrypoint.py / .sh          # Launches both portals and the worker; container wrapper
├── start.bat / stop.bat         # Windows start (with health check) and stop
├── start-demo.bat / stop-demo.bat  # Demo deployment in demo-run/ (Docker or Python)
├── config/                      # YAML configuration
│   ├── rules.yaml               # Thresholds for all 20 rules
│   ├── scoring.yaml             # Domain weights, severity multipliers, CRI bands
│   ├── peers.yaml               # Sector peer groupings
│   ├── expected.yaml            # Mandated MITRE tactics & lifecycle sequences
│   └── mappings/                # Source schemas (Splunk, ServiceNow, TheHive)
├── docs/                        # Technical and regulatory documentation (see below)
├── demo_data/                   # Demonstration upload bundle (synthetic)
├── scripts/                     # TLS certificate, wheelhouse, benchmark and validation helpers
├── src/satsa/
│   ├── admin/                   # Administration Portal (:8000): app, routes, RBAC, templates
│   ├── api/                     # SAT-SA (:8001) endpoints
│   ├── auth/                    # Local PBKDF2 identity store & session tokens
│   ├── cases/                   # Supervisory cases and blind-review tasks
│   ├── cli.py                   # Typer CLI entry point
│   ├── deployment.py            # Production / demo mode, first-run setup token
│   ├── ingest/                  # Ingestion, pseudonymisation, redaction
│   ├── jobs/                    # Durable job queue and worker
│   ├── rules/                   # Deterministic DuckDB SQL rules (EG/NS)
│   ├── scoring/                 # Domain scores and Composite Risk Index
│   ├── store/                   # DuckDB columnar engine & SQLite store (autocommit + WAL)
│   ├── validate/                # Validation harness
│   ├── peers/ explain/ report/  # Peer cohorts and leads; finding explanations; dossiers
│   ├── audit/ bundle/ synth/ …  # Audit checkpoints; offline bundle; synthetic data generators
│   └── ui/                      # SAT-SA templates and static assets (vendored ECharts)
├── tests/                       # pytest: rules, scoring, RBAC, audit, ingest, offline, property, browser
└── pyproject.toml               # Package metadata, CLI and dependencies
```

---

## Scope & Limitations

1. **Supervisory support, not adjudication.** SAT-SA supports NCIIPC's review of SOC records.
   NCIIPC is the agency designated under Section 70A of the Information Technology Act, 2000; the
   problem statement itself cites no law, and SAT-SA claims no statutory force for its output. What
   the Act and its rules empower is marked for legal review in
   [`docs/legal_traceability.md`](docs/legal_traceability.md). Outputs are indicators requiring
   human review, not compliance determinations, and SAT-SA does not replace on-site forensic
   inspection or legal examination.
2. **Data truthfulness.** Reconciliation finds discrepancies between independent logs. If an
   entity falsifies all raw event timestamps consistently across independent systems before
   submission, the reconciliation reflects the falsified data; that needs physical forensic
   inspection.
3. **Third-party MSSP visibility.** If an entity outsources Tier-1 triage to an MSSP that does not
   share workflow event logs, rules that depend on `workflow_event` are not assessed for that
   entity, and the DQ view and the ingest report say so (`rule_not_assessed`).
4. **Host security.** SAT-SA is designed to run without internet access. The air gap protects
   against remote exfiltration; physical and operating-system security of the host remain the
   operator's responsibility.

---

## Documentation

- [`docs/SAT-SA_Architecture.pdf`](docs/SAT-SA_Architecture.pdf): the 2-page architecture document for evaluation (source: [`docs/architecture_2page.md`](docs/architecture_2page.md); `python scripts/render_architecture_pdf.py` rebuilds it and fails above 2 pages).
- [`docs/architecture.md`](docs/architecture.md): components, data flow and security model.
- [`docs/functional_design.md`](docs/functional_design.md): RBAC roles and examiner workflows.
- [`docs/analytics_methodology.md`](docs/analytics_methodology.md): all 20 rules, the systemic detector, robust statistics.
- [`docs/analytics_context.md`](docs/analytics_context.md): entity context (time zone, schedule, maintenance, exceptions), peer cohorts and their strength, evidence support, provider-level leads.
- [`docs/threshold_rationale.md`](docs/threshold_rationale.md): why the most fragile thresholds sit where they do (proposals only; none changed).
- [`docs/data_requirements.md`](docs/data_requirements.md): canonical schemas, ingest sources, per-rule data needs.
- [`docs/connectors.md`](docs/connectors.md): Splunk ES, ServiceNow SIR and TheHive 5 exports.
- [`docs/validation.md`](docs/validation.md): validation methodology and what each set does and does not prove.
- Validation reports: [primary](docs/validation_report.md), [stress](docs/validation_stress_report.md), [hard set](docs/validation_hard_report.md), [independent generator](docs/validation_independent_report.md).
- [`docs/shadow_pilot_runbook.md`](docs/shadow_pilot_runbook.md): measuring accuracy against historical examiner workpapers.
- [`docs/benchmarks.md`](docs/benchmarks.md) and [`docs/infrastructure.md`](docs/infrastructure.md): measured ingest, assessment, page-load times and memory; hardware sizing.
- [`docs/deployment_ops.md`](docs/deployment_ops.md) and [`docs/offline_install.md`](docs/offline_install.md): air-gapped deployment, wheelhouse install, rule packs, backups.
- [`docs/first_run_setup.md`](docs/first_run_setup.md), [`docs/security/mfa.md`](docs/security/mfa.md): production setup token, first administrator, administrator second factor; demo deployments.
- [`docs/backup_restore.md`](docs/backup_restore.md), [`docs/migrations.md`](docs/migrations.md), [`docs/key_management.md`](docs/key_management.md), [`docs/api_credentials.md`](docs/api_credentials.md): backup and restore, schema migrations, pseudonymisation keys, submission-API credentials.
- [`docs/ps_traceability.md`](docs/ps_traceability.md) and [`docs/legal_traceability.md`](docs/legal_traceability.md): requirement to code, test and evidence; statutory context for legal review.
- [`docs/usability_protocol.md`](docs/usability_protocol.md): timed examiner tasks (no session run yet).
- [`docs/slides_outline.md`](docs/slides_outline.md), [`docs/demo_script.md`](docs/demo_script.md): presentation outline and demo click-path.
- [`EVIDENCE.md`](EVIDENCE.md) and [`docs/CHANGES_quality_pass.md`](docs/CHANGES_quality_pass.md): commands and results, open items, doc/code mismatches found and fixed.
