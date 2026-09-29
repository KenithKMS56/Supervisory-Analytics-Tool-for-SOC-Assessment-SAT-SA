# SAT-SA Functional Design Specification

> **Supervisory Notice:** *Indicators requiring supervisory review; not a compliance determination.*

This document details the functional design, supervisory workflows, user personas, and user interface specifications for the **Supervisory Analytics Tool for SOC Assessment (SAT-SA)**.

---

## 1. Regulatory Context & Scope

SAT-SA enables regulatory supervisors at the **National Critical Information Infrastructure Protection Centre (NCIIPC)** to periodically assess operational SOC data submitted by **Critical Sector Entities (CSEs)** across 5 sectors (Power, Banking, Telecom, Transport, Oil & Gas).

SAT-SA provides evidentiary oversight rather than subjective compliance scoring. It surfaces concrete, verifiable operational anomalies ("execution gaps" and "negative space") and equips examiners with transparent finding cards, record drill-downs, and audit-ready review queues.

---

## 2. User Personas & Permissions (RBAC)

SAT-SA implements a real, local, offline role-based access control (RBAC) layer (`src/satsa/auth/`)
backed by a SQLite `identities` table (usernames + PBKDF2-HMAC-SHA256-hashed passphrases,
`hashlib.pbkdf2_hmac`, 200,000 iterations, no plaintext, no network-dependent identity provider)
and a `sessions` table (random tokens, SHA-256-hashed at rest, cookie-based, 8-hour expiry). Login
is at `/login`; logout at `/logout`. Default demo identities (`admin`, `analyst`, `examiner`,
documented in `src/satsa/auth/identities.py`) are seeded into a fresh database and MUST be rotated
before real deployment via `satsa users set-password <username> --role <role>`.

SAT-SA (`:8001`) has exactly **two operator roles**, following the real regulator workflow: the
analyst operates the pipeline and the examiner makes the regulatory decision. Both use the same app,
and the navigation adapts to the role. Administrators work on the Admin Portal (`:8000`) only.
Every other role (administrators, CSE-scoped accounts) is refused at SAT-SA's `/login`, and any
session such a role holds gets HTTP 403 on every gated path (`enforce_auth_middleware`).

| Role | Primary Responsibilities | Enforced Permissions (server-side, `require_role` / `require_admin_operator`) |
|---|---|---|
| **Admin** (`NCIIPC Super Administrator`) | Identity & registry governance | **Sole** access to the NCIIPC Administration Portal (`:8000`): user provisioning, blocking, credential resets, organisation/CSE registries, admin audit trail, admin activity feed. Portal access is derived from the administrator role only; the legacy `is_admin_user` flag no longer grants it. **No** SAT-SA access. |
| **Analyst** (`NCIIPC Analyst`, formerly *Supervisor*) | Technical operator ("engine room") | Ingest periodic batches (`/upload`, `/upload/add-entity`, `/upload/trigger-demo`, `POST /api/v1/submissions`), trigger assessment runs, calibrate rule thresholds (`/tuning`, `/tuning/save`), export/import signed rule packs, and use the technical views: alert explorer (`/alerts`), rules catalog, data quality (`/dq`), runs & audit ledger (`/runs`, `/audit`, `/api/v1/audit/verify`), CSV templates and raw CSV exports. Sees the review queue read-only. **No** Admin Portal access. |
| **Examiner** (`NCIIPC Examiner`) | Decision maker / auditor | Executive views (portfolio heatmap, entity radar vs peer median, findings, PDF/HTML dossiers) plus the **only** role that records review decisions (`POST /api/v1/feedback`: *Escalate to Statutory Notice*, *Mark as Justified*, *Request CSE Explanation*) and blinded-review verdicts (`POST /blind-review/submit`). HTTP 403 on every analyst-only page. |

Keeping the analyst and examiner apart is deliberate separation of duties: whoever tunes the rules
can't also sign off the findings. The former `supervisor` role is migrated to `analyst` on startup
(`SQLiteStore._migrate_supervisor_to_analyst`); historical audit entries keep their original actor,
so the hash chain still verifies.

**Current scope, stated plainly:** every route is classified in the explicit permission table in
`tests/test_rbac_matrix.py`, and a completeness check fails if a new route is added without being
classified. Public: `/`, `/splash`, `/login`, `/logout`, `/api/session/status` (and static assets).
Everything else requires a session: anonymous browser page loads are redirected to `/login`;
anonymous API calls, downloads and all mutating requests get HTTP 401; a signed-in role outside the
route's allowed set gets HTTP 403 and no state change occurs.

- Executive views (portfolio, entity profile, finding detail, review queue, blind review) and the
  PDF/HTML dossiers and read APIs are open to both operators; entity-level pages still enforce the
  CSE boundary (`require_cse_access`) as defence in depth.
- Technical views and raw exports (alert explorer, rules catalog, DQ view, runs & audit, CSV
  templates, findings/queue CSV exports) are analyst-only.

Remaining gaps, stated plainly:

- No per-route audit trail for *read* access (only state-changing actions are logged to
  `audit_log`, as before).
- No password-complexity policy or expiry on the local identities beyond what an operator enforces
  via `satsa users set-password`.
- Login lockout is per username: 5 failed attempts within 15 minutes (since the last successful
  login) lock that username on both `/login` and the Admin Portal, even for the correct passphrase,
  with the same generic error as an unknown user (`login_locked` / `ADMIN_LOGIN_LOCKED` audit
  entries). There is no per-source-IP rate limiting, so a caller can still lock out a known
  username (accepted trade-off for an air-gapped, small-user-base deployment).

Every gated action's `audit_log.actor` field is populated from the authenticated session identity
(`Identity.username`), never from a caller-supplied form field -- see `src/satsa/api/routes.py`
and `tests/test_auth.py`.

---

## 3. Statutory Authority & Legal Mandate (Section 70A IT Act, 2000)

SAT-SA operates under the statutory authority of **Section 70A of the Information Technology Act, 2000 (read with Information Technology Rules, 2013)**, designating NCIIPC as the national nodal agency for all measures taken to protect Critical Information Infrastructure (CII). 

All system interfaces, outputs, and exports display the statutory supervisory notice:
> *"Indicators requiring supervisory review; not a compliance determination. Issued pursuant to regulatory advisory oversight under Section 70A, IT Act, 2000."*

---

## 4. UI Views & Examiner Workflows

SAT-SA provides ten self-contained, server-rendered UI screens powered by FastAPI, Jinja2, and vendored Apache ECharts (zero CDN dependencies):

### 1. Portfolio Overview (`/`)
- **Executive KPI Cards:** Total entities assessed, portfolio average risk index, total flagged indicators, total review queue records.
- **National Entity Ranking Table:** Entities ranked by composite Supervisory Risk Index (0–100) using Noisy-OR domain aggregation with categorical risk bands (*Low*, *Moderate*, *Elevated Concern*, *High Concern*).
- **8-Domain Supervisory Heatmap:** Matrix visualizing risk scores across all 10 CSEs and 8 capability domains (Threat Detection, Investigation, Escalation, Incident Response, Security Operations, Governance & Oversight, Operational Discipline, Cyber Resilience).
- **One-Click Dossier Exports:** Direct access to Portfolio HTML reports, Findings CSV, and Review Queue CSV.
- **Systemic / Cross-Entity Findings:** a distinct section (rendered only when present) surfacing patterns where 3+ entities sharing the same third-party SOC provider all triggered the identical rule in the same run -- see `satsa.rules.systemic` and `docs/analytics_methodology.md` Section 3A.
- **Multi-Period Risk Trajectory Trend Chart:** plots REAL historical risk_index values from persisted `entity_scores` across past assessment runs (never fabricated); entities with fewer than 2 historical runs are omitted with an "insufficient history" notice rather than padded with synthesized points.

### 2. National Alert Explorer (`/alerts`)
- **Cross-Entity Alert Grid:** Searchable multi-entity alert catalog with live filtering by severity, entity ID, and disposition.
- **Duration & Timing Metrics:** On-page calculation of triage durations (`duration_min`) and display of alert lifecycle states.
- **SOC Summary Statistics:** On-page calculation of total alerts, high/critical count, SOAR automation count, and fleet-wide false-positive rate.

### 3. Blinded Supervisory Review Studio (`/blind-review`)
- **Cognitive Bias Mitigation:** Examiners review raw objective metrics (median MTTA, median MTTR, SOAR automation share, false positive rate, sample comment hashes, silent assets) without seeing algorithmic scores or rule flags.
- **Independent Examiner Inquest Form:** Captures human examiner concern rating (Low/Moderate/Elevated/Critical), recommended audit priority, and statutory recommendation under Sec 70A.
- **Inter-Rater Concordance Matrix:** Side-by-side comparison revealing the examiner's verdict vs. SAT-SA's mathematical risk band, calculating algorithmic concordance percentage ($0\text{--}100\%$) and logging to the tamper-evident audit trail.

### 4. Periodic Submission & Ingestion Wizard (`/upload`)
- **Air-Gapped Batch Ingestion Dropzone:** Drag-and-drop or select CSV, JSON, or ZIP packages for automated ingestion.
- **Data Minimization Pipeline:** Instant HMAC-SHA256 pseudonymisation of analyst identifiers and regex redaction of internal IPs and hostnames.
- **One-Click Demo Launcher:** Instantly re-seeds the canonical 10-CSE synthetic dataset and triggers full assessment.
- **Recent Batch Audit Log:** Displays previous ingestion batches and their cryptographic SHA-256 state hashes.

### 5. Supervisory Rule Calibration & Rule-Pack Studio (`/tuning`)
- **Interactive Threshold Calibration:** Live modification of detection parameters (e.g. EG01 human closure threshold, EG04 comment hash share, NS01 silence threshold, NS02 prevalence).
- **Cryptographic Config Tracking:** Displays active SHA-256 configuration hash.
- **Signed Rule-Pack Studio:** One-click export of signed rule-pack archives (`satsa_signed_rule_pack_v1.0.0.tar.gz`) and HMAC-verified import form.

### 6. Entity Profile (`/entity/{entity_id}`)
- **Supervisory Score Card:** Entity risk index, sector baseline, size band, and number of triggered rules.
- **Radar & Domain Breakdown Chart:** Visual comparison of entity domain scores against peer group medians.
- **Reported vs. Recomputed KPI Panel:** Auditing panel comparing declared entity KPIs (MTTA, MTTR, SLA%) against empirical timestamps calculated directly from the submitted records.
- **Key Findings Table:** Filterable list of all execution gaps and negative space findings flagged for this entity.
- **Direct Dossier Exports:** Instant PDF dossier generation via ReportLab and standalone HTML view.

### 7. Finding Detail & Card View (`/finding/{finding_id}`)
- Complete supervisory finding card containing:
  - **Core Metadata:** Rule ID, title, domain, severity, calibrated score (0–100), and sample confidence rating.
  - **Plain-Language Rationale:** Fully deterministic rationale generated from computed metric values and dynamic peer cut-offs.
  - **Parametric Evidence Table:** Direct links to underlying record IDs (alerts, cases, assets).
  - **Peer Benchmarking Context:** Entity metric value compared side-by-side with peer median, IQR, and percentile rank.
  - **Possible Legitimate Explanations:** Concrete engineering or architectural contexts that could explain the pattern benignly (e.g., automated SOAR triage, scheduled maintenance windows).
  - **Suggested Examiner Checks:** Step-by-step instructions for on-site or evidentiary examination.
  - **Known Limitations:** Data assumptions and boundaries of the detection heuristic.

### 8. Review Queue (`/queue`)
- **Stratified Queue Composition:** 70% top-risk items (highest accumulated rule severity) combined with 30% stratified random control samples (partitioned by entity and severity).
- **Examiner Feedback Capture:** Examiners can mark each record as `Confirmed Issue`, `Not an Issue / Benign Context`, or `Needs More Data`, alongside explanatory notes.
- **CSV Export:** One-click download of the complete review queue for field examiners.

### 9. Data Quality & Coverage (`/dq`)
- Summary of schema conformity, missing mandatory fields, sequence gaps, timestamp inversions, and high null rates.
- Reports rules skipped due to insufficient or unmonitored data feeds.

### 6. Runs & Audit Trail (`/runs`)
- History of all assessment runs with execution timestamps, config hashes, input data manifests, and row counts.
- On-demand verification of the `prev_hash` hash chain (each entry checked with its recorded algorithm), reporting the first entry whose contents or links no longer match. This does not by itself detect removal of the newest entries -- compare against an off-box `satsa audit head` checkpoint for that (DECISIONS.md ADR-005).

---

## 4. Examiner Feedback Loop & Supervisory Tuning

1. **Non-Corrupting Design:** Examiner feedback is strictly recorded in the SQLite database for regulatory tracking. **Feedback does not alter mathematical scoring models automatically**, preventing feedback loop distortion or model drift.
2. **Periodic Calibration:** Supervisors inspect historical examiner confirmation rates per rule. If a rule demonstrates high false-alarm rates for specific sectors, supervisors manually adjust thresholds in `config/rules.yaml` and export a newly signed rule pack.

---

## 5. Supervisory Report Deliverables

- **Per-Entity Report (HTML & PDF):** Self-contained, printable supervisory report. The HTML version has a risk summary, domain table, finding table and review queue sample. The A4 PDF (`GET /reports/entity/{id}/pdf`) has a risk gauge, a domain bar chart and layered finding cards.
- **Portfolio Summary Report (HTML & PDF):** Cross-entity briefing for supervisory leadership. The A4 PDF (`GET /reports/portfolio/pdf`) opens with an "N of M CSEs require supervisory attention" cover page (risk index ≥ 25, the dashboard's threshold). It then has an entity ranking chart, a domain-weakness chart, escalation findings, data-quality limitations and an appendix table.
- **Finding Report (PDF):** A single-finding evidence report (`GET /reports/finding/{id}/pdf`, supervisory roles only). It gives one verdict (action badge + plain-language headline), a paired comparison chart where the rule stores two same-unit values (NS03, EG10), and the technical record.
- **Layered finding cards (all PDFs):**
  - Tier 1 is for non-technical readers: an ESCALATE / MONITOR / NOTE badge (from severity critical / high / other) and a one-sentence headline. The headline is filled only from the finding's stored values (`src/satsa/report/plain_language.py`).
  - Tier 2 is a shaded Technical Detail box: the rule and version, the unchanged rationale, the measured values and the evidence record IDs from `finding_evidences`.
- **Offline rendering:** All PDFs are rendered with ReportLab (`reportlab.graphics.charts`) on A4, with no network access. Charts carry band text labels and patterns, so they still read correctly in grayscale.
- **Statutory Footer Notice:** Mandatory on every generated report and UI footer:
  > *"Indicators requiring supervisory review; not a compliance determination."*
