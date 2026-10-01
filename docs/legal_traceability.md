# SAT-SA Legal and Requirement Traceability

> **Supervisory Notice:** *Indicators requiring supervisory review; not a compliance determination.*

This document maps each requirement of problem statement SIH26157 to the component that
addresses it and the test that checks it, and sets out what can and cannot be said about the
statutory context. **It is an engineering document, not legal advice.** Every entry in the
"Statutory context" columns that goes beyond quoting a text is marked **needs legal review**.

## 1. Sources, and how far each was verified

| Source | How it was read | Status |
|---|---|---|
| Problem statement SIH26157, <https://sih2026.vuce.in/ps/SIH26157> | Fetched on 2026-09-30 through a page-summarising fetch tool. The requirement wording in Section 3 is as that tool quoted it. | Wording should be re-checked against the page by a person before it is quoted in a submission. |
| Information Technology Act, 2000, Section 70A | Text as returned by a web search on 2026-09-30 (Indian Kanoon / India Code listings). The official India Code page refused the automated fetch (HTTP 403). | **Needs legal review**: confirm against the official Gazette / India Code text. |
| NCIIPC designation under Section 70A | Secondary sources only (gazette notification of 16 January 2014, as reported). | **Needs legal review.** |
| Information Technology (NCIIPC and Manner of Performing Functions and Duties) Rules, 2013 | **Not read.** | **Needs legal review.** No statement in this repository should attribute a requirement to these Rules. |
| CERT-In directions on incident reporting (Section 70B) | **Not read.** | **Needs legal review.** Relevant to NS07 only (Section 4). |

## 2. The statutory context, stated no further than the text goes

Section 70A of the IT Act, 2000, as retrieved:

> (1) The Central Government may, by notification published in the Official Gazette, designate
> any organisation of the Government as the national nodal agency in respect of Critical
> Information Infrastructure Protection.
> (2) The national nodal agency designated under sub-section (1) shall be responsible for all
> measures including Research and Development relating to protection of Critical Information
> Infrastructure.
> (3) The manner of performing functions and duties of the agency referred to in sub-section (1)
> shall be such as may be prescribed.

What follows from that, and what does not:

- Section 70A is an **enabling provision**: it designates a nodal agency and makes it
  responsible for CII protection measures. It does not mention SOC assessment, supervisory
  analytics, audit trails, determinism, evidence standards or any technical control.
- **The problem statement cites no law.** It names NCIIPC as the body that "performs manual
  reviews of samples of security alerts and case-management records"; it does not cite
  Section 70A or any statute.
- So the honest chain is: NCIIPC is (per secondary sources) the agency designated under
  Section 70A; the problem statement says NCIIPC reviews SOC records; SAT-SA supports that
  review. **Whether Section 70A, or the Rules made under it, empower NCIIPC to require CSEs to
  submit SOC records, to issue directives, or to rely on this tool's output, is a legal
  question this project has not answered: needs legal review.**
- SAT-SA therefore claims no statutory force for its output. Every page, report and export
  says so (Section 5).

**Corrections made in this pass.** Earlier UI text attributed specific requirements to the
law. None could be supported and all were removed or reworded:

| Where | Earlier wording | Now |
|---|---|---|
| `/tuning` | "Under Rule 3 of NCIIPC Rules, 2013, all supervisory assessment parameters must maintain mathematical determinism." | States that assessment is deterministic and changes are audited; no legal attribution. |
| `/runs` | "...under Section 70A evidence standards." | Removed. Section 70A defines no evidence standard. |
| `/upload` | badge "Section 70A Registry" | "Entity Registry" |
| `/blind-review` | "Statutory Recommendation", "Issue Formal Audit Directive under Sec 70A" | "Examiner Recommendation", "Recommend Formal Audit Directive" |
| `/finding/...` | "Statutory Notice:" | "Supervisory Notice:" |

Wording still in the product or its documents that **needs legal review** before use outside a
demonstration:

- `/queue`: the examiner status "Escalate to Statutory Notice". What instrument that refers to,
  and who may issue it, is not established here.
- `docs/functional_design.md` Section 3 and `README.md` ("Regulatory Compliance & Statutory
  Boundary"): describe SAT-SA as operating "under the statutory authority of Section 70A". The
  supportable statement is the chain above.
- `docs/demo_script.md`: "strictly grounded under Section 70A of the IT Act, 2000".

## 3. Requirement traceability

"Statutory context" is the same for every functional row: the requirement comes from the
problem statement, which cites no law; its link to Section 70A is the chain in Section 2
(**needs legal review**). The column is therefore given once per group.

### 3.1 Functional requirements (statutory context: problem statement only; Section 70A link needs legal review)

| # | Requirement (as quoted from the problem statement) | Component | Test or measured evidence | Status |
|---|---|---|---|---|
| F1 | "Ingest structured data from multiple CSEs" | `IngestionPipeline` (`src/satsa/ingest/pipeline.py`), per-entity Parquet partitions | `tests/test_ingest.py`, `tests/test_connectors.py` | Met |
| F2 | "Support common formats such as CSV, JSON, database exports and APIs" | `SourceAdapter` (csv, json/ndjson, sqlite, loopback-only REST); SQLite exports (`.db/.sqlite/.sqlite3`) read by `IngestionPipeline` table by table; `satsa ingest --api-config` stages local REST endpoints and ingests them; product mappings for Splunk ES, ServiceNow SIR, TheHive 5 | `tests/test_ingest.py` (`test_read_api_from_local_fixture` and neighbours), `tests/test_connectors.py`, `tests/test_anomaly_scan.py` (SQLite export ingests to the same row counts as the CSV files; API submission staged and ingested; non-loopback endpoint refused) | Met end to end for all four. Product mappings tested on hand-built samples only (`docs/connectors.md`); the API path is tested on fixture responses, not a live ticketing system. (Updated: SQLite and API used to be tested as adapters only, not wired into `satsa ingest`.) |
| F3 | "Support analysis of large datasets spanning multiple entities and time periods" | Chunked ingest, DuckDB over Parquet, analytics cache | `docs/benchmarks.md`: 50 entities x 100,000 alerts (5,000,000 alerts, 21.4M rows) ingested in 603 s and assessed in 310 s on the machine described there | Met on one machine, synthetic uniform data |
| F4 | "Identify indicators of detection, investigation and escalation weaknesses" | 20 rules across 8 domains (`src/satsa/rules/`) | `tests/test_rules.py`, `tests/test_validation_integrity.py` | Met on synthetic data only |
| F5 | "Detect potential execution gaps" | EG01-EG12 (`rules/execution_gaps.py`) | `tests/test_rules.py::test_injected_defects_detection`, `docs/validation_report.md` | Met on synthetic data only |
| F6 | "Detect potential negative space" | NS01-NS08 (`rules/negative_space.py`) | same | Met on synthetic data only |
| F7 | "Identify anomalies, outliers and suspicious operational patterns" | Robust z-scores (median/MAD) in NS03 and EG11; burst and boilerplate patterns in EG04, EG06, EG07; exploratory anomaly scan (`satsa/peers/anomaly_scan.py`): about 40 rates per entity tested for peer outliers (robust z >= 3.5) and for time shifts within the period (CUSUM against the entity's first three months), shown as leads on the entity profile | `tests/test_validation_integrity.py`, `tests/test_anomaly_scan.py` (leads only on entities with injected defects, none on the three clean ones; CSE-10's volume collapse found as a time shift; deterministic; leads do not change scores) | Met, on synthetic data. Leads are not scored (DECISIONS.md ADR-007); their false-positive rate on real submissions is unmeasured until the shadow pilot. |
| F8 | "Perform peer comparison and benchmarking across entities" | `PeerResolver`; peer baselines in EG01, NS02, NS03, EG11; every metric of the anomaly scan benchmarked against the same cohort; entity radar against the peer median | `tests/test_validation_integrity.py` (peer-baseline tests), `tests/test_anomaly_scan.py` | Met: 4 of 20 rules use a peer baseline, and the anomaly scan benchmarks about 40 operational rates per entity against its cohort. The other 16 rules keep fixed thresholds by design (a zero-tolerance control such as EG03 should not relax because peers also fail it). |
| F9 | "Generate entity-level supervisory risk indicators" | `ScoringEngine` (rule -> domain noisy-OR -> risk index and band) | `tests/test_scoring.py` | Met |
| F10 | "Prioritise entities, controls, processes and alert samples for manual review" | Entity ranking; `ReviewPrioritiser` queue (cited records plus random controls); `satsa/scoring/control_priorities.py` ranks controls (rules, by entities failing, severity, score; untested entities shown) and processes (domains, by entities scoring 50 or more, then portfolio median) on the portfolio page and `GET /api/v1/priorities` | `tests/test_scoring.py`, `tests/test_validate.py`, `tests/test_anomaly_scan.py` (ordering and agreement with stored findings); lift figures in `docs/validation_report.md` | Met for all four. (Updated: controls and processes used to be prioritised only through the domain scores.) |
| F11 | "Provide clear rationale for findings" | Rationale text on every `Finding`; plain-language headlines in PDFs | `tests/test_report_pdf.py`, `tests/test_scoring.py` | Met |
| F12 | "Present supporting evidence" | `FindingEvidence` records for every finding | `tests/test_rules.py::test_every_finding_carries_evidence_records` | Met |
| F13 | "Support traceability and auditability of results" | Hash-chained audit log, run manifest (config hash, reference date), submission manifest | `tests/test_audit_tamper.py`, `tests/test_store.py`, `tests/test_validation_integrity.py::test_no_rule_reads_the_wall_clock` | Met; limits in `DECISIONS.md` ADR-005 |
| F14 | "Allow supervisors to understand why an entity or activity was flagged" | Finding card: rationale, parameters used, benign explanations, examiner check | `tests/test_scoring.py`, `tests/test_api.py` | Met |
| F15 | "Generate supervisory dashboards and reports" | Web app (`/portfolio`, `/entity`, `/queue`), HTML/PDF/CSV reports | `tests/test_api.py`, `tests/test_report.py`, `tests/test_report_pdf.py` | Met |
| F16 | "Support trend analysis across entities and time periods" | Historical runs, `satsa seed-history`, portfolio trend chart | `tests/test_trends.py` | Met on re-assessed windows of one dataset |
| F17 | "Enable drill-down from supervisory findings to underlying evidence" | `/entity/{id}` -> `/finding/{id}` -> evidence records; evidence ids in PDFs | `tests/test_api.py`, `tests/test_report_pdf.py` | Met |

### 3.2 Deployment requirements (statutory context: none cited; needs legal review if a security standard is to be claimed)

| # | Requirement | Component | Test | Status |
|---|---|---|---|---|
| D1 | "Operate in a fully offline (air-gapped) network" | No outbound calls; vendored assets; loopback-only REST adapter | `tests/test_offline.py`, `tests/test_offline_hardening.py::test_every_get_route_is_offline_and_healthy` (socket guard over every route) | Met |
| D2 | "Require no Internet connectivity" | same | same | Met |
| D3 | "Have no dependency on cloud services" | Local SQLite, DuckDB, Parquet | same; `pyproject.toml` | Met |
| D4 | "Have no dependency on SaaS platforms" | same | same | Met |
| D5 | "Have no dependency on externally hosted AI models or APIs" | No AI/ML at all: SQL, robust statistics, templates | `pyproject.toml` dependency list | Met. The problem statement's AI/ML specification clause applies only "where AI or machine learning is proposed": not applicable. |
| D6 | "Support local deployment and local data processing" | `satsa serve`, Docker image, offline bundle | `tests/test_bundle.py`, `tests/test_serving.py` | Met. The Docker image was not built or run in this pass (no Docker on the test machine). |

### 3.3 Out-of-scope items (what SAT-SA must not be)

| # | Out of scope | How SAT-SA stays out | Test |
|---|---|---|---|
| O1-O6 | Not a SOC, not real-time monitoring, not a SIEM, not a centralised SOC, no continuous log collection, not a national monitoring platform | Periodic batch submissions only; one batch per entity and period; no collector | `tests/test_batch_submission.py` (a repeat submission is refused) |

### 3.4 Other statements in the problem statement

| Statement | Component | Test | Status |
|---|---|---|---|
| "minimise dependence on raw logs, packet captures, customer information, or other sensitive operational data" | Works on alert and case metadata; pseudonymisation; comment redaction and hashing; only canonical columns stored | `tests/test_connectors.py::test_no_personal_identifier_from_an_export_is_stored`, `tests/test_ingest.py` (pseudonymisation, redaction and column tests) | Met. **Needs legal review:** whether pseudonymised analyst identifiers are personal data under the Digital Personal Data Protection Act, 2023, and what retention applies. Not assessed. |
| "It is not intended to replace supervisory judgement." | Supervisory notice on every output; blinded review; examiner decisions recorded separately from the tool's findings | `tests/test_supervisory_notice.py`, `tests/test_blind_review.py` | Met |

## 4. NS07 (absent external reporting)

NS07 flags a critical incident case with no record of an external report. The rule checks
**presence only**. It does not check any reporting deadline, and it does not decide whether an
incident was reportable. Which incidents must be reported, to whom and within what time is set
by instruments this project has not read (**needs legal review**). NS07's output is an
indicator for an examiner to follow up, like every other finding.

## 5. The supervisory notice, and pseudonymisation and redaction tests

| What | Where it is checked |
|---|---|
| The notice on every web page (both roles, and signed out) | `tests/test_supervisory_notice.py::test_every_page_of_the_web_app_carries_the_notice` |
| The notice on every page of every PDF | `::test_every_page_of_every_pdf_carries_the_notice`, `::test_pdfs_served_by_the_app_carry_the_notice` |
| The notice in HTML reports | `::test_html_reports_carry_the_notice`, `tests/test_report.py` |
| The notice on every record of the JSON and CSV exports | `::test_json_exports_carry_the_notice_on_every_record`, `::test_csv_exports_carry_the_notice_on_every_row` |
| No unsupported legal attribution on any page | `::test_no_page_claims_a_legal_basis_the_project_cannot_cite` |
| Pseudonymisation is deterministic and salted | `tests/test_ingest.py::test_pseudonymiser_determinism` |
| Analysts pseudonymised even when the source has no closer-type column; case owners pseudonymised | `tests/test_ingest.py::test_analyst_is_pseudonymised_when_the_source_has_no_closer_type_column`, `::test_case_owner_is_pseudonymised_and_service_accounts_are_left_readable` |
| Redaction of IPs, e-mail addresses, hostnames, long numbers | `tests/test_ingest.py::test_redactor_and_shingles` |
| Free text and unknown columns never stored | `tests/test_ingest.py::test_free_text_and_unknown_columns_are_not_stored` |
| No identifier from a product export reaches any store | `tests/test_connectors.py::test_no_personal_identifier_from_an_export_is_stored` (Splunk, ServiceNow, TheHive samples) |

**Before this pass** the notice appeared on the finding page and the HTML reports only, not on
the portfolio, entity or queue pages, the PDFs, or the JSON/CSV exports, although the
traceability matrix said it was on every view. Three privacy defects were also found and fixed
(`docs/connectors.md` Section 4).

**Known limit of redaction.** It is pattern-based. A person's name typed into a free-text
comment is not recognised by any pattern; that is why the comment text and its word shingles
are not stored at all, only hashes.

## 6. Open legal items

1. Confirm the text of Section 70A and the NCIIPC designation against official sources.
2. Read the 2013 Rules and establish what powers and procedures they give NCIIPC with respect
   to CSE SOC records; adjust the documents listed in Section 2 accordingly.
3. Establish the reporting obligations NS07 is a proxy for.
4. Assess the tool's own data (pseudonymised identifiers, examiner decisions, audit log)
   under the Digital Personal Data Protection Act, 2023, including retention.
5. Re-check the quoted requirement wording against the problem-statement page.
