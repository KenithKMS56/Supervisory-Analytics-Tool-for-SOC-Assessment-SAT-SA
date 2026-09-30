# PS SIH26157 Traceability Matrix

> **Sourcing caveat (read before using this in a slide):** the verbatim official problem-statement
> document for SIH26157 (NTRO/NCIIPC, "Supervisory Analytics Tool for SOC Assessment") could not be
> independently re-fetched in full during this work session -- no complete, authoritative copy of
> its numbered requirements text was reachable. The "PS Requirement" column below paraphrases the
> capability areas as corroborated across multiple independent public sources referencing PS26157
> (the SIH problem-statement catalogue, and several independent teams' repositories built against
> the same PS), and the numbering 1-17 is this document's own enumeration of those capability areas,
> **not a verbatim quotation of the official numbered list**. Before this table is used in an
> official submission, cross-check it against the actual PS document text and correct any numbering
> or wording drift. Every entry in the "SAT-SA Component / Evidence" and "Evidence" columns, by
> contrast, is a direct, verifiable pointer into this repository's actual code, routes, and docs.

---

## Functional Requirements

| # | PS Functional Requirement (paraphrased, see caveat above) | SAT-SA Component | Evidence |
|---|---|---|---|
| 1 | Provide an offline, air-gapped tool for a supervisory examiner to assess how well a CSE ran its SOC, using the CSE's own periodic submission as evidence. | Whole application; binds to `127.0.0.1`, zero CDN or outbound network calls. | `satsa serve` (`src/satsa/cli.py`); air-gap enforced and tested in `tests/test_offline.py`. |
| 2 | Ingest periodic SOC alert and case-management data from disparate sources: CSV, JSON, DB exports, and APIs. | `IngestionPipeline`, `SourceAdapter` (csv/json/sqlite/api). | `src/satsa/ingest/pipeline.py`, `src/satsa/ingest/adapters.py::read_api`; routes `/upload`, `POST /api/v1/submissions` (one batch per entity and period; repeats get 409). |
| 3 | Normalize disparate SIEM/ticketing schemas (e.g. Splunk, ServiceNow, TheHive, generic REST ticketing) into one canonical model. | `CSEMapper`, `TaxonomyNormaliser`, per-source mapping configs. | `src/satsa/ingest/mapper.py`, `config/mappings/cse_splunk.yaml`, `cse_servicenow.yaml`, `cse_thehive.yaml`, `cse_api_ticketing.yaml`. |
| 4 | Detect "execution gaps": documented procedure/reported metric vs. what operational records actually show. | 12 EG rules. | `src/satsa/rules/execution_gaps.py` (EG01-EG12); catalog at `/rules`, config `config/rules.yaml`. |
| 5 | Detect "negative space": evidence that is expected but absent (e.g. missing alert categories, silent assets, missing escalations/reports). | 8 NS rules. | `src/satsa/rules/negative_space.py` (NS01-NS08). |
| 6 | Surface additional supervisory signals beyond the illustrative EG/NS examples, including cross-entity patterns. | Cross-entity systemic correlation detector. | `src/satsa/rules/systemic.py`, `config/systemic.yaml`; portfolio dashboard "Systemic / Cross-Entity Findings" section (`/`). |
| 7 | Benchmark each entity against its sector/size peer cohort using robust statistics, not raw thresholds alone. | **Partial.** `PeerResolver` cohorts are used by EG01 (peer p5 close-time baseline, entity excluded), NS02 (categories reported by a share of peers), and NS03 and EG11, which flag robust z-score (median/MAD) outliers against the cohort. The other rules use fixed thresholds; IQR and `SPCDetector` (CUSUM/EWMA) are implemented but not used by any rule or score. | `src/satsa/peers/grouping.py`, `src/satsa/rules/base.py::peer_filter`; `src/satsa/rules/base.py::robust_z` (uses `src/satsa/peers/robust_stats.py`); SPC in `src/satsa/peers/spc.py` is unused. **Correction:** an earlier version of this row listed robust z/MAD/CUSUM/EWMA as delivering this requirement. |
| 8 | Every finding must be deterministic, cite the exact source records it came from, and be explainable to a non-technical examiner. | `Finding`/`FindingEvidence` models; finding-card rationale templates. | `src/satsa/models/outputs.py`, `src/satsa/explain/finding_card.py`; finding detail view `/finding/{finding_id}`. |
| 9 | No dependency on externally hosted AI models or APIs; local deployment and local data processing. The PS's AI/ML clause is conditional: *"Where AI or machine learning is proposed, participants shall specify"* model architecture, hardware requirements, offline training/inference, model update mechanism, explainability controls and auditability controls. | SAT-SA proposes **no** AI/ML: detection, scoring and every rationale are deterministic SQL, classical robust statistics and static templates. The conditional AI/ML specification clause is therefore **N/A by design**. | `DECISIONS.md` ADR-001; `pyproject.toml` has no ML/LLM dependency. **Correction:** an earlier version of this row said the PS describes an "optional local-LLM restatement layer" and listed it as an unmet roadmap gap. The official PS text (https://sih2026.vuce.in/ps/SIH26157, checked during the hardening pass) contains no such requirement, so that claim was removed. |
| 10 | Produce a composite, explainable supervisory risk score per entity, aggregated from multiple capability domains. | `ScoringEngine`: rule score -> domain score (noisy-OR) -> entity risk index. | `src/satsa/scoring/scorer.py`; methodology `docs/analytics_methodology.md` Section 4. |
| 11 | Prioritize a manageable review queue for human examiners rather than dumping raw findings. | `ReviewPrioritiser`: stratified top-risk + random-control queue. | `src/satsa/scoring/prioritiser.py`; `/queue` view. |
| 12 | Maintain a tamper-evident audit trail of ingestion, assessment runs, configuration changes, and examiner actions. | Hash-chained `audit_log` (SHA3-256 for new entries, legacy SHA-256 entries still verify) plus off-box checkpoints for truncation. | `src/satsa/store/sqlite.py::append_audit/verify_chain/verify_checkpoint`; `/runs`, `satsa audit verify`, `satsa audit head`; limits in `DECISIONS.md` ADR-005. |
| 13 | Control who can ingest data, trigger runs, calibrate rules, and log review dispositions. | Local RBAC (admin/supervisor/examiner), PBKDF2-hashed identities, cookie sessions. | `src/satsa/auth/`; `/login`; gated routes in `src/satsa/api/routes.py` (see `docs/functional_design.md` Section 2); `tests/test_auth.py`. |
| 14 | Check submitted data for completeness/quality issues (missing fields, sequence gaps, high null rates) before scoring. | `DQValidator`, NS08 (submission completeness). | `src/satsa/ingest/dq_checks.py`; `/dq` view. |
| 15 | Generate supervisory-facing reports (per-entity and portfolio) suitable for a regulatory dossier. | `ReportGenerator`: HTML + PDF + CSV exports. | `src/satsa/report/generator.py`; `/reports/*` routes. |
| 16 | Allow supervisors to calibrate rule thresholds and distribute an updated, verifiable rule pack. | Rule tuning UI + cryptographically signed rule-pack export/import. | `/tuning`, `/tuning/export-pack`, `/tuning/import-pack`; `src/satsa/bundle/rules_signer.py`. |
| 17 | Validate detection accuracy against ground truth and, ideally, real historical examiner findings, and be honest about what that validation does and doesn't prove. | Synthetic detector-correctness harness + stress scenario + shadow-pilot adapter for real historical data. | `src/satsa/validate/harness.py`; `satsa validate`, `satsa validate-stress`; `docs/validation.md` (Sections 0, 2, 2A, 5). |

---

## Out-of-Scope Confirmations

| # | Out-of-Scope Item | SAT-SA's Confirmation |
|---|---|---|
| A | SAT-SA is not a SOC, not a SIEM, and does not provide real-time monitoring or continuous telemetry ingestion. | The tool only ever operates on periodic batch submissions (`/upload`, `POST /api/v1/submissions`) evaluated after the fact at each periodic assessment cycle; there is no always-on collector and no per-second alerting anywhere in `src/`. The JSON endpoint accepts exactly one batch per entity and period (a repeat returns HTTP 409), so it cannot act as a continuous feed. The Admin Portal's activity feed monitors SAT-SA's own operators (sign-ins, report downloads), not CSE logs or telemetry (DECISIONS.md ADR-006). |
| B | SAT-SA's output is a set of indicators for supervisory review, not an automated compliance determination or legal adjudication. | Every UI view, report, and export carries the statutory notice *"Indicators requiring supervisory review; not a compliance determination"* (`src/satsa/ui/templates/base.html` footer; `docs/functional_design.md` Section 3; every generated report in `src/satsa/report/generator.py`). |

---

## Deliverables

| # | Deliverable (standard SIH deliverable categories; see sourcing caveat above) | Status / Evidence |
|---|---|---|
| 1 | Working prototype / functional software | `satsa serve` launches the full offline dashboard; `satsa run`/`satsa validate` exercise the full pipeline end to end. |
| 2 | Source code | This repository, `src/satsa/`. |
| 3 | Setup / deployment instructions | `README.md`, `docs/deployment_ops.md`, `Containerfile`, `Makefile`, `satsa offline-bundle`. |
| 4 | Architecture & design documentation | `docs/architecture.md`, `docs/functional_design.md`, `docs/analytics_methodology.md`, `docs/data_requirements.md`, `DECISIONS.md`. |
| 5 | Presentation / pitch material | `docs/slides_outline.md`, `docs/demo_script.md`. |
| 6 | Validation / evidence of correctness | `docs/validation.md`, `docs/validation_report.md`/`.html`, `docs/validation_stress_report.md` (see Section 0 of `docs/validation.md` for what each of these does and does not prove). |
