# SAT-SA Executive Presentation: 5-Slide Outline

> **Supervisory Notice:** *Indicators requiring supervisory review; not a compliance determination.*

---

## Slide 1: Problem & Regulatory Mission
- **Regulatory Challenge:** NCIIPC oversees SOC operations across Critical Sector Entities (Power, Banking, Telecom, Transport, Oil & Gas). Standard compliance audits rely on static questionnaires and self-declared KPIs that fail to detect operational degradation, metric gaming, or surveillance blindspots.
- **The SAT-SA Solution:** The **Supervisory Analytics Tool for SOC Assessment (SAT-SA)** ingests periodic batch submissions exported from CSE tools (Splunk, ServiceNow, TheHive) and applies deterministic relational analytics and robust statistics to surface objective operational realities.
- **Guiding Principle:** Strict supervisory support, not subjective compliance verdicts. Every finding provides evidentiary proof for human examiner verification.

---

## Slide 2: Architectural Foundation & "No AI/ML" Commitment
- **Zero Black-Box Risk:** 100% deterministic execution. Zero LLMs, zero neural networks, zero generative hallucinations. Explainable by design.
- **Air-Gapped & Offline Security:** Default binding to `127.0.0.1`, zero external CDN dependencies, vendored Apache ECharts, and a best-effort in-process egress guard (loopback-only Python socket connections; does not cover native code or DNS).
- **Data Minimization & Privacy:** HMAC-SHA256 pseudonymisation of human analyst handles and regex redaction of sensitive internal network IPs and PII.
- **Cryptographic Auditability:** Hash-chained audit log (SHA3-256) that exposes edits, insertions and deletions within the chain; Ed25519-signed off-box checkpoints (`satsa audit checkpoint --sign`) catch truncation and full recomputation. Tamper-evident, not tamper-proof; limits in ADR-005 and ADR-008.

---

## Slide 3: Detection Heuristics: Execution Gaps & Negative Space
- **Execution Gaps (EG01–EG12):** Detects operational shortcuts, metric manipulation, and triage failures:
  - *Example EG01:* High/Critical alerts closed in $<120$ seconds without investigation.
  - *Example EG06:* SLA deadline-hugging, bulk closures, and MTTA/MTTR gaming.
  - *Example EG10:* Discrepancies between declared KPIs and KPIs recomputed from the submitted records.
- **Negative Space (NS01–NS08):** Detects what is missing from a submission:
  - *Example NS01:* Critical monitored assets that have gone completely silent ($>3$ days zero logs).
  - *Example NS03:* Collapse of nighttime and weekend logging activity (lack of 24x7 coverage).
  - *Example NS06:* Shadow assets (telemetry without CMDB record) and ghost assets (inventory without logs).

---

## Slide 4: Explainability, Scoring & Validation Results
- **Scoring:** 20 deterministic rules with configurable thresholds; EG01, EG11, NS02 and NS03 compare each entity with its peer cohort (sector/size, with fallback); NS03 and EG11 flag robust z-score outliers (median/MAD) against that cohort. Probabilistic Noisy-OR aggregates scores into 8 capability domains. (CUSUM/EWMA are implemented but not used by any rule.)
- **Review Queue Prioritisation:** records cited by findings, highest risk first, plus stratified random controls to measure lift and catch blindspots.
- **Synthetic Ground-Truth Correctness Check** (not a real-world accuracy benchmark; see docs/validation.md §0):
  - **Entity Rank Precision@7:** **100.0%** (all 7 injected entities ranked in top 7; clean entities at bottom).
  - **Injected Defect Recall / Precision:** **100.0%** (21/21 defects found; 21 of 21 findings correct, every finding counted).
  - **Review-Effort Lift:** the top 25 queue alerts are **19x** as likely to be defect-affected as random alerts (5.2x across the whole 130-alert queue), on the synthetic dataset.
  - **Ranking Stability:** Spearman $\rho = \mathbf{1.0000}$ under $\pm 20\%$ domain-weight perturbations.
  - **Threshold Sensitivity:** every tunable threshold moved ±20%; no move creates a false alarm on a clean entity.
  - **Limits:** all synthetic; real accuracy needs a shadow pilot on historical examiner workpapers.

---

## Slide 5: Deployment, Operational Sizing & Roadmap
- **Hardware Efficiency:** Executes on standard commodity CPUs. DuckDB columnar engine aggregates at $>10\text{M}$ rows/second; full 5-million alert assessment completes in under 10 minutes.
- **Operational Packaging:** Single self-contained offline bundle (`tar.gz`), containerized `Containerfile`, and signed versioned rule packs (`satsa rules import`).
- **Implementation Roadmap:**
  - *Phase I (Current):* Standalone offline forensic station and examiner portal.
  - *Phase II (Next):* Secure automated quarterly batch drops via encrypted air-gap media.
  - *Phase III:* Sector-wide anonymized peer benchmark registry across national critical sectors.
