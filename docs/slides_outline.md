# SAT-SA Executive Presentation: 5-Slide Outline

> **Supervisory Notice:** *Indicators requiring supervisory review; not a compliance determination.*

---

## Slide 1: Problem & Regulatory Mission
- **Regulatory Challenge:** NCIIPC oversees SOC operations across Critical Sector Entities (Power, Banking, Telecom, Transport, Oil & Gas). Standard compliance audits rely on static questionnaires and self-declared KPIs that fail to detect operational degradation, metric gaming, or surveillance blindspots.
- **The SAT-SA Solution:** The **Supervisory Analytics Tool for SOC Assessment (SAT-SA)** ingests raw telemetric feeds (Splunk, ServiceNow, TheHive) and applies deterministic relational analytics and robust statistics to surface objective operational realities.
- **Guiding Principle:** Strict supervisory support, not subjective compliance verdicts. Every finding provides evidentiary proof for human examiner verification.

---

## Slide 2: Architectural Foundation & "No AI/ML" Commitment
- **Zero Black-Box Risk:** 100% deterministic execution. Zero LLMs, zero neural networks, zero generative hallucinations. Explainable by design.
- **Air-Gapped & Offline Security:** Default binding to `127.0.0.1`, zero external CDN dependencies, vendored Apache ECharts, and socket-level outbound blocking.
- **Data Minimization & Privacy:** HMAC-SHA256 pseudonymisation of human analyst handles and regex redaction of sensitive internal network IPs and PII.
- **Cryptographic Auditability:** Hash-chained audit log (SHA3-256) that exposes edits, insertions and deletions within the chain; off-box `satsa audit head` checkpoints catch truncation of the newest entries. Limits stated in ADR-005.

---

## Slide 3: Detection Heuristics: Execution Gaps & Negative Space
- **Execution Gaps (EG01–EG12):** Detects operational shortcuts, metric manipulation, and triage failures:
  - *Example EG01:* High/Critical alerts closed in $<120$ seconds without investigation.
  - *Example EG06:* SLA deadline-hugging, bulk closures, and MTTA/MTTR gaming.
  - *Example EG10:* Discrepancies between declared KPIs and empirical telemetry.
- **Negative Space (NS01–NS08):** Detects what is missing from telemetry:
  - *Example NS01:* Critical monitored assets that have gone completely silent ($>3$ days zero logs).
  - *Example NS03:* Collapse of nighttime and weekend logging activity (lack of 24x7 coverage).
  - *Example NS06:* Shadow assets (telemetry without CMDB record) and ghost assets (inventory without logs).

---

## Slide 4: Explainability, Scoring & Validation Results
- **Calibrated Scoring:** Classical robust statistics (Median, MAD, IQR, CUSUM/EWMA) benchmark entities against sector peers. Probabilistic Noisy-OR aggregates scores into 8 capability domains.
- **Review Queue Prioritisation:** 70% top-risk alerts + 30% stratified random controls to measure lift and catch blindspots.
- **Empirical Ground-Truth Validation:**
  - **Entity Rank Precision@7:** **100.0%** (all 7 injected entities ranked in top 7; clean entities at bottom).
  - **Injected Defect Recall:** **100.0%** (11/11 injected defects discovered).
  - **Review-Effort Lift:** **16.60x** more defects discovered at 1% audit budget vs random sampling.
  - **Ranking Stability:** Spearman $\rho = \mathbf{1.0000}$ under $\pm 20\%$ parameter perturbations.

---

## Slide 5: Deployment, Operational Sizing & Roadmap
- **Hardware Efficiency:** Executes on standard commodity CPUs. DuckDB columnar engine aggregates at $>10\text{M}$ rows/second; full 5-million alert assessment completes in under 10 minutes.
- **Operational Packaging:** Single self-contained offline bundle (`tar.gz`), containerized `Containerfile`, and signed versioned rule packs (`satsa rules import`).
- **Implementation Roadmap:**
  - *Phase I (Current):* Standalone offline forensic station and examiner portal.
  - *Phase II (Next):* Secure automated quarterly batch drops via encrypted air-gap media.
  - *Phase III:* Sector-wide anonymized peer benchmark registry across national critical sectors.
