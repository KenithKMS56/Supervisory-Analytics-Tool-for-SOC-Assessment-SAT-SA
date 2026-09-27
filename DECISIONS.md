# SAT-SA Architecture & Design Decisions

This document records architectural decisions, context, rationale, and alternatives considered during the development of SAT-SA.

## ADR-001: Strict Adherence to No AI/ML Hard Constraint
- **Decision:** All analytics, detection, scoring, and text rationales are strictly deterministic, relying on DuckDB SQL, classical robust statistics (median, MAD, robust z-score, CUSUM, EWMA, Jaccard similarity), and static string templates.
- **Reason:** We chose full determinism over ML-based detection because the problem statement weights Explainability & Auditability equally with detection performance, and a rule-based system gives supervisors a traceable, court-defensible rationale for every finding: each score can be reproduced by hand from the same inputs, and every finding cites the exact records and thresholds that produced it. This is a design choice made in service of that criterion, not a literal textual mandate in the problem statement for "complete determinism."
- **Alternatives Considered:** Lightweight regression/decision trees, local embeddings. Rejected because they would trade away byte-identical reproducibility and per-finding explainability for a detection-accuracy gain that is unverifiable against the tool's own synthetic validation set (see docs/validation.md's "detector-implementation correctness" framing) and would be far harder for a non-technical examiner to independently audit.

## ADR-002: Dual-Store Architecture (DuckDB + SQLite)
- **Decision:** Use DuckDB querying partitioned Parquet files (`data/parquet/{entity_id}/{year_month}/...`) for high-performance columnar analytical queries on millions of alerts. Use SQLite (`data/satsa.db`) for operational state: run manifests, finding cards, review queues, examiner feedback, and cryptographically chained audit logs.
- **Reason:** DuckDB excels at columnar vector scans and group-by aggregations without loading entire datasets into RAM. SQLite provides ACID transactional integrity, simple schema migrations, and reliable single-file persistence for audit logs.
- **Alternatives Considered:** Pure SQLite (insufficient performance for 5M+ rows), PostgreSQL (requires external daemon, violating simple offline air-gap deployment).

## ADR-003: Pure-Python and Local Vendored Assets for Offline Guarantee
- **Decision:** Vendor Apache ECharts locally in `src/satsa/ui/static/echarts.min.js`. All HTML templates render without external fonts or CDN stylesheets. PDF generation uses `reportlab` (pure Python).
- **Reason:** Hard constraint requires SAT-SA to function in an air-gapped environment with no internet access.
- **Alternatives Considered:** CDN references with local cache fallback. Rejected because external network lookups would violate the strict air-gap test.

## ADR-004: Cryptographic Audit Chaining (`prev_hash`)
- **Decision:** Every entry in `audit_log` includes `prev_hash = SHA256(previous_row_bytes)`. Verification traverses the chain and detects any unauthorized update, deletion, or tampering.
- **Reason:** Guarantees tamper-evidence for supervisory audits and inspections.
- **Alternatives Considered:** Blockchain/external ledger (over-engineered and requires networking), signed individual files (difficult to verify sequential insertion).
