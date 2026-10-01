# Quality Pass (`quality/10of10`): What Changed, What Was Verified, What Was Not Done

> **Supervisory Notice:** *Indicators requiring supervisory review; not a compliance determination.*

Branch `quality/10of10`, created from `fix/validation-root-causes` at f5a9ad0, October 2026.
All data used is synthetic. The baseline this pass started from is `docs/baseline_before.md`.

## Doc/code mismatches

Each documented behaviour below was checked against the code before anything was changed.
"Resolution" says which side was wrong and what was done.

| # | Topic | What the docs said | What the code does | Resolution |
|---|---|---|---|---|
| M1 | Socket egress guard | README ("Socket-level egress is blocked"), `docs/architecture.md` ("Outbound network sockets are blocked at runtime"), `docs/slides_outline.md` ("socket-level outbound blocking") | No guard in `src/`. Socket guards existed only as test fixtures (`tests/test_offline.py`, `tests/test_offline_hardening.py`); `SATSA_AIRGAPPED=1` in `Containerfile` was read by nothing. | **Code was missing.** Added `src/satsa/netguard.py` (loopback-only guard on Python socket connects, installed by both FastAPI lifespans, opt-out `SATSA_ALLOW_EGRESS=1`), tested in `tests/test_netguard.py`. Docs now describe it as best-effort defence in depth that does not cover native code and does not block DNS. |
| M2 | Bind address | `docs/architecture.md` §5: "Uvicorn Server (127.0.0.1:8000)" as the single server | Two portals: Admin Portal `:8000`, SAT-SA `:8001`; both default to `127.0.0.1` (`satsa/serving.py`); container listens on `0.0.0.0`, compose publishes on `127.0.0.1` | **Doc was wrong** (port/topology). Rewritten. The loopback default itself was correct. `Containerfile`'s `--host 0.0.0.0` is by design (comment in the file) and was left unchanged. |
| M3 | DuckDB threads | `docs/infrastructure.md` §3.1: "DuckDB executes multi-threaded SIMD vectorized scans" | `PRAGMA threads=1` in `DuckDBStore.__init__` (`store/duckdb.py`), for reproducible floating-point aggregation | **Doc was wrong.** architecture.md §3 and infrastructure.md §3.1 now state the single thread and why (Phase 1). |
| M4 | Ingest adapters | `docs/architecture.md` §3: `SplunkAdapter`, `ServiceNowAdapter`, `TheHiveAdapter` | No such classes. One `SourceAdapter` (csv, json/ndjson, sqlite, loopback REST) plus YAML `SourceMapping` (`ingest/mapper.py`, `config/mappings/*.yaml`) | **Doc was wrong.** Rewritten to name the real classes and files. |
| M5 | Parquet layout | DECISIONS.md ADR-002: `data/parquet/{entity_id}/{year_month}/...`; architecture.md: only `alert`, `workflow_event`, `log_source_daily`, `asset` are Parquet | All 15 canonical tables at `data/parquet/{table}/entity_id={entity_id}/data.parquet`; no time partitioning | **Docs were wrong.** ADR-002 and architecture.md corrected. |
| M6 | "Partition-pruned" scans | architecture.md §3 and infrastructure.md §3.1: "partition-pruned, vectorized analytical scans", "each rule query scans only relevant column projections" | `load_all_tables()` reads every table into an in-memory DuckDB; rules query in-memory tables | **Docs were wrong.** Removed; architecture.md §3 describes the in-memory load and the web app's `AnalyticsCache`. |
| M7 | Audit chain strength | architecture.md §3: "Guarantees forensic immutability via `prev_hash` cryptographic chaining" | Keyless hash chain; tail truncation and full recomputation are not detectable without an off-box checkpoint (ADR-004/005) | **Doc overstated.** Now "tamper-evident, not tamper-proof", with the limits stated. |
| M8 | Entity risk index | architecture.md §4: "Weighted sum of 8 capability domain scores plus breadth penalty" | `(1 - breadth_weight) × weighted mean + breadth_weight × breadth score` (`scoring/scorer.py`) | **Doc was imprecise.** Formula stated as implemented. |
| M9 | Package layout | README directory tree: `src/satsa/core/  # Ingestion, validation, pseudonymisation, scoring` | No `core/` package; that work lives in `ingest/`, `scoring/`, `validate/` | **Doc was wrong.** Tree line corrected. |
| M10 | Audit hash algorithm | README §10 and admin diagram: "SHA-256 tamper-evident log chain", "Chained SHA-256 prev_hash"; CLI reference: "verify the SHA-256 audit log hash chain" | New entries are SHA3-256; legacy SHA-256 entries still verify (`store/sqlite.py::compute_chain_hash`) | **Doc was stale.** Wording now says SHA3-256 with legacy SHA-256. |
| M11 | Report file names vs Windows path limit | EVIDENCE.md: the suite had to be run "from a short path" | Reproduced: from a 181-character root, 4 PDF-route tests fail (`reports/SAT-SA_CSE_<entity>_Report_<full run id>.pdf.tmp` > 260 characters) and `test_bundle` fails (the offline bundle mirrors the source tree under `dist/satsa_offline_bundle/`) | **Code fixed for the reports** (`satsa/report/naming.py`; see Phase 1). The bundle depth is recorded as an open item. |

## Phase log

### Phase 0: baseline

`docs/baseline_before.md`: 871 passed / 33 skipped / 0 failed, coverage 89%, 21/21 and 3/3,
ruff and mypy clean. Matches EVIDENCE.md, so no pause.

### Phase 1: hygiene and doc/code consistency

- **Removed** the committed backup `data_backup_20260929_181654/` (9 Parquet files and a
  `satsa.db`; nothing referenced it). `git ls-files` showed no other stray build output: the
  `demo_data/*.zip` bundles (used by the demo walkthrough) and the connector CSV fixtures (used
  by `tests/test_connectors.py`) stay. `.gitignore` now excludes backups, `data/`, `*.parquet`,
  `*.db`, `*.zip`, `*.tar.gz`, coverage output and `wheelhouse/`, with explicit exceptions for
  `demo_data/` and `tests/fixtures/` (checked with `git check-ignore --no-index -v`).
- **Report file names shortened** (`satsa/report/naming.py`), used by the three PDF routes and
  `satsa report`: `SATSA_Portfolio_20261001-ea12a0fc.pdf`, `SATSA_CSE-03_20261001-ea12a0fc.pdf`,
  `SATSA_Finding_EG10_CSE-02_<8-hex hash of the finding ID>.pdf`. They keep report kind, entity,
  rule and run date, and are 29 or more characters shorter than before. Test expectations in
  `tests/test_report_pdf.py` changed **only because the file names changed**; a new test
  checks the format and length.
  **Verified** by re-running, from the same 181-character root as the baseline, the five tests
  that failed there: the four PDF-route tests now pass; `tests/test_bundle.py::test_offline_packager`
  still fails, because `satsa offline-bundle` copies the source tree under
  `dist/satsa_offline_bundle/`. That is not a report file name and is left as an **open item**.
- **Egress guard implemented** (M1): `src/satsa/netguard.py`, installed by both FastAPI
  lifespans (and so by `satsa serve`, `satsa admin`, `entrypoint.py` and bare uvicorn), by
  `satsa serve`/`satsa admin` around `uvicorn.run`, and by `entrypoint.py` when run as a script.
  Reference-counted install/uninstall; a wrapper left behind after uninstall passes calls
  through, so no test leaks it. `tests/test_netguard.py` (external blocked, loopback and
  `read_api` against a loopback server still work, lifespans install and remove it, CLI holds
  it while uvicorn runs, opt-out logs a warning). Described as best-effort defence in depth in
  README, architecture.md and slides_outline.md.
- **Docs corrected** for M2-M10: `docs/architecture.md` Sections 1-5 rewritten from the code;
  DECISIONS.md ADR-002; `docs/infrastructure.md` thread claim; README tree and hash wording.

