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
| M12 | Submitted entity profile | `docs/data_requirements.md` and the UI: the entity's submitted name, sector, size band and SOC model are what the tool shows and what peer cohorts are built from | On a fresh store, ingest appended a default record ("<id> Operations", "General Infrastructure", "Medium", "inhouse") **after** the submitted rows, and the entity table keeps the newest non-null value per column, so every submitted profile was overwritten. Reproduced by ingesting `data/generated` (the seed-42 demo) with the pre-fix `src` (`git archive` of `37b9bd4`, the commit before the fix): all 10 CSEs came out as "CSE-xx Operations / General Infrastructure / Medium / inhouse"; with the fix, "Northern Power Grid Ltd / power / large / inhouse" etc. Every entity therefore fell into one peer cohort. | **Code bug, fixed** in Phase 4 (`ingest/pipeline.py`: defaults first). Regression tests in `tests/test_entity_profile_ingest.py` fail without the fix. Found because the independent generator gives entities distinct sectors and sizes; the original generator's checks did not depend on cohort membership, and the primary and stress results were the same before and after the fix (21/21, 3/3). |
| M13 | Canonical schema page | `docs/data_requirements.md` §1.1, §1.5: `soc_model` values `internal`/`hybrid`/`managed_mssp`; criticality 1-5; `declared_kpi(metric_name, declared_value)`; `external_report(report_id, case_id, regulatory_body)`; no `soc_provider`, `comment_len`, `detection_rule`, `remediation`, `sla_policy` | `satsa.models.canonical`: `inhouse`/`hybrid`/`mssp`; criticality 1-4; `declared_kpi(metric, value)`; `external_report(incident_id, reported_to)`; `soc_provider`, `closure.comment_len`, and the three tables exist and are read by rules | **Doc was wrong.** Corrected. Found by writing the independent generator from that page: CSVs built to the page did not load as documented. |

## Process note: another session edited the same working tree

While Phases 1 and 2 ran, at least one other Claude Code session worked in this checkout on a
separate feature (an exploratory anomaly scan, control/process priorities, SQLite and REST
ingest, and an ADR it numbered ADR-007). Its changes were left untouched and are **not** part of
these commits. Consequences, stated plainly:

- The Phase 1 commit first picked up one of its `src/satsa/api/routes.py` hunks (12 lines that
  call functions it had not yet committed), written between this session's check and `git add`.
  The commit was local and unpushed; it was **amended** so that it holds only Phase 1's changes.
- Two Phase 1 test failures (`tests/test_config_drift.py::test_tuning_preview_shows_the_effect_and_persists_nothing`,
  `tests/test_trends.py::test_seed_historical_periods_produces_real_distinct_runs`) were
  off-by-one row counts in the shared `data/satsa.db`; both pass when rerun alone.
- From Phase 2 on, each phase is verified on a **clean copy**: `git archive HEAD` plus exactly
  the file contents being committed, with its own `data/` directory. The files are written to
  the index from those contents, never with `git add` on the shared working tree.

**Repair after Phase 2 (at the user's request):** the main checkout was moved, unchanged, to a
new branch `feat/anomaly-scan-wip` for the other session's uncommitted work, and the quality pass
continues in its own git worktree (`satsa-quality`, branch `quality/10of10`) with its own `data/`.
The other session was told by message. Its ADR keeps the number 007; this pass uses ADR-008.

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


### Phase 2: honest performance claims

Measured in this phase (2026-10-01):

```bash
uv run satsa benchmark      # scan: 7,570,338 rows/s at 1,000,000 rows, one thread;
                            # demo assessment: 16,253 alerts in 2.038 s
uv run satsa validate --output-md <scratch>.md    # lift: top 25 19.47x, top 50 11.98x, whole queue 5.19x
```

Code changes:

- `satsa benchmark` (`bench/benchmark.py`): the scan query ran on DuckDB's default
  multi-threaded connection, unlike SAT-SA's store (one thread), so its figure overstated how
  the tool runs DuckDB. It is now pinned to one thread, labelled as one in-memory query, and
  the command says scan figures are not assessment times.
- `satsa benchmark` printed an **"Extrapolated 5M time"** (5,000,000 divided by the demo
  run's throughput). Removed: the 5M figure is measured by `scripts/benchmark_scale.py`.

**Claims removed or softened** (file: before -> after):

| File | Before | After |
|---|---|---|
| README.md §4 | "Extreme Columnar Analytics Performance ... scan speeds exceeding **10.6 Million rows/second** ... multi-gigabyte submissions to be evaluated in seconds" | Measured 5M-alert ingest 603 s / 13.2 GB and assessment 310 s / 3.3 GB on the named laptop (recorded 2026-09-30); single-query scan 7.6M rows/s (one thread, 2026-10-01); "scan speed is not end-to-end time" |
| README.md results table | "DuckDB Scan Throughput 10,623,549 rows/second ... target >= 1,000,000, exceeds target" | 7,570,338 rows/s, one in-memory query, one thread, not an assessment time; no self-set target |
| README.md | "20 Production Rules" | "20 Detection Rules" |
| README.md | "Method 1: One-Click Docker Deployment (Production & Demo -- Recommended)" | "(Demo; the image has not been built in this project's recorded evidence)" (EVIDENCE.md open item 7: Docker was never run) |
| README.md | "air-gapped, fully deterministic analytical tool and sovereign identity management platform"; "engineered to meet strict regulatory and forensic standards"; "SOVEREIGN BACKEND"; "Sovereign Identity Control"; "Sovereign PBKDF2 identity store" | "offline, deterministic analytical tool with its own identity management"; "built around explainability, auditability and offline operation"; "LOCAL"; "Identity Control"; "Local PBKDF2" |
| README.md | "100% Air-Gapped & Sovereign Data Security"; "irreversibly pseudonymised" | "Offline Operation & Data Minimisation"; pseudonymised with HMAC-SHA256 under a local salt, and anyone holding the salt can re-derive a known name's pseudonym |
| docs/infrastructure.md §2.1 | 10,623,549 rows/s (multi-threaded) | re-measured on one thread, with the "not end-to-end" statement |
| docs/infrastructure.md §2.2 | 0.686 s on an old 5,650-alert dataset | 2.038 s on the current 16,253-alert dataset, measured 2026-10-01 |
| docs/infrastructure.md §3.1 | "partition pruning ... reducing I/O bandwidth by >85%"; "multi-threaded SIMD ... over 10.6 million rows/second" | removed (wrong for this code, M6 and M3); measured scale table |
| docs/infrastructure.md §4 | unmeasured storage estimates; "ideal for self-contained air-gapped forensic laptops and low-profile appliances" | measured CSV and Parquet sizes only |
| docs/infrastructure.md §1 | "Recommended Production (10 CSEs, 5M Alerts)" with 8 cores / 16 threads | "Suggested for about 5,000,000 alerts", RAM taken from the measured 13.2 GB peak, and a note that extra cores do not shorten the single-threaded assessment |
| docs/demo_script.md | "about twenty-one times ... the whole queue about six times" (stale) | "about nineteen times ... about five times (19.47x and 5.19x, `satsa validate`, 2026-10-01)" |
| docs/demo_script.md | "confirms the entire supervisory audit chain is intact and untampered" | says what the chain does and does not detect: "tamper-evident, not tamper-proof" |
| docs/data_requirements.md | "SAT-SA's air-gapped guarantee" | "SAT-SA's offline design" |
| UI: `runs_audit.html` | "Immutable chronological journal items" | "Hash-chained (tamper-evident) journal entries" |
| UI: `dq_coverage.html` | "All uploaded SOC submission data strictly satisfies canonical schema and temporal constraints." | "The ingest data-quality checks found no issue in the uploaded submission data." |
| `admin_overview.html` (comment) | "guarantee 100% sync" | "fallback in case WebSocket messages are missed" |

Searched and left as they are, because they are accurate: "Disposition Extremes" (a rule
name), "extreme outliers" in the statistics text, "Fully Deterministic" (no rule reads the
clock or a random source; reproducibility is tested), "zero false positives" and "100%
accurate" (no occurrence in the repository). The "Fully Offline / Air-Gapped Engine" footer on
reports describes the design, which `tests/test_offline_hardening.py` exercises.

Verification (clean copy, see the process note): full suite, `satsa validate`, `satsa
validate-stress`, `ruff check .`, `mypy src`; results in the Phase 2 commit message.

### Phase 3: signed, verifiable audit checkpoints

Verified first: `satsa audit head` and `satsa audit verify --checkpoint-count/--checkpoint-head`
already implemented an unsigned, hand-copied checkpoint (`SQLiteStore.audit_head`,
`verify_checkpoint`), and ADR-005 stated its limits correctly. They were kept and reused.

- `src/satsa/audit/signing.py`: `Signer`/`Verifier` interface and an algorithm registry.
  `ed25519` implemented with `cryptography`; `ml-dsa-44/65/87` reserved (raise "not
  implemented"); any other name rejected (`UnknownAlgorithmError`).
- `src/satsa/audit/keys.py`: `satsa audit keygen` writes the key pair owner-only (0600 on POSIX;
  on Windows `icacls /inheritance:r /grant:r <user>:(F)`); signing refuses a private key that
  other accounts can read (POSIX group/other bits; Windows: an Allow-read entry for Everyone,
  Anonymous, Authenticated Users, Users or Guests, checked by SID so the display language does
  not matter).
- `src/satsa/audit/checkpoint.py`: `satsa audit checkpoint [--sign --key K] [--out F]` emits
  `satsa-audit-checkpoint/1` JSON (chain, table, entries, head hash, hash algorithm, UTC time,
  tool version) with a detached Ed25519 signature over its canonical encoding; it refuses to
  checkpoint a chain that does not verify. `satsa audit verify --checkpoint F --pubkey P`
  checks the signature, then that the live chain matches or extends the checkpoint.
- `tests/test_audit_tamper_matrix.py`, one test per case. Result:

| Case | Chain alone | With a signed checkpoint |
|---|---|---|
| 1 Edit a middle entry | detected (row 5) | detected |
| 2 Insert an entry | detected (row 6) | detected |
| 3 Delete a middle entry | detected (row 5) | detected |
| 4 Reorder two entries | detected (row 4) | detected |
| 5 Truncate the newest 3 entries | **not detected** (documented limit) | detected ("truncated") |
| 6 Recompute the whole chain after an edit | **not detected** (documented limit) | detected ("history rewritten") |
| 7 Verify with the wrong public key (and with the right key id copied in) | n/a | rejected |
| 8 Modified checkpoint (entries, head hash, time, version; flipped signature bits) | n/a | rejected |

  Also tested: appended entries extend a checkpoint; an unsigned checkpoint, a checkpoint of a
  broken chain and an unknown algorithm in a checkpoint are refused; ML-DSA is reserved, not
  implemented; keygen never overwrites without `--force`; a world-readable key is refused by
  the API and the CLI; the CLI catches truncation end to end.
- DECISIONS.md ADR-008 (new; "tamper-evident, not tamper-proof"; key custody stated as the
  condition the guarantee rests on); ADR-005 points to it. `docs/deployment_ops.md`, README,
  `docs/architecture.md` and `docs/slides_outline.md` describe the signed checkpoint.
- New dependency `cryptography` (50.0.2, with `cffi`, `pycparser`): justified in ADR-008; prebuilt
  wheels for Windows and Linux, no network use at run time.

**Not done, by decision** (each recorded in ADR-008):
- An ML-DSA signer: only the interface and the reserved names, as the Phase 3 scope said. It
  needs no new dependency: the pinned `cryptography` 50.0.2 already provides ML-DSA keys.
  (Correction: the first version of this commit said an optional dependency would be needed;
  checking the installed library showed otherwise.)
- Checkpoint verification in the web app: deliberately CLI-only, because a page served by the
  host being checked could be made to report anything; the examiner verifies on their own machine.
- A passphrase on the private key: possible hardening; the key is protected by owner-only
  permissions and by being kept off the host.

### Phase 4: validation rigour

- `src/satsa/synth/independent.py` (`independent/1`): a second synthetic generator, written from
  README.md, `docs/analytics_methodology.md` §3 and `docs/data_requirements.md`. It uses the
  standard library only and imports nothing from `satsa` (an AST test enforces this). Per
  seed: 15 entities `ORG-A`..`ORG-O` covering every sector and size band, lognormal volumes,
  its own analyst naming and timing. Each rule's defect is built 1.08-1.9x over the documented
  threshold, most rules get a decoy just under it, and there is a systemic group plus a
  two-entity systemic decoy. For EG05, EG11 and NS03 the generator computes the documented
  criterion on what it built and labels the ground truth by it. EG11 is built in both of its
  documented forms (no true positives, or a skewed rate with 1-2.5% true positives). The first
  version built only the first form, so the robust-z branch was tested only by chance cases;
  this was found while writing the threshold rationale and fixed before the reported run.
- `src/satsa/validate/baselines.py`: three one-line baselines (`fast_closure`,
  `short_comment`, `no_escalation`).
- `src/satsa/validate/independent.py` and `satsa validate-independent`: per seed, generate,
  ingest and assess, then score the engine against the baselines with Wilson 95% intervals.
  It also runs an ablation (without EG, without NS; the systemic detector reported on its
  own) and a ±20% sweep of every tunable threshold (reusing the harness).
- `docs/validation_independent_report.md`, from `uv run satsa validate-independent --seeds 20
  --start-seed 1`, run 2026-10-01 in 10 min 50 s:
  - recall 487/487, precision 487/487 and decoys flagged 0/245;
  - clean entities flagged 0/57;
  - baselines lose on precision to the matching rule (20/23, 20/26, 20/300);
  - baseline entity ranking precision@k is 81.8% against the engine's 100%;
  - without EG recall is 198/487, and without NS it is 289/487.
  The report has a "what this does and does not prove" section.
- `docs/threshold_rationale.md` and `scripts/threshold_probe.py`. The probe computes each
  rule's statistic per entity with the rule's own SQL, counts flags at candidate values, and
  reproduces the engine at every current value. The rationale covers EG04, EG05, EG07, NS05,
  NS08 and EG11, and makes **proposals only**. No change was made to `config/`.
- Two defects found by the independent set and fixed (see M12 and M13 above):
  - the entity-profile overwrite at ingest, with regression tests in
    `tests/test_entity_profile_ingest.py`;
  - the schema page in `docs/data_requirements.md`.
- Tests: `tests/test_validate_independent.py` (12 tests: generator independence, documented
  defaults, determinism, ground-truth consistency, decoys under threshold, formulas,
  precision@k ties, one seed end to end, EG11 built both ways).
- `docs/validation_hard_report.md` was re-run (`uv run python scripts/validate_hard.py --out
  docs/validation_hard_report.md`, 11 min), because its earlier figures were produced while M12
  put every entity in one peer cohort. Every result is unchanged; only the date and the
  per-run seconds differ. The 4 known STRESS-03:EG05 false positives (seeds 3, 10, 14 and 15)
  are the same ones as before.

**Not done:**
- The structural proposals in the threshold rationale (EG04 group size relative to volume,
  peer-relative EG07, NS05 excluding new rules) are not evaluated, because each needs a code
  change.
- NS03's `min_spread` was not probed, although 8 entities met its criterion by chance.
- The independent generator was written in a session that had read the rule code. The report
  states this.
- Open item, observed while verifying: some web tests (for example
  `tests/test_shadow_pilot.py`) use the working tree's `data/satsa.db`. A `satsa validate` run
  after the suite therefore reports their shadow workpaper in place of the stand-in one. The
  committed validation reports were not regenerated in this phase.
