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
| M14 | Deterministic output | DECISIONS.md ADR-001: analytics are "strictly deterministic", with "byte-identical reproducibility"; README: "deterministic analytical tool" | Findings, scores and counts were reproducible, but the **evidence records** of EG01, EG02, EG04, EG05, EG08, EG09, NS04 and NS05 were the first rows of a query with no (or no complete) ORDER BY, so they depended on the order rows happened to be stored in. That order changes on a re-ingest (Parquet merge with `unique()`). Reproduced: seed 42 ingested twice, then assessed, in two fresh stores gave different evidence alerts for CSE-03 EG01 (9 of the 10 differed) and therefore different review queues. | **Code fixed** in Phase 5: each of those queries now has a total order (`rules/execution_gaps.py`, `rules/negative_space.py`; EG09 lists the oldest stale case first, the rest by record id). No threshold, count or score changed. `tests/test_golden_findings.py::test_findings_do_not_depend_on_the_order_of_submitted_rows` (same submission, rows shuffled) fails without the fix. Found by the Phase 5 golden test, which failed against its own snapshot before any optimisation. |
| M15 | Close-before-create DQ check | `docs/validation_summary.md`: alerts closed before they were created "are already reported by the `close_before_create` data-quality check"; `docs/architecture.md` listed the check among those ingest runs | `DQValidator.check_timestamp_logic` compares only values that are Python `datetime`s. Timestamps in a CSV or JSON submission arrive as text, so for those submissions the check never runs; it works for product exports through a mapping, whose timestamps are parsed. Reproduced on the pre-Phase 5 code: a CSV alert closed one day before it was created gave no `close_before_create` issue. EG01 and EG10 still exclude such alerts in SQL, so findings are not affected. | **Code fixed** in the Phase 5 follow-up (decided at the Phase 5 pause). Text timestamps are now read the way the store reads them (DuckDB's `TRY_CAST(... AS TIMESTAMP)`, as in `DuckDBStore.load_table_from_parquet`), so the check reports exactly the alerts the rules see as closed before they were created; text the store cannot read is not compared, as before. The check only reads: no stored row, finding, score or other DQ issue changes (`tests/test_dq_timestamps.py`, and the golden snapshot, taken before the fix, still matches). The method's docstring also claimed an `acknowledged_at >= created_at` check that has never existed; the docstring was corrected and no check was added. |
| M16 | UTC offsets in canonical timestamps | `docs/data_requirements.md` §1.2: `created_at` is "Alert generation timestamp (UTC)"; nothing says what happens to a timestamp that carries an offset | In a canonical CSV or JSON submission, a timestamp is stored as text and cast at load with `TRY_CAST(... AS TIMESTAMP)`, which **drops** an offset instead of applying it: `2026-04-02T10:00:00+05:30` is stored as 10:00, not 04:30 UTC. Product exports through a mapping are not affected (the mapping's `utc_offset` converts to UTC). Shown in a full ingest by `tests/test_dq_timestamps.py` (alert A-0009). | **Code fixed** in the second Phase 5 follow-up (asked for at the Phase 5 pause). Text with an offset is now converted to UTC with it (`text_timestamp_sql` in `store/duckdb.py`, used by the store's load and by the close-before-create check); text without one is read exactly as before, independent of the session time zone. The golden snapshot did not move: no generator writes a non-zero offset. `docs/data_requirements.md` §1 now states how timestamps are read. |

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
- Open item (fixed in the second Phase 5 follow-up), observed while verifying: some web tests (for example
  `tests/test_shadow_pilot.py`) use the working tree's `data/satsa.db`. A `satsa validate` run
  after the suite therefore reports their shadow workpaper in place of the stand-in one. The
  committed validation reports were not regenerated in this phase.

### Phase 5: ingest performance

**Golden test first.** `tests/test_golden_findings.py` ingests and assesses four scenarios:
- the original generator (seed 42), ingested twice;
- the independent generator (seed 7);
- the Splunk and TheHive sample exports through their mappings.

For each scenario it compares the outputs with `tests/golden/golden_findings.json`:
- every canonical table (row count and SHA-256 of the sorted rows);
- the DQ issues;
- the findings, including a hash of their text and evidence;
- the entity scores, the review queue and the systemic findings.

**Finding before any change (M14).** The first snapshot did not match a second run of the
unchanged code. The cause was that evidence samples depended on storage row order. This was
fixed first, in the rules, and the snapshot was then taken on the code before any
optimisation (SHA-256 `e470c0d9dcaa713f…`).

That snapshot passes on both versions:
- **The pre-optimisation source** (commit `b371788` plus the M14 fix, run with `PYTHONPATH`
  pointing at a copy of it): 6 passed.
- **The current code:** 6 passed.

**Profile** (`uv run python scripts/profile_ingest.py --entities 10 --alerts 50000`, cProfile,
121.8 s under the profiler; 58.4 s without it, 1,837 MiB peak):

| Cost | Cumulative under cProfile |
|---|---|
| Row-wise column normalisation (`normalize_row_columns`, 2.17 million calls) | 54.8 s (45%) |
| Row hygiene (`_apply_row_hygiene`; 1.47 million HMAC pseudonymisations) | 21.8 s (18%) |
| Rebuilding canonical rows and frames from dicts | about 15 s |
| `to_dicts` for chunks and per-entity DQ checks | 9.5 s |
| Parquet write | 4.3 s |

**Changes:**
- `src/satsa/ingest/columnar.py`: a canonical CSV table is normalised column by column.
  - It covers column aliases, header case and trimming (with Python's own whitespace set), the
    default entity, rejection of rows without a valid entity, pseudonymisation, taxonomy
    mapping and comment redaction.
  - Per-value functions run once per distinct value.
  - Where exact equivalence is not certain, it declines and the row path runs as before. This
    covers mixed-type columns, two alias columns for one field, JSON, and product mappings.
- `src/satsa/ingest/dq_checks.py` `FrameDQ`: the DQ checks on columns, with the same counts,
  samples (in row order) and text as `DQValidator`. Non-text columns go through the
  dict-based logic.
- `src/satsa/ingest/pipeline.py`:
  - Each entity's rows are found by position instead of copying every table per entity.
  - Field coverage is counted for all columns of a table together, in 500,000-row slices.
  - Each table's frame is released once written.
  - The written tables are reloaded into DuckDB after all are written (new
    `DuckDBStore.deferred_reload()`). A failed reload still counts as a failed store.
- `scripts/profile_ingest.py`: new. `scripts/benchmark_scale.py` now labels sizes MiB, which
  is what it measured all along.

**Equivalence tests** (`tests/test_columnar_ingest.py`, 56 tests):
- Messy submissions are ingested with the columnar path on and off. Every stored table, the
  ingest result and every DQ issue must be identical, and the test asserts that the columnar
  path really ran. The submissions mix:
  - alias columns and odd headers;
  - Python-only whitespace;
  - raw comments with e-mail addresses and IPs;
  - invalid and missing entity IDs, and a default entity.
- `FrameDQ` is compared with `DQValidator` on 40 random frames and on non-text columns.
- Column counts are compared with the per-column formula.
- Two deliberately planted bugs were each caught:
  1. a wrong default closer type;
  2. using the regex engine's whitespace instead of Python's.

**Results.** `python scripts/benchmark_scale.py --configs 10x50000,50x100000`, before and after,
on the same machine and interpreter on 2026-10-01. Details are in `docs/benchmarks.md`.

| Alerts | Ingest before | Ingest after | Peak before | Peak after |
|---|---:|---:|---:|---:|
| 500,000 | 55.1 s | 6.5 s (8.5x) | 1,855 MiB | 1,155 MiB |
| 5,000,000 | 529.7 s | 54.2 s (9.8x) | 13,339 MiB | 5,716 MiB |

**Targets:**
- **At least 3x faster:** met.
- **Under 6 GB at 5,000,000 alerts:** under 6 GiB, not reliably under 6 GB. This entry first
  said "met, narrowly" from one run (5,716 MiB, 5.99 GB); two later measurements gave 5,731 and
  5,736 MiB (6.01 GB), see the follow-up below. The peak comes while the 938 MiB workflow-event
  CSV is read; none of the Polars readers tried (default, low-memory, batched, streaming) was
  lower.

**Not done:**
- Assessment speed. It was not in scope, and its before and after figures differ by 7%.
- The first web page after a run still reloads every table (about 20 s at 5,000,000 alerts).
- README, `docs/infrastructure.md` and EVIDENCE.md still carry the 2026-09-30 figures,
  labelled with that date. They are refreshed in Phase 8, as agreed.
- M15 (close-before-create never runs for CSV/JSON timestamps) was recorded here and fixed in
  the follow-up below.

### Phase 5 follow-up: close-before-create on text timestamps (M15)

Decided at the Phase 5 pause: fix M15 without changing any other data-quality output.

- `src/satsa/ingest/dq_checks.py`: `_stored_timestamps` casts text timestamps with DuckDB's
  `TRY_CAST(... AS TIMESTAMP)`, the cast the store applies when it loads a table. Both
  `FrameDQ.check_timestamp_logic` and `DQValidator.check_timestamp_logic` use it. Text against
  a zoned datetime is not compared, because the store would convert a zoned value by its session
  time zone.
- `src/satsa/ingest/pipeline.py`: the ingest result and its audit entry list entities sorted.
  Before, the list was in Python set order, which changes with the per-process hash seed.
  - This made `tests/test_columnar_ingest.py::test_messy_submission_is_stored_identically`
    flaky. It was added in Phase 5 and failed on the Phase 5 commit itself with
    `PYTHONHASHSEED=16`.
  - Only the order of that list changes.
- `tests/test_dq_timestamps.py` (37 tests):
  - CSV (columnar and row path), JSON and NDJSON submissions with ten kinds of timestamp pair.
    The check reports exactly the alerts the store holds as closed before created.
  - Against the check as it was, the stored alerts and every other DQ issue are identical.
  - The frame and dict checks agree on 30 randomised frames of mixed timestamp text.
  - Neither check rewrites its input.
- The Phase 5 messy-submission tests contain alerts closed up to five minutes before
  creation, so they now also show the columnar and row paths agreeing on this issue.
- **Unchanged:** the golden snapshot (`tests/golden/golden_findings.json`, taken before the
  fix) still matches. No generator produces inverted timestamps
  (`tests/test_edge_paths.py::test_generated_defects_are_what_their_ground_truth_says`), so no
  finding, score, stored row or other DQ issue in the four scenarios moved.
- **Found, not fixed:** M16 (UTC offsets in canonical text timestamps are dropped at load).
- **Cost** (`python scripts/benchmark_scale.py --configs 10x50000,50x100000`, 2026-10-02): ingest
  5.4 s at 500,000 alerts and 45.8 s at 5,000,000; ingest peak 1,261 and 5,731 MiB. A memory trace
  at 5,000,000 shows the peak set while the workflow-event CSV is read, before the checks run, so
  the fix does not set it. It did show that the read peak varies between runs (5,716 to 5,736 MiB),
  so the Phase 5 "under 6 GB, met narrowly" was corrected above: it is under 6 GiB, not reliably
  under 6 GB.

### Phase 5 follow-up 2: offsets, test isolation, peak memory

Decided at the Phase 5 pause: fix everything found in Phase 5 before Phase 6.

**M16, UTC offsets** (`src/satsa/store/duckdb.py`, `src/satsa/ingest/dq_checks.py`):
- `text_timestamp_sql` reads a text timestamp as UTC. One carrying an offset (`Z`, `+05:30`,
  `+0530`, `+05`) is converted with it. One without an offset is read exactly as before. The
  result does not depend on the DuckDB session's time zone.
- The store's load and the close-before-create check both use it.
- It uses DuckDB's ICU extension, which is statically linked in the DuckDB wheel, so nothing is
  downloaded (checked with `duckdb_extensions()`: `STATICALLY_LINKED`).
- **Cost:** 0.11 s per 10,000,000 values against the plain cast, measured on a 10,000,000-row
  table.
- **Tests:** `tests/test_dq_timestamps.py` now has 42 tests:
  - offsets stored in UTC for CSV and JSON;
  - three session time zones;
  - an alert inverted only once its offset is applied (A-0010).
  - One expectation in that file, which this session added, was updated: alert A-0009 was
    recorded as inverted under the old behaviour, which dropped offsets. With offsets applied it
    is not.
- **Golden snapshot:** unchanged.

**Tests no longer write to the working tree** (`tests/conftest.py`):
- The application keeps its state relative to the working directory, and about 30 test lines
  use `data/satsa.db` the same way. The suite therefore used to change a developer's database,
  salt and reports.
- It now runs from a temporary copy of the repository inputs it reads by relative path:
  `config/`, `demo_data/`, `docs/`, `scripts/`, `src/` and the top-level files.
- That copy is bootstrapped as CI bootstraps a clean checkout: `generate-data`, `ingest`, `run`.
  This takes about 13 s.
- The copy is removed at the end of the session, and also when the bootstrap fails. It holds
  copies only, nothing linked.
- `SATSA_TESTS_IN_PLACE=1` keeps the old behaviour.
- **Shown:** after a full run (1,053 passed), the SHA-256 of every file under `data/`,
  `reports/` and `.satsa_salt` is unchanged.

**Peak memory at 5,000,000 alerts** (`src/satsa/ingest/pipeline.py`, `src/satsa/__init__.py`):
- **Memory traces** (resident and peak memory logged at each ingest step) showed three phases
  within 100 MiB of each other:
  - the read of the largest CSV, on top of the tables already held;
  - the data-quality checks;
  - the final reload into DuckDB, on top of about 2.6 GB that Polars' allocator kept after the
    frames were freed. `gc.collect()` released none of it.
- **Changes:**
  - The largest CSV is read before the others. Files are still processed in their usual order,
    so row order, DQ samples and error reporting are unchanged.
    `tests/test_ingest_read_order.py` checks this with the early read on and off, including an
    unreadable largest file.
  - `MIMALLOC_PURGE_DELAY=0` is set in `satsa/__init__.py` before Polars is imported, unless
    the environment sets it.
- **Result:** 5,761 to 5,435 MiB. The peak is now under 6 GB (5,722 MiB), at the cost of about
  6 s (13%) more ingest time at 5,000,000 alerts (`docs/benchmarks.md`, "Peak-memory change").
- The "under 6 GB" target in Phase 5 is now met. Before this it was not reliably met.

### Phase 6: examiner workflow and traceability

**The finding page** (`src/satsa/ui/templates/finding_detail.html`, `src/satsa/api/routes.py`,
`src/satsa/explain/finding_card.py`) is in five numbered sections:
1. what was found;
2. why it matters;
3. evidence;
4. confidence and limitations;
5. next step.

- **Why it matters is new.** `WHY_IT_MATTERS` holds one statement per rule, following the
  rule's Purpose in `docs/analytics_methodology.md` and worded as what the pattern *may* mean.
- **The evidence section now also shows two things the page never displayed:**
  - the figures the rule recorded (`peer_comparison`);
  - the rule's parameters.
- **What the parameter values are.** A run stores only a hash of `config/rules.yaml`, not the
  values. The page therefore shows the current values and says whether the configuration is
  unchanged since the finding's run.
- **Confidence shows as a whole percentage** ("100%", not "100.0%").
- **Tests:** `tests/test_finding_page.py` (23 tests).
  - For one finding of each of the 19 rules with a finding in the test data (all but EG02), as
    an examiner: the five sections, in order, with the right content in each.
  - Every registered rule has a statement.
  - The parameter table and both configuration messages.
- **Doc correction:** `docs/functional_design.md` §7 described a peer IQR and percentile rank
  on this page. No rule computes either, and the page never showed them. The section now
  describes the page as built.

**Traceability** (`docs/ps_traceability.md`):
- Rewritten as one table: requirement, feature, code, test, and evidence with status.
- One row for each of the problem statement's 17 functional and 6 deployment requirements, the
  out-of-scope items and two further statements. The quoted wording is from
  `docs/legal_traceability.md` §3.
- The old version used this project's own paraphrased numbering and is replaced.
- **Statuses are stated as found, not upgraded:**
  - F2 is Partial: the SQLite and REST adapters are not wired into `satsa ingest` on this branch.
  - F7, F8 and F10 are Partial.
  - F14 is "met as built; not measured with examiners".
- **Tests:**
  - `tests/test_traceability_links.py`: every path and `file.py::test_name` in the table exists,
    and every requirement has code and a test. It checks more than 60 references.
  - `tests/test_dependencies.py` is new evidence for D3-D5. No cloud, telemetry, SaaS or AI/ML
    client is among the 50 locked packages.
- F3 cites this session's 5,000,000-alert measurement. `docs/legal_traceability.md` §3 still has
  the 2026-09-30 figures, which are refreshed in Phase 8 with the others.

**Usability:**
- `docs/usability_protocol.md`:
  - 8 timed tasks for 5 to 8 examiners new to the tool;
  - what counts as correct;
  - what is recorded;
  - what the results can and cannot show.
- `docs/usability/usability_results_template.csv` holds only its header.
- `scripts/usability_summary.py` uses the standard library only. Per task it gives
  participants, completion, median time over completed attempts, and total and median errors.
  It refuses malformed rows, naming the line, and says so when there are no rows.
- `tests/test_usability_summary.py` (8 tests).
- **No session has been run**, and the protocol says so at the top.

**Finding PDF:**
- The finding PDF report (`src/satsa/report/generator.py`) now has a "Why it matters" section
  after its headline.
- `tests/test_finding_page.py::test_the_finding_pdf_states_why_it_matters` reads it back from
  the PDF.
- The PDF otherwise keeps its own layout: headline, comparison, technical detail, verification
  step and benign explanations.

**Not done:** no examiner session was run, so there is no usability figure.
