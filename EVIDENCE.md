# SAT-SA Feasibility Evidence

> **Supervisory Notice:** *Indicators requiring supervisory review; not a compliance determination.*

Branch `feat/feasibility-evidence`, 17 commits on top of `main` (69028c6), then
`fix/validation-root-causes` on top of it (Phase 8), 30 September 2026.
Every number below was produced by a command that was run in this pass; the command is given
with it. Nothing is estimated. Where something could not be run or verified, it says so and is
repeated under **Open items**.

**Machine for all measurements:** AMD Ryzen 5 7235HS (4 cores, 8 threads), 23.7 GB RAM,
Windows 11, Python 3.13.2, DuckDB 1.5.5, Polars 1.44.2.

**How the full suite was run.** A clean copy of the tracked files in a short temporary path,
then:

```bash
satsa generate-data && satsa ingest && satsa run
python scripts/build_shadow_standin.py
satsa validate --shadow-csv data/generated/shadow_pilot_standin.csv
satsa validate-stress
python -m coverage run --branch --source=src/satsa -m pytest tests -q
```

(A short path is needed because four report tests write file names that exceed Windows'
260-character limit under a long working directory. Those four are fixed in the quality pass, Phase 1.)

| After | Tests passed | Skipped | Failed | Primary set | Stress set |
|---|---:|---:|---:|---|---|
| Start (main) | 740 | 33 | 0 | 21/21, 0 false positives | 3/3, 0 false positives |
| Phase 1 | 772 | 33 | 0 | 21/21, 0 FP | 3/3, 0 FP |
| Phase 2 | 809 | 33 | 0 | 21/21, 0 FP | 3/3, 0 FP |
| Phase 3 | 847 | 33 | 0 | 21/21, 0 FP | 3/3, 0 FP |
| Phase 4 | 847 | 33 | 0 | 21/21, 0 FP | 3/3, 0 FP |
| Phases 5-7 | 866 | 33 | 0 | 21/21, 0 FP | 3/3, 0 FP |
| Phase 8 (end of feasibility pass) | **871** | 33 | **0** | 21/21, 0 FP | 3/3, 0 FP |
| Quality pass, final (2026-10-02) | **1,107** | 33 | **0** | 21/21, 0 FP | 3/3, 0 FP |

The 33 skips are public routes in the RBAC matrix, exercised once anonymously instead of once
per role. The primary and stress sets are single-seed synthetic sets built around the rules'
thresholds; their perfect scores are a correctness check. The harder results are in Phase 5.

---

## Phase 1: Functional gaps

| # | Gap | What changed | Test |
|---|---|---|---|
| 1.1 | Findings with no evidence records | Measured first: **three** rules had none (NS03, NS05, NS08); the fourth, EG11, had been fixed before this pass. NS03 now cites night-time alerts and the last alert of recent days, NS05 the dormant detection rules, NS08 the alerts on either side of each missing month. | `tests/test_rules.py::test_every_finding_carries_evidence_records` (all 20 rules) |
| 1.2 | Blinded-review agreement wrong for High and Critical entities | Failing test written first (`assert 50.0 == 100.0`): "High" and "Critical" bands had no level, so an examiner who agreed scored 50%. `blind_review_concordance` now maps both scales explicitly and rejects unknown values (HTTP 422). | `tests/test_blind_review.py` |
| 1.3 | Tuning had no preview and re-ran as 2026-Q1 | `POST /tuning/preview` evaluates proposed thresholds with `run_assessment(dry_run=True)`: nothing is persisted, and it shows findings gained and lost. Save, preview, upload and entity changes use the selected or latest period. | `tests/test_config_drift.py`, `tests/test_rbac_matrix.py` |
| 1.4 | Stale-case rule depended on the wall clock | EG09 measures age to the assessment reference date: `--reference-date`, else the latest timestamp in the data. It is recorded in the run manifest. | `tests/test_validation_integrity.py::test_eg09_case_age_uses_the_assessment_reference_date_not_the_clock`, `::test_no_rule_reads_the_wall_clock` |
| 1.5 | Six-month review period hard-coded | `rules.NS08.params.review_period_months` (default 6), a whole number from 1 to 24. An out-of-range value stops the rule registry; the tuning form rejects it with 422. | `tests/test_config_drift.py` (12 cases) |

Side effects, measured on the primary set: the review queue grew from 119 to 129 alert items
(new evidence records), so lift in the top 25 queue alerts went from 20.97x to 19.47x and over
the whole queue from 5.98x to 5.52x. The threshold sweep went from 3 of 64 to 4 of 66 (NS08's
period is now swept; lowering it to 5 months loses the one-month gap defect).

## Phase 2: Deployment hardening

| # | Item | What changed | Test |
|---|---|---|---|
| 2.1 | Forced password change | The `force_password_change` flag existed but was **never enforced**, and the four seeded accounts were created without it. Seeded accounts are now created owing a change; a session for any flagged account reaches `/change-password` and nothing else on either portal (pages redirect; APIs, downloads, mutations and the admin websocket are refused). Start-up flags seeded accounts still on their default in an older database. New passphrase: 12+ characters, not a published default, current passphrase re-checked with lockout. No setting turns this off. | `tests/test_first_login_password_change.py` (11 tests, both portals, including a fresh install end to end) |
| 2.2 | Loopback by default | `docker-compose.yml` publishes on `127.0.0.1` unless `SATSA_BIND_ADDRESS` is set; `entrypoint.py`, `satsa serve` and `satsa admin` bind `SATSA_HOST` (default `127.0.0.1`) and warn when listening elsewhere over plain HTTP. | `tests/test_serving.py` |
| 2.3 | Optional TLS | `SATSA_TLS_CERT` + `SATSA_TLS_KEY` (or `--ssl-certfile` / `--ssl-keyfile`). Half a configuration refuses to start. `scripts/generate_selfsigned_cert.py` / `satsa tls-cert` create an RSA-3072 certificate with the local `openssl`, no CA, no network. Cookies become `Secure`; the container healthcheck follows the scheme. Documented in `docs/deployment_ops.md` Section 1.3. | `tests/test_serving.py::test_portal_serves_https_with_the_generated_certificate` starts a real server and completes a verified TLS handshake |
| 2.4 | Existing controls kept | Lockout (5 failures / 15 minutes), PBKDF2-HMAC-SHA256 (200,000 iterations) and role separation are unchanged; their tests still pass. | `tests/test_login_lockout.py`, `tests/test_auth.py`, `tests/test_rbac_matrix.py` |

The test suite signs in with the seeded passphrases as already-rotated operators:
`tests/conftest.py` lifts the flag after seeding, in the tests only.

## Phase 3: Data connectors

`satsa ingest --source splunk|servicenow|thehive --entity <id>`. The three mappings existed but
the pipeline never used them, and they named columns the products do not export. They were
rewritten to the products' export field names and wired in.

```bash
python tests/fixtures/connectors/build_fixtures.py     # the sample exports (deterministic)
pytest tests/test_connectors.py                        # 24 tests
```

| Source (sample) | Maps cleanly | Missing from the export | Rules assessed | Cannot fire | Not assessed | Findings on the sample |
|---|---|---|---|---|---|---|
| Splunk ES: 209 notables + review history | id, rule, category, both severities, asset, created, closed (175), closer, disposition, status; 314 workflow events; 175 closures | acknowledged/first-touch times, playbook; no cases, escalations, assets, SLA, KPIs | 8 | 0 | 12 | EG02, EG07 |
| ServiceNow SIR: 14 incidents + audit rows | case id, severity, status, owner, opened, closed (9); 50 state-change events | work-note lengths; **no alerts**, no external reports | 2 | 0 | 18 | EG09, EG12 |
| TheHive 5: 94 alerts + 8 cases | id, title as rule (approximate), type, severity, dates, assignee, stage; 6 case links; 8 cases | **asset, disposition**, playbook; no workflow events or closures | 5 | 2 (EG11, NS04) | 13 | EG07, EG09 |
| Splunk + ServiceNow, one entity | | | 10 | 0 | 10 | EG02, EG07, EG09, EG12 |

Full field tables: `docs/connectors.md`. **No single product export supports all 20 rules.**

Reporting (3.3): every ingest now returns and prints, per entity, the rules **not assessed**
(a table, the alert table included, was never submitted) and the rules that **cannot fire**
(an alert column they rest on is empty; new DQ check `rule_input_missing`). A file the mapping
does not describe is reported (`file_not_mapped`), not guessed at.

**Defects found by running realistic exports, none visible on the synthetic sets:**

1. EG02 and EG04 counted alerts still open as closures. On the Splunk sample EG02 reported
   59 of 198; correct is 36 of 164. The synthetic sets have 16,253 alerts and none is open.
2. Analyst names were stored unpseudonymised when the source had no closer-type column.
3. Case owners were never pseudonymised.
4. Raw closure comments and unknown source columns were written to Parquet as submitted.
5. Comment shingles were stored as readable words (a name survives pattern redaction).

All fixed; `tests/test_connectors.py::test_no_personal_identifier_from_an_export_is_stored`
checks every Parquet file and the findings, evidence, queue, DQ and audit tables for each sample.

**Limit:** the samples are hand-built to documented field names. They are not captures from
live systems, and the mappings have not been run against a real instance.

## Phase 4: Performance and scale

**Cache.** Every request built a DuckDB store and re-read every Parquet table, including 19
handlers that only needed SQLite. Read requests now share a store that is rebuilt only when a
new run completes or the Parquet store changes. `tests/test_analytics_cache.py` (10 tests):
18 analytics requests cause one load; a new run causes a second; state-only requests cause none.

**Ingest.** The first benchmark showed the limit: 10 x 50,000 alerts peaked at 3,417 MB because
every row was held as a Python dict, which put 2.5M and 5M alerts out of reach. Ingest now
normalises 100,000 rows at a time into columnar buffers.

| 10 x 50,000 alerts (2.17M rows) | Ingest time | Ingest peak memory |
|---|---:|---:|
| Before | 66.0 s | 3,417 MB |
| After | 65.9 s | 1,858 MB |

DQ results and findings are identical before and after (full suite and both validation sets).

**Benchmark** (`docs/benchmarks.md`, with machine specs and raw results):

```bash
python scripts/benchmark_scale.py --configs 10x50000,25x100000,50x100000 --out docs/benchmarks.md
```

| Entities x alerts | Alerts | Rows | Ingest | Ingest peak | Assess | Assess peak | Old per-request reload | `/portfolio` first | `/portfolio` repeat | `/alerts` repeat |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 10 x 50,000 | 500,000 | 2,171,868 | 65.9 s | 1,858 MB | 16.3 s | 460 MB | 2.03 s | 2,921 ms | 60 ms | 133 ms |
| 25 x 100,000 | 2,500,000 | 10,681,566 | 309.7 s | 6,996 MB | 105.2 s | 1,728 MB | 12.21 s | 13,148 ms | 92 ms | 326 ms |
| 50 x 100,000 | 5,000,000 | 21,365,139 | 603.0 s | 13,248 MB | 310.2 s | 3,314 MB | 24.49 s | 27,021 ms | 95 ms | 673 ms |

What this shows and does not: 5,000,000 alerts complete in about 15 minutes on a laptop, and
repeat page loads stay under 0.7 s. Ingest needs 13.2 GB at that size, so a 16 GB host is the
practical minimum. Assessment time grows faster than volume (16 s, 105 s, 310 s). The first
page after a run or an ingest still pays the full reload (27 s at 5M alerts). The data is
uniform and clean. `docs/infrastructure.md` used to promise 10.1 minutes by extrapolating from
a 5,650-alert run; that is withdrawn.

*Superseded by the quality pass:* on its final code, 5,000,000 alerts took 54.5 s to ingest
(5,424 MiB peak) and 107.3 s to assess (`docs/benchmarks.md`, "Final code (2026-10-02)").

## Phase 5: Accuracy evidence

**All synthetic.** Full statement: `docs/validation_summary.md`.

```bash
python scripts/validate_hard.py --out docs/validation_hard_report.md    # 44 runs, 12 minutes
```

The hard set is separate from the primary set and never uses its seed: the portfolio generator
under 8 other seeds at 1,500, 600 and 300 base alerts per entity (24 runs), and the stress
scenario (borderline EG04, ambiguous EG02/EG04, noisy clean entity) under 20 seeds.

| Set | Runs | Recall (95% CI) | Precision (95% CI) | Clean entities flagged |
|---|---:|---|---|---|
| Portfolio, 1,500 | 8 | 99.4% (167/168; 96.7-99.9%) | 98.8% (167/169; 95.8-99.7%) | 0 of 24 |
| Portfolio, 600 | 8 | 99.4% (167/168; 96.7-99.9%) | 97.7% (167/171; 94.1-99.1%) | 0 of 24 |
| Portfolio, 300 | 8 | 100.0% (168/168; 97.8-100%) | 97.7% (168/172; 94.2-99.1%) | 0 of 24 |
| **Portfolio, all** | **24** | **99.6% (502/504)** | **98.0% (502/512)** | **0 of 72** |
| Stress | 20 | 100.0% (60/60; 94.0-100%) | 93.8% (60/64; 85.0-97.5%) | 4 of 20 (20.0%; 8.1-41.6%) |

Per rule (24 portfolio runs; every rule not listed: 24 of 24 detected, 0 false positives; the
per-volume tables with intervals are in the report):

These are the Phase 5 figures. Phase 8 traced every failure below to its records and fixed
the cause; the current figures are in Phase 8.

| Rule | Detected | False positives | Note |
|---|---|---:|---|
| EG10 | 24/24 | 10 | precision 70.6% (24/34); always CSE-07, which has no KPI-gap defect |
| EG09 | 23/24 | 0 | missed under seed 808 at 1,500 |
| EG03 | 23/24 | 0 | missed under seed 808 at 600 |
| EG05 (stress) | none injected | 4 | the noisy clean entity, 4 of 20 seeds |

A rule with 8 of 8 detected at one volume has a 95% interval of 67.6% to 100%.

**Fragile thresholds** (a 20% move changes what the rule detects): EG05
`min_unaddressed_pairs` (+20% loses the defect in 24 of 24 runs; -20% adds false positives in
5 of 24 portfolio runs and 16 of 20 stress runs); EG07 `min_closures_per_analyst_hour`, NS05
`max_dormant_share`, NS08 `review_period_months` (defect lost in 24 of 24); EG04
`max_comment_hash_share` and `min_hash_group_size` (lost in 20 of 20 stress runs); EG09
`min_stale_cases` (4 of 24 in Phase 5, none after Phase 8); EG12 `min_skipped_cases`, NS03 `max_robust_z`, EG05
`min_repeat_count` (1 of 24 each).

**No threshold was changed in this pass.** The false positives and misses above are reported,
not tuned away. The one rule-logic change (EG02/EG04 judging closures only) is a population
fix; on the synthetic sets, where every alert is closed, it changes nothing (21/21 and 3/3
before and after).

**Shadow-pilot mode**, run on a stand-in workpaper built from the generator's ground truth:
122 rows, 47 confirmed; finding recall 100% (47/47), precision 100%, 59.6% (28/47) of confirmed
records in the review queue. It proves the evaluation pipeline runs. It is not independent
evidence.

## Phase 6: Legal and traceability

`docs/legal_traceability.md` maps the problem statement's 17 functional, 6 deployment and 6
out-of-scope items (as quoted from <https://sih2026.vuce.in/ps/SIH26157>, read on 2026-09-30
through a summarising fetch tool) to component and test, quotes Section 70A, and marks every
statutory reading beyond the text **needs legal review**.

What the check found:

- **The problem statement cites no law.** The link to Section 70A is a chain (NCIIPC is the
  agency designated under it; the problem statement says NCIIPC reviews SOC records).
- **UI text attributed requirements to the law that could not be supported**: "Under Rule 3
  of NCIIPC Rules, 2013 ... mathematical determinism", "Section 70A evidence standards",
  "Section 70A Registry", "Audit Directive under Sec 70A". Removed or reworded.
- **The notice was not where the documents said it was.** It appeared on the finding page and
  the HTML reports only. It is now on every web page, every page of every PDF, and on every
  record of the findings and queue JSON and CSV exports.

```bash
pytest tests/test_supervisory_notice.py    # 9 tests
```

Pseudonymisation and redaction tests are listed by name in `docs/legal_traceability.md`
Section 5 (`tests/test_ingest.py`, `tests/test_connectors.py`).

Not verified: the official text of Section 70A (the India Code page refused the fetch; the
text used came from a web search); the NCIIPC designation; the 2013 Rules (not read);
reporting obligations behind NS07 (not read); the DPDP Act, 2023 (not assessed).

## Phase 7: Code quality

```bash
ruff check .            # All checks passed (src, tests, scripts, entrypoint.py)
mypy src                # Success: no issues found in 63 source files
python -m coverage run --branch --source=src/satsa -m pytest tests -q
python -m coverage report
```

| Coverage (statements and branches) | |
|---|---:|
| Whole package | **89%** |
| `rules/` | base 100%, execution_gaps 99%, negative_space 99%, registry 96%, systemic 94% |
| `scoring/` | runner 100%, scorer 99%, prioritiser 97%, history 83% |
| `store/sqlite.py` (audit chain and state) | 91% |
| `ingest/` | mapper 96%, pipeline 89%, adapters 78% |
| Rules, scoring, audit store and ingest together | 93% |

- Real issues fixed: the SQLite adapter quoted table names in a way SQLite rejects (found by
  its first test); `entrypoint.py` now passes the linter.
- Removed as unreferenced: five `MetricsEngine` methods, one report helper, one ingest helper.
- Left in place, referenced by nothing: `has_permission` (`admin/rbac.py`) and four
  organisation/CSE getters and updaters in `store/sqlite.py`; the SPC detector
  (`peers/spc.py`) is used by no rule.
- Docs synced: README (test count, coverage, scale and hard-set rows, lift and sweep figures,
  CLI reference, index), `docs/infrastructure.md`, `docs/ps_traceability.md`,
  `docs/functional_design.md`, `docs/validation.md`; validation reports regenerated.

## Phase 8: Root causes of the hard-set failures

Each Phase 5 failure was traced to the records behind it before anything was changed.

```bash
python <scratch>/eg10_probe.py     # CSE-07 closure times per severity, 9 seeds x 2 volumes
python <scratch>/miss_probe.py     # records each EG03/EG09 injection actually changed
python <scratch>/eg05_probe.py     # repeat pairs on the noisy stress entity, 21 seeds
```

| Failure | What the records showed | Cause | Fix |
|---|---|---|---|
| EG10 false positive on CSE-07, 10 of 24 runs | 1-7 high/critical alerts per run closed up to 130,000 minutes **before** creation or months after; without them CSE-07's high-severity mean was 83-102 minutes against a declared 96 (critical 41-57 against 51) | Generator: the bulk-closure injection stamped the first 15 alerts closed on 31 March regardless of creation date | Bulk closure now sweeps the 15 low/medium alerts raised most recently before it |
| (same) | CSE-09 repeat alerts closed before they were created in all 3 seeds checked (16 at seed 42) | Generator: creation and closure hours drawn independently | One hour per alert; the random stream is unchanged |
| EG09 missed @ 808 | two of the four "stale" cases opened 1 and 7 days before period end; 2 stale, threshold 3 | Generator: cases picked by id, not age | The four opened earliest |
| EG03 missed @ 808, 600 alerts | the injection changed 0 records | Ground truth recorded a defect that was not injected | Recorded only when something was injected |
| EG05 on the noisy stress entity, 4 of 20 seeds | a random pair reaches exactly 8 benign, untuned repeats beside the built-in 9-repeat pair | The rule working as specified at the edge of its chance model | **Not changed**: it would need a threshold change judged on the data it is tuned to |

Rule change: **EG01 and EG10 (and the KPI reconciliation view and metrics engine) ignore
alerts closed before they were created.** These records are already reported by the
`close_before_create` data-quality check; real exports with clock skew contain them, and a
negative duration moved EG10's mean by weeks. No threshold was changed.

Results after the fixes (`python scripts/validate_hard.py`, 10 minutes; the primary and stress
sets and the test suite as at the top of this file):

| Set | Runs | Recall (95% CI) | Precision (95% CI) | Clean entities flagged |
|---|---:|---|---|---|
| Portfolio, 1,500 | 8 | 100% (168/168; 97.8-100%) | 100% (168/168; 97.8-100%) | 0 of 24 |
| Portfolio, 600 | 8 | 100% (167/167; 97.8-100%) | 100% (167/167; 97.8-100%) | 0 of 24 |
| Portfolio, 300 | 8 | 100% (168/168; 97.8-100%) | 100% (168/168; 97.8-100%) | 0 of 24 |
| **Portfolio, all** | **24** | **100% (503/503)** | **100% (503/503)** | **0 of 72** |
| Stress | 20 | 100% (60/60; 94.0-100%) | 93.8% (60/64; 85.0-97.5%) | 4 of 20 (EG05) |
| Primary (seed 42) | 1 | 21/21 | 21/21 | 0 of 3 |

What moved the other way: on the primary set the review queue grew from 129 to 130 alert
items and holds 18 defect-affected alerts instead of 19, so whole-queue lift fell from 5.52x
to 5.19x; top-25 lift is unchanged at 19.47x. The threshold sweep is unchanged (4 of 66
primary, 3 of 66 stress). Tests: 871 passed, 33 skipped, 0 failed; coverage 89%; ruff and
mypy clean.

What this does and does not change: the synthetic evidence is now clean on the portfolio
generator, and the four-for-four finding is that **the failures were in the test data, not the
rules**. It is still synthetic data built by people who knew the thresholds.

---

## Quality pass, Phase 7: coverage, property tests, offline install (2 October 2026)

Branch `quality/10of10`, same machine, run from the worktree (the suite now copies its inputs
to a temporary directory and bootstraps its own data, `tests/conftest.py`):

```bash
uv run coverage run --branch --source=src/satsa -m pytest tests -q -p no:cacheprovider
uv run coverage report --precision=1
```

| Measure | Result |
|---|---|
| Tests | 1,104 passed, 33 skipped, 0 failed (995.6 s under coverage) |
| Coverage, statements and branches | **89.2%** (9,157 statements, 809 missed; 2,550 branches, 304 partial) |
| Lowest modules | `cli.py` 42%, `validate/independent.py` 44%, `audit/keys.py` 75% |

Subprocesses are not measured (subprocess coverage is not enabled), so code that tests reach
only through `python -m satsa.cli` (the suite's data bootstrap, some CLI tests) counts as
missed; that is most of why `cli.py` is low. Branch coverage of 89.2% says which lines ran, not
that their results were checked.

Three property tests (EG06, NS01, NS06) were added after that coverage run. The final suite
for this phase, `uv run pytest tests -q -p no:cacheprovider`, gave **1,107 passed, 33 skipped,
0 failed** (866.5 s), with `data/`, `reports/` and `.satsa_salt` hashing the same before and
after; `satsa validate` 21/21, `satsa validate-stress` 3/3, `satsa audit verify` OK (388
entries), `ruff check .` clean, `mypy src` clean (73 files).

Property tests (`tests/test_property_rules.py`, `tests/test_property_ingest.py`) and the
offline install are described in `docs/CHANGES_quality_pass.md` (Phase 7) and
`docs/offline_install.md`. The CI workflow gained a coverage upload and a no-network install
job; **no CI run was executed** from this machine.

---

## Quality pass, Phase 8: final figures (2 October 2026)

Branch `quality/10of10`, final code, same machine (Python 3.11.16, Windows 11). Every row was
run in this phase; the full account of the pass is `docs/CHANGES_quality_pass.md`.

| Command | Result |
|---|---|
| `uv run coverage run --branch --source=src/satsa -m pytest tests -q -p no:cacheprovider` | **1,107 passed, 33 skipped, 0 failed** (870.5 s); `data/`, `reports/` and `.satsa_salt` hash the same before and after |
| `uv run coverage report --precision=1` | **89.2%** statements and branches (9,157 statements, 809 missed; 2,550 branches, 305 partial); rules 94.3-100%, scoring 82.7-100%, `store/sqlite.py` 91.2%; lowest `cli.py` 42.1% (subprocesses not measured) |
| `uv run satsa validate` | Recall 21/21, precision 21 of 21 findings, entity rank precision@k 100% |
| `uv run satsa validate-stress` | Recall 3/3, precision 3 of 3 findings |
| `uv run satsa audit verify` | 388 entries intact |
| `uv run ruff check .` / `uv run mypy src` | clean / clean (73 files) |
| `uv run satsa validate-independent --seeds 20 --start-seed 1` | Recall 487/487, precision 487/487, 0 of 245 decoys, 0 of 57 clean entities flagged (409 s); identical to the 2026-10-01 run |
| `python scripts/benchmark_scale.py --configs 10x50000,50x100000 --workdir build/bench ...` | 5,000,000 alerts: ingest **54.5 s** (5,424 MiB peak), assess **107.3 s** (3,301 MiB peak), 150 findings, first page after a run 15.4 s; 500,000 alerts: 7.1 s, 797 MiB, 9.8 s |

Before and after the pass (baseline: `docs/baseline_before.md`, 2026-09-30/10-01):

| Measure | Baseline | Final |
|---|---|---|
| Tests | 871 passed, 33 skipped, 0 failed (Python 3.13) | 1,107 passed, 33 skipped, 0 failed (Python 3.11) |
| Coverage (statements and branches) | 89% (7,417 statements) | 89.2% (9,157 statements) |
| Primary / stress validation | 21/21, 3/3 | 21/21, 3/3 |
| Independent generator (20 seeds) | did not exist | 487/487 recall and precision, 0 of 245 decoys |
| Ingest, 5,000,000 alerts | 603.0 s, 13,248 MiB (2026-09-30, Python 3.13) | 54.5 s, 5,424 MiB |
| Assess, 5,000,000 alerts | 310.2 s (2026-09-30) | 107.3 s (varies 106-191 s between runs; not claimed as an improvement) |

All of it is synthetic data. **Synthetic only; a real-data pilot is pending.**

---

## Open items

1. **No real data.** No real SOC submission and no real examiner finding has been run through
   SAT-SA. Accuracy on real data is unknown.
2. ~~EG10 false positives~~: resolved in Phase 8 (generator fault).
3. **EG05 false positives on a noisy clean entity**: 4 of 20 stress seeds; its
   `min_unaddressed_pairs` threshold is fragile in both directions.
4. ~~EG09 and EG03 each missed once~~: resolved in Phase 8 (generator faults).
5. **Connectors unverified against live systems.** Samples are hand-built; TheHive's rule
   identifier is approximated by the alert title; ServiceNow SIR has no field for external
   reporting. The web upload page accepts the canonical layout only.
6. **No product export supports all 20 rules**; supporting tables must be submitted alongside.
7. **Docker not run.** No Docker on the test machine: the image was not built, and the compose
   file was checked by parsing only. Whether `python:3.11-slim` includes the `openssl` command
   was not checked.
8. **Linux not run; CI never run.** The baseline ran on Python 3.13 (Windows); the quality
   pass's own worktree (from after Phase 2) runs Python 3.11 (Windows). Neither ran on Linux. The CI
   workflow (3.11 and 3.13 on Linux, coverage, offline install in an empty network namespace)
   has not been run, so none of its jobs is known to pass.
9. **Scale limits** (final code, 2026-10-02): 5,424 MiB peak to ingest 5M alerts; first page
   after a run takes 15.4 s at 5M; assessment time varied from 106 s to 191 s between runs of
   the same code; measured on one machine with uniform data; closure comments were pre-hashed,
   so free-text redaction cost is not in the ingest time.
10. **Legal review** of everything marked so in `docs/legal_traceability.md`, including the
    "Escalate to Statutory Notice" label on the review queue, which was left unchanged.
11. **Problem-statement wording** was read through a summarising tool; re-check the quotes
    against the page before submitting them.
12. **Peer comparison and outlier statistics are partial**: 4 and 2 of 20 rules.
13. **Unreferenced code left in place** (Phase 7).
14. **Band-floor policy** in `config/scoring.yaml` still awaits confirmation by the project owner.
15. **Tests sign in with the seeded passphrases**; the first-login flag is lifted for them in
    `tests/conftest.py`. (They no longer share the working database: since the quality pass
    the suite copies its inputs to a temporary directory and bootstraps its own data.)
16. **Nothing has been pushed.** The branch is local.
17. **Offline bundle under a deep path (quality pass).** From a 181-character working directory,
    `tests/test_bundle.py::test_offline_packager` fails on Windows: `satsa offline-bundle` copies
    the source tree under `dist/satsa_offline_bundle/`, which pushes the deepest file past 260
    characters. The four PDF-route tests that failed the same way are fixed (shorter report
    names, `docs/CHANGES_quality_pass.md` Phase 1); this one is not.
18. **The "independent" generator is not independent of mind** (quality pass, Phase 4). It
    shares no code with the original generator, but the same AI-assisted team wrote it after
    reading the rule code. Its 100% results test the code against its documentation, not
    accuracy.
19. **Threshold proposals not applied.** `docs/threshold_rationale.md` reviews EG04, EG05,
    EG07, NS05, NS08 and EG11; it proposes keeping most values and two changes to consider
    (EG04 `min_hash_group_size` scaled with volume, EG11 `min_spread` 0.02 once real spreads are
    known). No threshold or weight in `config/` was changed.
20. **No usability session run.** `docs/usability_protocol.md` and its template exist; there
    is no usability figure.
21. **Audit checkpoints:** only Ed25519 is implemented (ML-DSA names are reserved). On Windows
    the private-key permission check parses `icacls` output, which is less robust than POSIX
    mode bits. Key custody is a procedure (DECISIONS.md ADR-008), not something the tool
    enforces.
22. **Offline install checked without a physical disconnect.** The Windows bundle install ran
    with the package index pointed at a closed port; the no-network-namespace check exists only
    as an unrun CI job. A wheelhouse serves one OS family and Python minor version.

## Suggested re-rating

Based only on the evidence in this file.

| Dimension | Rating | Justification |
|---|---|---|
| Technical | **High** | 1,107 tests pass (including property-based tests) with 89.2% coverage, lint and type checks are clean, and findings and evidence are reproducible with the reference date recorded (2026-10-02). CI has not been run. |
| Operational | **Medium-High** | First-login rotation, loopback default and TLS are enforced and tested, and 5M alerts were ingested and assessed in under 3 minutes on a laptop (2026-10-02); Docker was not run, the offline install was not tried on a disconnected machine, and the first page after a run takes 15 s at that size. |
| Legal | **Medium** | The notice is now on every output and unsupported legal wording is removed, but the statutory basis rests on unread Rules and unverified text, all marked for legal review. |
| Economic | **Medium-High** | Runs offline on one commodity machine with open-source components and no licences or cloud cost; staffing and integration cost were not measured. |
| Data | **Medium** | Three product exports ingest end to end with gaps reported per rule, but on hand-built samples only, and none supports more than 10 of 20 rules alone. |
| Accuracy | **Medium** (synthetic ceiling) | On synthetic data recall and precision are 100% (503/503) across 24 seeded portfolio runs and 93.8% precision on the stress set (EG05); every hard-set failure was traced to its cause. Your rule caps Accuracy at Medium without real or realistic non-synthetic data, and none has been used. |

### In the requested table format

| Dimension | Rating | Evidence |
|---|---|---|
| Technical | **High** | 20 rules; 1,107 tests pass, 89.2% coverage (statements and branches), 2026-10-02 |
| Operational | **High** for speed; Medium-High overall | Assesses 50 entities (5,000,000 alerts) in 107 s, plus 54.5 s ingest (2026-10-02; assessment varied 106-191 s between runs); Docker not run |
| Legal | **Medium** | Mapped to the problem statement in `docs/legal_traceability.md`; **reviewed by: nobody yet** |
| Accuracy | **Medium** | Precision 100%, recall 100% on the synthetic hard set (24 runs, 503 defects); 93.8% precision on the stress set |
| Footer note | | **synthetic** |
| Scale row | **High** | Benchmarked to 50 entities, 100,000 alerts each |

Two cells cannot be filled truthfully from here. **Reviewed by [name]** needs a person with
legal standing who has read `docs/legal_traceability.md` and agrees to be named. **Accuracy:
High** needs results on real or realistic non-synthetic data, which also changes the footer
from "synthetic" to "realistic".
