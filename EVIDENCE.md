# SAT-SA Feasibility Evidence

> **Supervisory Notice:** *Indicators requiring supervisory review; not a compliance determination.*

Branch `feat/feasibility-evidence`, 17 commits on top of `main` (69028c6), 30 September 2026.
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
260-character limit under a long working directory.)

| After | Tests passed | Skipped | Failed | Primary set | Stress set |
|---|---:|---:|---:|---|---|
| Start (main) | 740 | 33 | 0 | 21/21, 0 false positives | 3/3, 0 false positives |
| Phase 1 | 772 | 33 | 0 | 21/21, 0 FP | 3/3, 0 FP |
| Phase 2 | 809 | 33 | 0 | 21/21, 0 FP | 3/3, 0 FP |
| Phase 3 | 847 | 33 | 0 | 21/21, 0 FP | 3/3, 0 FP |
| Phase 4 | 847 | 33 | 0 | 21/21, 0 FP | 3/3, 0 FP |
| Phases 5-7 (final) | **866** | 33 | **0** | 21/21, 0 FP | 3/3, 0 FP |

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
`min_stale_cases` (4 of 24); EG12 `min_skipped_cases`, NS03 `max_robust_z`, EG05
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

---

## Open items

1. **No real data.** No real SOC submission and no real examiner finding has been run through
   SAT-SA. Accuracy on real data is unknown.
2. **EG10 false positives**: 10 of 24 hard-set runs, always CSE-07. Cause not investigated.
3. **EG05 false positives on a noisy clean entity**: 4 of 20 stress seeds; its
   `min_unaddressed_pairs` threshold is fragile in both directions.
4. **EG09 and EG03 each missed once** (seed 808). Cause not investigated.
5. **Connectors unverified against live systems.** Samples are hand-built; TheHive's rule
   identifier is approximated by the alert title; ServiceNow SIR has no field for external
   reporting. The web upload page accepts the canonical layout only.
6. **No product export supports all 20 rules**; supporting tables must be submitted alongside.
7. **Docker not run.** No Docker on the test machine: the image was not built, and the compose
   file was checked by parsing only. Whether `python:3.11-slim` includes the `openssl` command
   was not checked.
8. **Python 3.11 and Linux not re-run** in this pass (3.11 last passed at an earlier step).
   The GitHub CI result was not visible.
9. **Scale limits**: 13.2 GB peak to ingest 5M alerts; first page after a run takes 27 s at 5M;
   assessment grows faster than linearly; measured on one machine with uniform data; closure
   comments were pre-hashed, so free-text redaction cost is not in the ingest time.
10. **Legal review** of everything marked so in `docs/legal_traceability.md`, including the
    "Escalate to Statutory Notice" label on the review queue, which was left unchanged.
11. **Problem-statement wording** was read through a summarising tool; re-check the quotes
    against the page before submitting them.
12. **Peer comparison and outlier statistics are partial**: 4 and 2 of 20 rules.
13. **Unreferenced code left in place** (Phase 7).
14. **Band-floor policy** in `config/scoring.yaml` still awaits confirmation by the project owner.
15. **Tests share one working database** and sign in with the seeded passphrases; the
    first-login flag is lifted for them in `tests/conftest.py`.
16. **Nothing has been pushed.** The branch is local.

## Suggested re-rating

Based only on the evidence in this file.

| Dimension | Rating | Justification |
|---|---|---|
| Technical | **High** | 866 tests pass with 89% coverage, lint and type checks are clean, and results are reproducible with the reference date recorded. |
| Operational | **Medium-High** | First-login rotation, loopback default and TLS are enforced and tested, and 5M alerts run in about 15 minutes on a laptop; Docker was not run and the first page after a run takes 27 s at that size. |
| Legal | **Medium** | The notice is now on every output and unsupported legal wording is removed, but the statutory basis rests on unread Rules and unverified text, all marked for legal review. |
| Economic | **Medium-High** | Runs offline on one commodity machine with open-source components and no licences or cloud cost; staffing and integration cost were not measured. |
| Data | **Medium** | Three product exports ingest end to end with gaps reported per rule, but on hand-built samples only, and none supports more than 10 of 20 rules alone. |
| Accuracy | **Low-Medium** | On synthetic data recall is 99.6% and precision 98.0% across 24 seeded runs, with known false positives (EG10, EG05); no real or realistic non-synthetic data has been used, so this cannot be rated higher. |
