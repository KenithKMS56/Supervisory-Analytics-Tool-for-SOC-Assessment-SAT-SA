# Baseline Before the Quality Pass

> **Supervisory Notice:** *Indicators requiring supervisory review; not a compliance determination.*

Recorded on 2026-10-01 on branch `quality/10of10` at commit f5a9ad0 (identical to
`fix/validation-root-causes`), before any change of the quality pass. **All data is synthetic.**
Every figure below comes from the command printed next to it, run in this session, except the
benchmark section, which is copied from `docs/benchmarks.md` and labelled as such.

**Machine:** AMD Ryzen 5 7235HS (4 cores, 8 threads), 23.7 GB RAM, Windows 11 (10.0.26300),
Python 3.13.2, DuckDB 1.5.5, Polars 1.44.2, uv 0.12.19, pytest 9.1.1, coverage 7.16.2.
Working directory: the repository checkout (path length 88 characters).

## 1. Data bootstrap (from a clean `data/`)

The pre-existing local `data/` directory was moved out of the repository first, so ingest did
not append to old Parquet files.

```bash
uv run satsa generate-data && uv run satsa ingest && uv run satsa run
uv run python scripts/build_shadow_standin.py
```

Ingest reported 10 entities, 18 data-quality issues, and all 20 rules assessable for every entity.

## 2. Test suite and coverage

```bash
uv run coverage run --branch --source=src/satsa -m pytest tests -q -p no:cacheprovider -rfE
uv run coverage report
```

| Result | Value |
|---|---:|
| Passed | **871** |
| Skipped | 33 |
| Failed | **0** |
| Wall time (under coverage) | 514.87 s |
| Coverage, statements and branches | **89%** (7,417 statements, 629 missed; 1,904 branches, 256 partial) |

Selected modules (same command): `rules/` base 100%, execution_gaps 99%, negative_space 99%,
registry 96%, systemic 94%; `scoring/` runner 100%, scorer 99%, prioritiser 97%, history 83%;
`store/sqlite.py` 91%; `ingest/` mapper 96%, pipeline 89%, adapters 78%.

```bash
uv run ruff check .     # All checks passed!
uv run mypy src         # Success: no issues found in 63 source files
```

## 3. Validation

```bash
uv run satsa validate --shadow-csv data/generated/shadow_pilot_standin.csv
```

| Measure | Result |
|---|---|
| Injected defect recall | 100.0% (21/21) |
| Defect precision (every finding counted) | 100.0% (21 of 21 findings) |
| False positives (clean / defect entities) | 0 / 0 |
| Entity rank Precision@k | 100.0% |
| Threshold sensitivity (±20%) | 4 of 66 moves change an outcome: EG05 `min_unaddressed_pairs` 2→3, EG07 `min_closures_per_analyst_hour` 30→36, NS05 `max_dormant_share` 0.4→0.48, NS08 `review_period_months` 6→5 (each loses its defect); EG03 and NS07 have no tunable threshold |
| Ranking stability (±20% domain weights) | Spearman ρ = 1.0000 |
| Review-effort lift, whole 130-alert queue | 5.19x (18/130 queue alerts affected, 13.9% vs 2.67% random) |
| Shadow-pilot rehearsal (stand-in workpaper) | 122 rows, 47 confirmed; finding recall 100.0% (47/47), queue record recall 59.6% (28/47), precision 100.0% |
| Audit chain | verified (2 entries) |

```bash
uv run satsa validate-stress
```

| Measure | Result |
|---|---|
| Injected defect recall | 100.0% (3/3) |
| Defect precision | 100.0% (3 of 3 findings) |
| Entity rank Precision@k | 100.0% |
| Threshold sensitivity (±20%) | 3 of 66 moves change an outcome: EG04 `max_comment_hash_share` 0.25→0.3 (misses STRESS-01, STRESS-02), EG04 `min_hash_group_size` 10→12 (misses STRESS-01), EG05 `min_unaddressed_pairs` 2→1 (false alarm on STRESS-03) |

Both commands rewrite their tracked reports (`docs/validation_report.*`,
`docs/validation_stress_report.md`); the only change was the run ID and timestamp, so the
committed reports were restored.

**Comparison with EVIDENCE.md:** 871 passed / 33 skipped / 0 failed, 21/21 and 3/3, coverage
89%, as recorded there. The baseline does not differ materially.

## 4. The Windows 260-character path failures

At the repository path (88 characters) nothing fails. To reproduce the failures EVIDENCE.md
mentions, `git archive HEAD` was extracted to a scratch directory whose path is 181 characters
(188 once Windows expands the short name `SANJAY~1`), the data was bootstrapped there, and the
full suite was run with that copy's `src/` first on `PYTHONPATH`:

```bash
python -m satsa.cli generate-data && python -m satsa.cli ingest && python -m satsa.cli run
python -m pytest tests -q -p no:cacheprovider -rfE
```

Result: **866 passed, 33 skipped, 5 failed**.

| Failing test | Cause |
|---|---|
| `tests/test_api.py::test_report_downloads` | PDF route: `reports/SAT-SA_CSE_<entity>_Report_<full run id>.pdf.tmp` exceeds 260 characters (`FileNotFoundError`, HTTP 500) |
| `tests/test_report_pdf.py::test_pdf_routes_serve_named_pdfs` | same (portfolio, entity and finding PDF names) |
| `tests/test_supervisory_notice.py::test_pdfs_served_by_the_app_carry_the_notice` | same |
| `tests/test_offline_hardening.py::test_every_get_route_is_offline_and_healthy` | same (the PDF routes return 500) |
| `tests/test_bundle.py::test_offline_packager` | **Different cause:** `satsa offline-bundle` copies the source tree into `dist/satsa_offline_bundle/`, adding about 22 characters to the deepest source path. Not a report file name. |

The first four are the report tests EVIDENCE.md refers to. Example overflowing name:
`reports\SAT-SA_CSE_CSE-03_Report_RUN-20261001094014509392-bbaf3dfa.pdf.tmp` (75 characters
after the root).

## 5. Benchmarks (as recorded on 2026-09-30, not re-run)

Copied from `docs/benchmarks.md`, produced there by
`python scripts/benchmark_scale.py --configs 10x50000,25x100000,50x100000 --out docs/benchmarks.md`
on the same laptop model (Windows build 10.0.26200 at that time). **Not re-run for this baseline.**

| Entities x alerts | Alerts | Rows | Ingest | Ingest peak | Assess | Assess peak | `/portfolio` first | `/portfolio` repeat |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 10 x 50,000 | 500,000 | 2,171,868 | 65.9 s | 1,858 MB | 16.3 s | 460 MB | 2,921 ms | 60 ms |
| 25 x 100,000 | 2,500,000 | 10,681,566 | 309.7 s | 6,996 MB | 105.2 s | 1,728 MB | 13,148 ms | 92 ms |
| 50 x 100,000 | 5,000,000 | 21,365,139 | 603.0 s | 13,248 MB | 310.2 s | 3,314 MB | 27,021 ms | 95 ms |

The README's "DuckDB Scan Throughput 10,623,549 rows/second" comes from `satsa benchmark`
(a single in-memory aggregation query), recorded in `docs/infrastructure.md` §2.1; it was not
re-run either and is not an end-to-end figure.
