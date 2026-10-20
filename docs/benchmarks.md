# SAT-SA Scale Benchmarks

> **Supervisory Notice:** *Indicators requiring supervisory review; not a compliance determination.*

**Current figures: Section "After the product brief: performance work (2026-10-20)" below.** The
other sections are earlier runs, kept with their dates, including the end of the brief's Phase 5
(2026-10-19). (They use an older project's phase numbering: their
"Phase 5" is an ingest change from 2026-10-01, not the product brief's Phase 5.) Measured with `scripts/benchmark_scale.py`,
on the machine described below.
Every figure is a measurement from the runs named here; nothing is extrapolated. Timings on
other hardware will differ. Sizes and memory are in MiB (1 MiB = 1,048,576 bytes); earlier
versions of this page labelled the same figures "MB".

The Phase 5 comparison used two runs, on the same machine and Python interpreter, one after
the other:

- **After** (the code just after the Phase 5 change): `python scripts/benchmark_scale.py --configs 10x50000,50x100000 --out <file> --json <file>`
- **Before** (the code as it was before the Phase 5 ingest change: commit `b371788` plus the
  evidence-ordering fix described in `docs/CHANGES_quality_pass.md`, M14): the same command, run from a copy of that source
  tree, so that its stage processes import the old ingest code.

The Phase 5 tables are those runs' own output; the raw results of every run are at the end.

## After the product brief: performance work (2026-10-20): current figures

Measured on branch `feat/post-brief-followups` after the changes listed below, on the machine
below (Python 3.13.2, Windows 11 build 10.0.26300). **One development laptop, not the declared
4-vCPU / 8-GiB reference machine.** Every figure is from the runs whose raw output is at the end
of this page.

```
python scripts/benchmark_scale.py --configs 10x10000,10x10000:skewed,10x10000:freetext,10x10000:uneven,10x50000 --readers --workdir build/bench --stage-timeout 3000 --out ... --json ...
python scripts/benchmark_scale.py --configs 40x50000 --workdir build/bench --stage-timeout 3000 --out ... --json ...
python scripts/benchmark_scale.py --configs 50x100000 --workdir build/bench --stage-timeout 3000 --out ... --json ...   (run twice)
```

### Ingest and assessment

| Entities x alerts each | Profile | Alerts | Ingest | Ingest peak | Assess | Assess peak | Ingest + assess | Findings |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| 10 x 10,000 | uniform | 100,000 | 5.2 s | 337 MiB | 4.9 s | 214 MiB | 10.1 s | 29 |
| 10 x 10,000 | skewed | 100,000 | 3.8 s | 393 MiB | 4.4 s | 215 MiB | 8.2 s | 23 |
| 10 x 10,000 | freetext | 100,000 | 21.7 s | 518 MiB | 3.5 s | 231 MiB | 25.2 s | 29 |
| 10 x 10,000 | uneven | 100,000 | 3.5 s | 339 MiB | 3.5 s | 214 MiB | 7.0 s | 29 |
| 10 x 50,000 | uniform | 500,000 | 6.4 s | 876 MiB | 9.6 s | 568 MiB | 16.0 s | 30 |
| 40 x 50,000 | uniform | 2,000,000 | 27.2 s | 2,770 MiB | 49.1 s | 1,879 MiB | 76.3 s | 120 |
| 50 x 100,000 | uniform | 5,000,000 | 51.5 s | 6,398 MiB | 112.7 s | 4,487 MiB | **164.2 s** | 150 |
| 50 x 100,000 (repeat run) | uniform | 5,000,000 | 50.5 s | 6,390 MiB | 112.1 s | 4,487 MiB | **162.6 s** | 150 |

At 5,000,000 alerts, ingest and assessment together took 164.2 s and 162.6 s in two runs, under
3 minutes. On the code at the end of the brief's Phase 5 they took 450.5 s (96.9 s + 353.6 s,
2026-10-19). The free-text ingest at 100,000 alerts (21.7 s) is slower than the Phase 5 run
(17.1 s) although nothing in its path got more expensive; its repeat ingest took 15.2 s.
Run-to-run spread on this laptop is that large, so single figures are indications.

### Same data, same session: before and after

At 2,000,000 alerts (40 entities), on copies of one data directory taken at the same moment, the
code before these changes (commit `c8d191e`) and after:

| | Before | After |
|---|---:|---:|
| Assessment | 130.5 s | 49.6 s |
| Reload of every table (`load_all_tables`, two runs each) | 18.5-18.9 s | 22.3-22.6 s |

The ingest of the same 2,000,000-alert submission, timed step by step on the same day: 48.1 s at
the start of this work, 26.2 s at the end (not side by side, so an indication).

**Every stored result is identical**: findings and evidence, per-rule results, domain and entity
scores, review queues, peer comparisons and anomaly-scan metrics, compared value for value, and
the run's data fingerprint, configuration hash and selection are the same (only the code version,
run id and time differ). Old runs therefore replay as before.

### Ten concurrent readers (a served instance, one uvicorn process)

| Entities x alerts each | Profile | Phase | Requests | Errors | p50 | p95 | Max |
|---|---|---|---:|---:|---:|---:|---:|
| 10 x 10,000 | uniform | idle | 200 | 0 | 635 ms | 781 ms | 1,231 ms |
| 10 x 10,000 | uniform | during ingest | 200 | 0 | 698 ms | 1,539 ms | 3,668 ms |
| 10 x 10,000 | skewed | idle | 200 | 0 | 612 ms | 829 ms | 1,501 ms |
| 10 x 10,000 | skewed | during ingest | 200 | 0 | 635 ms | 1,481 ms | 3,369 ms |
| 10 x 10,000 | freetext | idle | 200 | 0 | 408 ms | 499 ms | 912 ms |
| 10 x 10,000 | freetext | during ingest | 200 | 0 | 349 ms | 996 ms | 1,825 ms |
| 10 x 10,000 | uneven | idle | 200 | 0 | 403 ms | 515 ms | 797 ms |
| 10 x 10,000 | uneven | during ingest | 200 | 0 | 447 ms | 1,253 ms | 2,167 ms |
| 10 x 50,000 | uniform | idle | 200 | 0 | 467 ms | 640 ms | 823 ms |
| 10 x 50,000 | uniform | during ingest | 200 | 0 | 774 ms | 1,574 ms | 6,944 ms |

The p95 stays under the proposed 2 s. At 500,000 alerts during an ingest it is 1.57 s (0.99 s in
the Phase 5 run) and the slowest single request 6.9 s (4.5 s): the request that waits for the
reload after the publication, which the entity sort below makes about 16% longer.

### First page after a run

| Entities x alerts each | Reload of every table | `/portfolio` first request | `/portfolio` repeat |
|---|---:|---:|---:|
| 10 x 10,000 | 1.42 s | 2,020 ms | 66 ms |
| 40 x 50,000 | 20.62 s | 22,118 ms | 74 ms |
| 50 x 100,000 | 50.10 s | 55,273 ms | 83 ms |

**Not improved:** the first analytics request after a run waits for the web app to reload every
table (55 s at 5,000,000 alerts; 45.9 s in the Phase 5 run, 17.4 s on 2026-10-02). Later
requests take under a second. The worker does not pre-load the web app's cache after a run.

### What changed

Each change keeps every result as it was (see above); the two that compute differently are
pinned by tests against the previous computation.

- **Tables loaded in entity order.** Version selection and DISTINCT returned rows in hash order,
  so every per-entity query (each rule, for each entity) read the whole table: no row group's
  min/max excluded another entity. Sorted by entity, DuckDB skips them. Costs about 3 s per
  reload at 2M alerts.
- **Peer rules read portfolio figures once per run** (`DuckDBStore.memo`): NS02's categories,
  EG11's false-positive rates, NS08's count of other entities and EG01's close times were
  queried over the whole peer cohort again for each entity, which made the rules quadratic in
  the portfolio's size. EG01's 5th percentile is computed in Python with DuckDB's own
  interpolation (`RobustStats.quantile_cont`; `tests/test_robust_stats.py` checks it bit for bit
  against DuckDB).
- **Local time computed once per run** (`satsa.context.local_time_counts`): NS03 and the anomaly
  scan each converted every alert to its entity's time zone (about 2.6 microseconds an alert).
  The conversion is now done once, per entity and UTC hour, with alert-by-alert conversion in
  any hour holding an offset change (`tests/test_local_time.py` compares every alert's local
  time with converting it alone, across DST changes and fractional offsets, and fails if the
  fallback is removed).
- **Ingest no longer reloads every table after publishing.** The published tables are reloaded
  when the store is next read (`DuckDBStore.mark_stale`); the CLI and the import job never read
  it again, and an assessment reloads everything itself. The published files are still read
  back, so a file that cannot be read is reported as before.
- **Staged files written, hashed and flushed to disk in one pass** (each was opened three times).
- **Review queue:** a set rebuilt for every alert of the entity, and the unusable-column check run
  as one query per entity instead of one per column.

## Product-brief Phase 5 (2026-10-19)

Measured on the code at the end of the product brief's Phase 5 (`feat/product-brief-phase5`),
on the machine below but with Python 3.13.2 and Windows 11 build 10.0.26300. These are the
figures at the end of Phase 5, superseded by the section above. They come from **one development laptop, not the declared 4-vCPU / 8-GiB
reference machine**, so they are not evidence for the proposed targets on that machine.

```
python scripts/benchmark_scale.py --configs 10x10000,10x10000:skewed,10x10000:freetext,10x10000:uneven,10x50000 --readers --workdir build/bench --out ... --json ...
python scripts/benchmark_scale.py --configs 40x50000,50x100000 --workdir build/bench --out ... --json ...
```

### Proposed v1 targets (docs/product_brief.md section 13) against this laptop

| Proposed target (not a promise) | Measured here |
|---|---|
| 100k representative alerts assessed within 60 s | 4.6 to 6.3 s across the four profiles |
| p95 of warmed reads under 2 s with ten read sessions | idle: 0.51 to 0.93 s; while another process ingests: 0.92 to 1.54 s (100k), 0.99 s (500k). The slowest single request: 1.6 to 3.1 s (100k), 4.5 s (500k), during the reload that follows a publication |
| One worker within a documented memory budget | assessment peak 210 to 222 MiB at 100k, 516 MiB at 500k, 1,604 MiB at 2M, 3,800 MiB at 5M; the worker's memory preflight uses 256 MiB + 200 B per published row |

### Ingest and assessment

| Entities x alerts each | Profile | Alerts (largest / smallest entity) | Rows (all tables) | CSV | Parquet | Data dir | Ingest | Ingest peak | Assess | Assess peak | Findings |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 10 x 10,000 | uniform | 100,000 (10,000 / 10,000) | 493,004 | 48 MiB | 6 MiB | 7 MiB | 6.2 s | 362 MiB | 6.3 s | 210 MiB | 29 |
| 10 x 10,000 | skewed | 100,000 (34,146 / 3,414) | 493,089 | 48 MiB | 6 MiB | 7 MiB | 5.4 s | 391 MiB | 6.2 s | 214 MiB | 23 |
| 10 x 10,000 | freetext | 100,000 (10,000 / 10,000) | 493,004 | 105 MiB | 9 MiB | 10 MiB | 17.1 s | 518 MiB | 4.7 s | 222 MiB | 29 |
| 10 x 10,000 | uneven | 100,000 (10,000 / 10,000) | 493,004 | 48 MiB | 6 MiB | 7 MiB | 4.2 s | 359 MiB | 4.6 s | 211 MiB | 29 |
| 10 x 50,000 | uniform | 500,000 | 2,172,437 | 226 MiB | 28 MiB | 30 MiB | 8.3 s | 872 MiB | 13.6 s | 516 MiB | 30 |
| 40 x 50,000 | uniform | 2,000,000 | 8,692,253 | 906 MiB | 114 MiB | 117 MiB | 31.6 s | 2,750 MiB | 79.1 s | 1,604 MiB | 120 |
| 50 x 100,000 | uniform | 5,000,000 | 21,365,529 | 2,248 MiB | 281 MiB | 286 MiB | 96.9 s | 6,399 MiB | 353.6 s | 3,800 MiB | 150 |

### Ten concurrent readers (a served instance, one uvicorn process)

| Entities x alerts each | Profile | Phase | Requests | Errors | p50 | p95 | Max | Requests/s | Concurrent ingest |
|---|---|---|---:|---:|---:|---:|---:|---:|---|
| 10 x 10,000 | uniform | idle | 200 | 0 | 627 ms | 928 ms | 1,539 ms | 14.0 | |
| 10 x 10,000 | uniform | during ingest | 200 | 0 | 589 ms | 1,428 ms | 3,142 ms | 11.9 | 98,748 rows in 3.8 s, peak 300 MiB |
| 10 x 10,000 | skewed | idle | 200 | 0 | 383 ms | 603 ms | 978 ms | 21.5 | |
| 10 x 10,000 | skewed | during ingest | 200 | 0 | 409 ms | 1,544 ms | 2,021 ms | 17.5 | 98,581 rows in 2.6 s, peak 301 MiB |
| 10 x 10,000 | freetext | idle | 200 | 0 | 390 ms | 601 ms | 1,010 ms | 22.2 | |
| 10 x 10,000 | freetext | during ingest | 200 | 0 | 334 ms | 1,260 ms | 1,621 ms | 20.5 | 98,748 rows in 5.3 s, peak 330 MiB |
| 10 x 10,000 | uneven | idle | 200 | 0 | 373 ms | 509 ms | 984 ms | 22.8 | |
| 10 x 10,000 | uneven | during ingest | 200 | 0 | 378 ms | 922 ms | 1,933 ms | 19.8 | 98,748 rows in 2.6 s, peak 297 MiB |
| 10 x 50,000 | uniform | idle | 200 | 0 | 414 ms | 641 ms | 1,021 ms | 20.1 | |
| 10 x 50,000 | uniform | during ingest | 200 | 0 | 459 ms | 989 ms | 4,453 ms | 14.1 | 434,602 rows in 5.7 s, peak 741 MiB |

Ten sessions share one process, so the median is about ten times a single request's time (the
table below). No request failed.

### Repeated submission (the first submission ingested again, unchanged)

| Entities x alerts each | Profile | Repeat ingest | Status | Stored alerts before | after |
|---|---|---:|---|---:|---:|
| 10 x 10,000 | uniform | 7.2 s | success | 120,000 | 120,000 |
| 10 x 10,000 | skewed | 5.0 s | success | 120,000 | 120,000 |
| 10 x 10,000 | freetext | 17.0 s | success | 120,000 | 120,000 |
| 10 x 10,000 | uneven | 4.7 s | success | 120,000 | 120,000 |
| 10 x 50,000 | uniform | 10.4 s | success | 600,000 | 600,000 |

A repeated submission is read and validated again (its time is that of an ingest) but stores no
second copy: the stored alert count does not change. ("Before" includes the two entities the
readers step added.)

### Page loads (single client; first request after a run, then the median of the next 5)

| Entities x alerts each | Reload of all tables | `/portfolio` first | `/portfolio` repeat | `/alerts` repeat | `/entity` repeat | `/queue` repeat |
|---|---:|---:|---:|---:|---:|---:|
| 10 x 10,000 (uniform) | 1.10 s | 1,848 ms | 62 ms | 71 ms | 81 ms | 59 ms |
| 10 x 50,000 | 4.96 s | 3,152 ms | 38 ms | 70 ms | 55 ms | 37 ms |
| 40 x 50,000 | 11.21 s | 11,570 ms | 44 ms | 178 ms | 72 ms | 41 ms |
| 50 x 100,000 | 41.31 s | 45,873 ms | 78 ms | 823 ms | 179 ms | 86 ms |

### What Phase 5 changed, measured

At 100k alerts, before and after the Phase 5 performance work (same command and machine; the
"before" run is `build/bench_phase5_before.log`, stopped after three profiles):

| | Before | After |
|---|---:|---:|
| Free-text ingest | 47.2 s, peak 3,023 MiB | 17.1 s, peak 518 MiB |
| Readers p95 while another process ingests (uniform / skewed / free text) | 2,764 / 1,387 / 5,061 ms | 1,428 / 1,544 / 1,260 ms |
| Readers max while another process ingests (uniform / free text) | 6,506 / 14,204 ms | 3,142 / 1,621 ms |
| Single-client repeat: `/portfolio`, `/entity`, `/api/v1/entities` | 71, 139, 43 ms | 51, 68, 23 ms (in-process profiling run on the 100k uniform data) |

The changes: a store no longer re-runs its schema checks (DDL in a write transaction) on every
open; the Parquet walk behind the analytics cache runs at most every 2 s, publications being seen
at once through the catalog's sequence; configuration YAML is parsed once per change; the
time-zone list is read once; free-text redaction hashes only the ten shingles it stores and
joins its results instead of replacing over every comment. Assessment: NS03 converts every
alert's time zone once per run instead of once per entity, NS06 no longer multiplies every alert
by every log day of an asset, and NS08 reads the portfolio's months once. Findings are unchanged
(golden, rule and replay tests).

### Regressions and anomalies, reported as found

- **Larger portfolios are slower than on 2026-10-02.** At 5,000,000 alerts: ingest 96.9 s
  (46.6 s then), assessment 353.6 s (124.0 s then), first portfolio page after a run 45.9 s
  (17.4 s then). The data and machine are the same; the code now selects record versions,
  fingerprints every selected row, resolves context and records per-rule results and peer
  cohorts (Phases 1 to 4), and the peer queries of several rules still scan the whole alert
  table once per entity. Assessment grows faster than the data: 13.6 s at 500,000, 79.1 s at
  2,000,000, 353.6 s at 5,000,000. Above 500,000 alerts these times are measured, not a
  supported tier; nothing larger than 100,000 alerts is advertised.
- **One 5,000,000-alert run earlier the same day took 1,595 s to ingest and 1,397 s to assess.**
  Ingest at 1M and 2M alerts measured 25 s and 47 s just afterwards (linear), so that run was
  not reproduced; the assessment slowdown was the quadratic behaviour fixed above. Run-to-run
  spread on this laptop is large (the same 2M assessment: 124 s and 274 s in two runs before the
  final one), and Windows Defender scans every new Parquet file (about 5 ms per file open in the
  ingest profile). Treat single figures as indications.
- **The first request after a publication or a new run waits for the reload** of every table
  (41 s at 5,000,000 alerts); other requests queue behind it. The worker does not pre-load the
  web app's cache after a run.

## Machine

| | |
|---|---|
| CPU | AMD Ryzen 5 7235HS |
| Logical CPUs | 8 |
| RAM | 23.7 GB |
| OS | Windows (build 10.0.26300; `platform.release()` reports "10") |
| Python | 3.11.16 |
| DuckDB | 1.5.5 |
| Polars | 1.44.2 |

## What is measured

- **Data:** a generated canonical submission: the 14 tables of `satsa generate-data`, with
  2 workflow events and 1 closure per alert, a case and an escalation for 5% of alerts, and
  40 assets per entity reporting daily log volumes for 181 days. It is clean, uniform data built
  for volume; it says nothing about detection quality. Closure comments are submitted
  pre-hashed (as the generator does), so free-text redaction is not part of the ingest time.
- **Ingest:** `IngestionPipeline.ingest_directory` on the CSV directory (read, normalise,
  pseudonymise, data-quality checks, Parquet write, reload into DuckDB, manifest, audit entry).
- **Assess:** `AssessmentRunner.run_assessment` (all 20 rules for every entity, scoring, review
  queue, persistence).
- **Pages:** the SAT-SA web app through an in-process client, signed in as the analyst. Each
  page is requested 6 times: the first request, and the median of the next 5.
- **Peak memory:** the highest resident memory (peak working set) of the process that ran the
  stage; each stage runs in its own process.

## Final code (2026-10-02)

The code at the end of the quality pass, including the exploratory anomaly scan and the
control/process ranking (which run inside every assessment), on the same machine and Python as
the runs below:

```
python scripts/benchmark_scale.py --configs 10x50000,50x100000 --workdir build/bench --out <file> --json <file>
```

| Entities x alerts each | Alerts | Rows (all tables) | CSV | Parquet | Ingest | Ingest peak | Assess | Assess peak | Findings |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 10 x 50,000 | 500,000 | 2,171,868 | 226 MiB | 23 MiB | 6.5 s | 805 MiB | 10.6 s | 488 MiB | 30 |
| 50 x 100,000 | 5,000,000 | 21,365,139 | 2,248 MiB | 221 MiB | 46.6 s | 5,425 MiB | 124.0 s | 3,751 MiB | 150 |

Page loads (first request, and median of the next 5):

| Entities x alerts each | Reload (old per-request cost) | Page | First request | Repeat (median of 5) | Pages peak |
|---|---:|---|---:|---:|---:|
| 10 x 50,000 | 1.77 s | `/portfolio` | 1,757 ms | 33 ms | 457 MiB |
|  |  | `/alerts` | 87 ms | 69 ms |  |
|  |  | `/entity/{entity}` | 76 ms | 63 ms |  |
|  |  | `/queue` | 28 ms | 20 ms |  |
|  |  | `/api/v1/entities` | 23 ms | 23 ms |  |
| | | *30 requests caused 1 table load(s)* | | | |
| 50 x 100,000 | 15.03 s | `/portfolio` | 17,444 ms | 81 ms | 3,281 MiB |
|  |  | `/alerts` | 475 ms | 458 ms |  |
|  |  | `/entity/{entity}` | 125 ms | 106 ms |  |
|  |  | `/queue` | 30 ms | 21 ms |  |
|  |  | `/api/v1/entities` | 62 ms | 64 ms |  |
| | | *30 requests caused 1 table load(s)* | | | |

The same command on the code just before the anomaly scan was added (the Phase 8 code, commit `0c32b57`), earlier
the same day:

| Entities x alerts each | Alerts | Rows (all tables) | CSV | Parquet | Ingest | Ingest peak | Assess | Assess peak | Findings |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 10 x 50,000 | 500,000 | 2,171,868 | 226 MiB | 23 MiB | 7.1 s | 797 MiB | 9.8 s | 454 MiB | 30 |
| 50 x 100,000 | 5,000,000 | 21,365,139 | 2,248 MiB | 221 MiB | 54.5 s | 5,424 MiB | 107.3 s | 3,301 MiB | 150 |

With the scan, assessment at 5,000,000 alerts took 124.0 s instead of 107.3 s and peaked at
3,751 MiB instead of 3,301 MiB; findings are identical (150). The time difference is within
this machine's run-to-run spread for the same code (106 s to 191 s, sections below), so how
much of it is the scan was not separated; the extra memory is consistent with the scan's
metric tables. Ingest code did not change (46.6 s here against 54.5 s: run-to-run variation).

Compared with the first run of this page on 2026-09-30 (Section "Earlier recorded run"), at
5,000,000 alerts: ingest 603.0 s to 46.6 s, ingest peak 13,248 to 5,425 MiB. That run used
another Python and Windows build; the like-for-like comparison of the ingest change is the
Phase 5 table below (529.7 s to 54.2 s). Assessment is not compared as an improvement: its
time varies widely between runs here, and the scan has since added work to it. The first page
after a run or an ingest still reloads every table (17.4 s here; 15.4 s to 27.0 s in earlier
runs).

## Ingest before and after the Phase 5 change

| Entities x alerts each | Alerts | Ingest before | Ingest after | Faster by | Ingest peak before | Ingest peak after | Assess before | Assess after |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 10 x 50,000 | 500,000 | 55.1 s | 6.5 s | 8.5x | 1,855 MiB | 1,155 MiB | 13.8 s | 14.8 s |
| 50 x 100,000 | 5,000,000 | 529.7 s | 54.2 s | 9.8x | 13,339 MiB | 5,716 MiB | 165.2 s | 153.8 s |

Against the targets set for this change:

- **Ingest at least 3x faster:** met. 9.8x at 5,000,000 alerts and 8.5x at 500,000.
- **Ingest peak under 6 GB at 5,000,000 alerts:** under 6 GiB (6,144 MiB) every time, but not
  reliably under 6 GB (decimal, 5,722 MiB). Three measurements give 5,716 MiB (this run, 5.99 GB),
  5,731 MiB (the 2026-10-02 run below, 6.01 GB) and 5,736 MiB (a memory trace, 6.01 GB). The
  peak comes while the largest file (10,000,000 workflow events, 938 MiB of CSV) is read; reading
  that file alone peaks at about 2.8 GiB, with every reader Polars offers (measured; a batched or
  streaming read was no lower). An earlier version of this page said "met, narrowly" on the
  first measurement alone. **Met after the memory change below:** 5,435 and 5,440 MiB (5.70 GB)
  in two runs, against 5,761 MiB for the code before it in the same session.
- **Findings unchanged:** `tests/test_golden_findings.py` compares every stored row, DQ issue,
  finding, score, review-queue item and systemic finding with a snapshot taken before the
  change; it passes on both the old and the new code.

What changed (details in `docs/CHANGES_quality_pass.md`, Phase 5):

1. A canonical CSV table is normalised column by column instead of as one Python dict per row
   (`satsa/ingest/columnar.py`). This was 45% of ingest time under the profiler, and row
   hygiene (1.47 million HMAC calls at 10 x 50,000) another 18%. Per-value functions now run
   once per distinct value.
2. The data-quality checks work on columns (`FrameDQ`) instead of per-entity row dicts, and
   find each entity's rows by position instead of copying every table per entity.
3. Each table's frame is released once written, and the written tables are reloaded into
   DuckDB after all are written, so a submission is not held as frames and as DuckDB tables
   at once.

What did not change: assessment, which this change did not touch (the two runs differ by 7%,
in opposite directions at the two sizes; run-to-run variation was not measured), and the
first web page after a run or ingest, which still reloads every table (about 20 s at
5,000,000 alerts).

Reproduce the profile that guided the change with
`uv run python scripts/profile_ingest.py --entities 10 --alerts 50000` (add `--no-profile`
for timing only).

## Peak-memory change (2026-10-02)

Two changes lower the ingest's peak memory (details in `docs/CHANGES_quality_pass.md`, second
Phase 5 follow-up): the largest CSV of a submission is read before the others, while nothing else
is held, and Polars' memory allocator on Windows (mimalloc) is told to return freed memory at
once (`MIMALLOC_PURGE_DELAY=0`, set in `satsa/__init__.py` unless the environment sets it).

`python scripts/benchmark_scale.py --configs 50x100000 --out <file> --json <file>`, run twice back
to back on the same machine: first on commit `26d842e` (the code before the change), then on the
changed code.

| Code | Ingest | Ingest peak | Assess |
|---|---:|---:|---:|
| Before (`26d842e`) | 44.1 s | 5,761 MiB | 121.2 s |
| After | 50.0 s | 5,435 MiB | 114.2 s |

The peak falls by 326 MiB and is under 6 GB (5,722 MiB) with 287 MiB to spare; a second run of
the changed code (`--configs 10x50000,50x100000`) gave 5,440 MiB at 5,000,000 alerts and 804 MiB
at 500,000. Ingest takes about 6 s (13%) longer at 5,000,000 alerts: memory returned at once has
to be requested again. Assessment code did not change; its difference is run-to-run variation,
which on this machine and day was large (the same assessment took 190.7 s in another run).

## Re-run after the close-before-create fix (2026-10-02)

`python scripts/benchmark_scale.py --configs 10x50000,50x100000 --out <file> --json <file>`, same
machine, after the Phase 5 follow-up (M15 in `docs/CHANGES_quality_pass.md`), which adds a timestamp
cast to the data-quality checks:

| Entities x alerts each | Alerts | Ingest | Ingest peak | Assess | Findings |
|---|---:|---:|---:|---:|---:|
| 10 x 50,000 | 500,000 | 5.4 s | 1,261 MiB | 10.0 s | 30 |
| 50 x 100,000 | 5,000,000 | 45.8 s | 5,731 MiB | 106.3 s | 150 |

A memory trace of a 5,000,000-alert ingest (resident and peak memory logged at each step) shows
the peak (5,736 MiB) set while the workflow-event CSV is read, before the data-quality checks
start (5,324 MiB resident); memory stays below that peak through the checks. The difference from
the 5,716 MiB above is therefore run-to-run variation in that read, not the fix. Assessment ran
faster on this run (106.3 s against 153.8 s) with no change to assessment code; that spread is
variation between runs on this machine, and neither figure is a claim of improvement.

## Results (after the Phase 5 change, 2026-10-01)

| Entities x alerts each | Alerts | Rows (all tables) | CSV | Parquet | Ingest | Ingest peak | Assess | Assess peak | Findings |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 10 x 50,000 | 500,000 | 2,171,868 | 226 MiB | 23 MiB | 6.5 s | 1,155 MiB | 14.8 s | 457 MiB | 30 |
| 50 x 100,000 | 5,000,000 | 21,365,139 | 2,248 MiB | 221 MiB | 54.2 s | 5,716 MiB | 153.8 s | 3,307 MiB | 150 |

### Page loads

"Reload" is what every request paid before the analytics cache: building a store and
re-reading every Parquet table. It is measured directly here (`DuckDBStore.load_all_tables`)
and is now paid once, on the first analytics request after a run completes or the data changes.

| Entities x alerts each | Reload (old per-request cost) | Page | First request | Repeat (median of 5) | Pages peak |
|---|---:|---|---:|---:|---:|
| 10 x 50,000 | 1.73 s | `/portfolio` | 2,627 ms | 54 ms | 456 MiB |
|  |  | `/alerts` | 192 ms | 119 ms |  |
|  |  | `/entity/{entity}` | 193 ms | 105 ms |  |
|  |  | `/queue` | 48 ms | 33 ms |  |
|  |  | `/api/v1/entities` | 36 ms | 34 ms |  |
| | | *30 requests caused 1 table load(s)* | | | |
| 50 x 100,000 | 20.01 s | `/portfolio` | 23,459 ms | 125 ms | 3,286 MiB |
|  |  | `/alerts` | 754 ms | 702 ms |  |
|  |  | `/entity/{entity}` | 181 ms | 183 ms |  |
|  |  | `/queue` | 54 ms | 48 ms |  |
|  |  | `/api/v1/entities` | 119 ms | 99 ms |  |
| | | *30 requests caused 1 table load(s)* | | | |

## Results (before the Phase 5 change, 2026-10-01)

| Entities x alerts each | Alerts | Rows (all tables) | CSV | Parquet | Ingest | Ingest peak | Assess | Assess peak | Findings |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 10 x 50,000 | 500,000 | 2,171,868 | 226 MiB | 23 MiB | 55.1 s | 1,855 MiB | 13.8 s | 458 MiB | 30 |
| 50 x 100,000 | 5,000,000 | 21,365,139 | 2,248 MiB | 221 MiB | 529.7 s | 13,339 MiB | 165.2 s | 3,301 MiB | 150 |

### Page loads

"Reload" is what every request paid before the analytics cache: building a store and
re-reading every Parquet table. It is measured directly here (`DuckDBStore.load_all_tables`)
and is now paid once, on the first analytics request after a run completes or the data changes.

| Entities x alerts each | Reload (old per-request cost) | Page | First request | Repeat (median of 5) | Pages peak |
|---|---:|---|---:|---:|---:|
| 10 x 50,000 | 1.65 s | `/portfolio` | 2,495 ms | 50 ms | 457 MiB |
|  |  | `/alerts` | 156 ms | 116 ms |  |
|  |  | `/entity/{entity}` | 145 ms | 101 ms |  |
|  |  | `/queue` | 63 ms | 32 ms |  |
|  |  | `/api/v1/entities` | 35 ms | 33 ms |  |
| | | *30 requests caused 1 table load(s)* | | | |
| 50 x 100,000 | 18.03 s | `/portfolio` | 22,728 ms | 125 ms | 3,283 MiB |
|  |  | `/alerts` | 853 ms | 717 ms |  |
|  |  | `/entity/{entity}` | 217 ms | 178 ms |  |
|  |  | `/queue` | 73 ms | 37 ms |  |
|  |  | `/api/v1/entities` | 137 ms | 101 ms |  |
| | | *30 requests caused 1 table load(s)* | | | |

## Earlier recorded run (2026-09-30, not repeated)

The figures this page carried before Phase 5, recorded on 2026-09-30 with
`python scripts/benchmark_scale.py --configs 10x50000,25x100000,50x100000 --out docs/benchmarks.md`
on the same laptop but a different environment: Python 3.13.2, Windows build 10.0.26200.
They are kept for the 25 x 100,000 size, which was not re-run. They are **not** comparable
one-to-one with the tables above: the pre-change code measured on 2026-10-01 assessed
5,000,000 alerts in 165.2 s, against 310.2 s here, with no change to assessment in between.

| Entities x alerts each | Alerts | Rows (all tables) | CSV | Parquet | Ingest | Ingest peak | Assess | Assess peak | Findings |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 10 x 50,000 | 500,000 | 2,171,868 | 226 MiB | 23 MiB | 65.9 s | 1,858 MiB | 16.3 s | 460 MiB | 30 |
| 25 x 100,000 | 2,500,000 | 10,681,566 | 1,124 MiB | 111 MiB | 309.7 s | 6,996 MiB | 105.2 s | 1,728 MiB | 75 |
| 50 x 100,000 | 5,000,000 | 21,365,139 | 2,248 MiB | 221 MiB | 603.0 s | 13,248 MiB | 310.2 s | 3,314 MiB | 150 |

## Raw results

After:

```json
[
 {
  "entities": 10,
  "alerts_per_entity": 50000,
  "alerts": 500000,
  "rows": 2171868,
  "csv_mb": 226.37182521820068,
  "generate_seconds": 1.2518120999993698,
  "ingest": {
   "seconds": 6.469936399999824,
   "rows": 2171878,
   "dq_issues": 0,
   "ok": true,
   "peak_mb": 1155.19140625,
   "wall_seconds": 8.188374100000146
  },
  "assess": {
   "seconds": 14.817449200000738,
   "findings": 30,
   "queue": 300,
   "ok": true,
   "peak_mb": 457.37890625,
   "wall_seconds": 16.237560399999893
  },
  "pages": {
   "reload_seconds": 1.7317508000005546,
   "pages": {
    "/portfolio": {
     "first": 2.626683600000433,
     "repeat_median": 0.053526299999248295
    },
    "/alerts": {
     "first": 0.19196329999977024,
     "repeat_median": 0.1185273999999481
    },
    "/entity/{entity}": {
     "first": 0.1928472999998121,
     "repeat_median": 0.10528840000006312
    },
    "/queue": {
     "first": 0.04806129999997211,
     "repeat_median": 0.03271929999937129
    },
    "/api/v1/entities": {
     "first": 0.03623509999943053,
     "repeat_median": 0.033717999999680615
    }
   },
   "table_loads": 1,
   "requests": 30,
   "ok": true,
   "peak_mb": 455.5625,
   "wall_seconds": 9.28604280000036
  },
  "parquet_mb": 22.58732318878174
 },
 {
  "entities": 50,
  "alerts_per_entity": 100000,
  "alerts": 5000000,
  "rows": 21365139,
  "csv_mb": 2248.088671684265,
  "generate_seconds": 11.20273619999989,
  "ingest": {
   "seconds": 54.178342500000326,
   "rows": 21365189,
   "dq_issues": 0,
   "ok": true,
   "peak_mb": 5716.02734375,
   "wall_seconds": 56.876672399999734
  },
  "assess": {
   "seconds": 153.78058090000013,
   "findings": 150,
   "queue": 1500,
   "ok": true,
   "peak_mb": 3307.43359375,
   "wall_seconds": 155.84995049999998
  },
  "pages": {
   "reload_seconds": 20.00865579999936,
   "pages": {
    "/portfolio": {
     "first": 23.459092500000224,
     "repeat_median": 0.1247548999999708
    },
    "/alerts": {
     "first": 0.7537317999995139,
     "repeat_median": 0.702470600000197
    },
    "/entity/{entity}": {
     "first": 0.18125589999999647,
     "repeat_median": 0.1832962000007683
    },
    "/queue": {
     "first": 0.054148999999597436,
     "repeat_median": 0.047979599999962375
    },
    "/api/v1/entities": {
     "first": 0.11930899999970279,
     "repeat_median": 0.09885979999944539
    }
   },
   "table_loads": 1,
   "requests": 30,
   "ok": true,
   "peak_mb": 3285.6171875,
   "wall_seconds": 54.60639689999971
  },
  "parquet_mb": 221.3611192703247
 }
]
```

Before:

```json
[
 {
  "entities": 10,
  "alerts_per_entity": 50000,
  "alerts": 500000,
  "rows": 2171868,
  "csv_mb": 226.37182521820068,
  "generate_seconds": 1.2753705999994054,
  "ingest": {
   "seconds": 55.08685280000009,
   "rows": 2171878,
   "dq_issues": 0,
   "ok": true,
   "peak_mb": 1855.1484375,
   "wall_seconds": 56.85080800000014
  },
  "assess": {
   "seconds": 13.753193599999577,
   "findings": 30,
   "queue": 300,
   "ok": true,
   "peak_mb": 457.9921875,
   "wall_seconds": 15.160832100000334
  },
  "pages": {
   "reload_seconds": 1.654683599999771,
   "pages": {
    "/portfolio": {
     "first": 2.4952878000003693,
     "repeat_median": 0.0504242000006343
    },
    "/alerts": {
     "first": 0.15567830000054528,
     "repeat_median": 0.1158237999998164
    },
    "/entity/{entity}": {
     "first": 0.14467580000018643,
     "repeat_median": 0.10127579999971204
    },
    "/queue": {
     "first": 0.06322430000000168,
     "repeat_median": 0.032016899999689485
    },
    "/api/v1/entities": {
     "first": 0.03475720000005822,
     "repeat_median": 0.033390999999937776
    }
   },
   "table_loads": 1,
   "requests": 30,
   "ok": true,
   "peak_mb": 456.94140625,
   "wall_seconds": 8.860028800000691
  },
  "parquet_mb": 22.587308883666992
 },
 {
  "entities": 50,
  "alerts_per_entity": 100000,
  "alerts": 5000000,
  "rows": 21365139,
  "csv_mb": 2248.088671684265,
  "generate_seconds": 10.580810700000256,
  "ingest": {
   "seconds": 529.7495679999993,
   "rows": 21365189,
   "dq_issues": 0,
   "ok": true,
   "peak_mb": 13339.28125,
   "wall_seconds": 533.1861827000002
  },
  "assess": {
   "seconds": 165.22564450000027,
   "findings": 150,
   "queue": 1500,
   "ok": true,
   "peak_mb": 3301.27734375,
   "wall_seconds": 167.63449029999992
  },
  "pages": {
   "reload_seconds": 18.031801299999643,
   "pages": {
    "/portfolio": {
     "first": 22.72759859999951,
     "repeat_median": 0.1245812000006481
    },
    "/alerts": {
     "first": 0.8531231000006301,
     "repeat_median": 0.7170937000000777
    },
    "/entity/{entity}": {
     "first": 0.21684409999943455,
     "repeat_median": 0.17841599999974278
    },
    "/queue": {
     "first": 0.07253420000051847,
     "repeat_median": 0.036608000000342145
    },
    "/api/v1/entities": {
     "first": 0.13702960000046005,
     "repeat_median": 0.1005685000000085
    }
   },
   "table_loads": 1,
   "requests": 30,
   "ok": true,
   "peak_mb": 3282.9765625,
   "wall_seconds": 51.9353344000001
  },
  "parquet_mb": 221.35760593414307
 }
]
```

Before the anomaly scan was added (`0c32b57`, 2026-10-02):

```json
[
 {
  "entities": 10,
  "alerts_per_entity": 50000,
  "alerts": 500000,
  "rows": 2171868,
  "csv_mb": 226.37182521820068,
  "generate_seconds": 1.4442178000008425,
  "ingest": {
   "seconds": 7.129185100000541,
   "rows": 2171878,
   "dq_issues": 0,
   "ok": true,
   "peak_mb": 797.31640625,
   "wall_seconds": 8.808078000000023
  },
  "assess": {
   "seconds": 9.79210349999994,
   "findings": 30,
   "queue": 300,
   "ok": true,
   "peak_mb": 454.16796875,
   "wall_seconds": 11.106298799999422
  },
  "pages": {
   "reload_seconds": 1.6485334999997576,
   "pages": {
    "/portfolio": {
     "first": 1.7941672000015387,
     "repeat_median": 0.03376570000000356
    },
    "/alerts": {
     "first": 0.0995227999992494,
     "repeat_median": 0.07236940000075265
    },
    "/entity/{entity}": {
     "first": 0.07120120000035968,
     "repeat_median": 0.06321899999966263
    },
    "/queue": {
     "first": 0.03398409999863361,
     "repeat_median": 0.021923499998592888
    },
    "/api/v1/entities": {
     "first": 0.02510199999960605,
     "repeat_median": 0.023683100000198465
    }
   },
   "table_loads": 1,
   "requests": 30,
   "ok": true,
   "peak_mb": 457.484375,
   "wall_seconds": 6.9858576000006
  },
  "parquet_mb": 22.587337493896484
 },
 {
  "entities": 50,
  "alerts_per_entity": 100000,
  "alerts": 5000000,
  "rows": 21365139,
  "csv_mb": 2248.088671684265,
  "generate_seconds": 7.599077699998816,
  "ingest": {
   "seconds": 54.471194199999445,
   "rows": 21365189,
   "dq_issues": 0,
   "ok": true,
   "peak_mb": 5423.50390625,
   "wall_seconds": 56.968440499998906
  },
  "assess": {
   "seconds": 107.34106489999976,
   "findings": 150,
   "queue": 1500,
   "ok": true,
   "peak_mb": 3301.45703125,
   "wall_seconds": 109.26125780000075
  },
  "pages": {
   "reload_seconds": 14.728905899999518,
   "pages": {
    "/portfolio": {
     "first": 15.420827600000848,
     "repeat_median": 0.0773432000005414
    },
    "/alerts": {
     "first": 0.49939270000140823,
     "repeat_median": 0.45939849999922444
    },
    "/entity/{entity}": {
     "first": 0.11350700000002689,
     "repeat_median": 0.10331480000058946
    },
    "/queue": {
     "first": 0.029797099999996135,
     "repeat_median": 0.020859199999904376
    },
    "/api/v1/entities": {
     "first": 0.06139129999974102,
     "repeat_median": 0.061748800000714255
    }
   },
   "table_loads": 1,
   "requests": 30,
   "ok": true,
   "peak_mb": 3284.49609375,
   "wall_seconds": 37.93573589999869
  },
  "parquet_mb": 221.36109066009521
 }
]
```

Final code, with the anomaly scan (2026-10-02):

```json
[
 {
  "entities": 10,
  "alerts_per_entity": 50000,
  "alerts": 500000,
  "rows": 2171868,
  "csv_mb": 226.37182521820068,
  "generate_seconds": 1.1681518999994296,
  "ingest": {
   "seconds": 6.519486799999868,
   "rows": 2171878,
   "dq_issues": 0,
   "ok": true,
   "peak_mb": 804.78515625,
   "wall_seconds": 8.169195599999512
  },
  "assess": {
   "seconds": 10.592153699999471,
   "findings": 30,
   "queue": 300,
   "ok": true,
   "peak_mb": 488.16796875,
   "wall_seconds": 11.807548400000087
  },
  "pages": {
   "reload_seconds": 1.7654299999994691,
   "pages": {
    "/portfolio": {
     "first": 1.75749580000047,
     "repeat_median": 0.03309209999861196
    },
    "/alerts": {
     "first": 0.08695380000062869,
     "repeat_median": 0.06851900000037858
    },
    "/entity/{entity}": {
     "first": 0.0758322000001499,
     "repeat_median": 0.06324829999903159
    },
    "/queue": {
     "first": 0.028021199999784585,
     "repeat_median": 0.019981399998869165
    },
    "/api/v1/entities": {
     "first": 0.022831999998743413,
     "repeat_median": 0.022611200000028475
    }
   },
   "table_loads": 1,
   "requests": 30,
   "ok": true,
   "peak_mb": 457.265625,
   "wall_seconds": 6.814722399998573
  },
  "parquet_mb": 22.58732509613037
 },
 {
  "entities": 50,
  "alerts_per_entity": 100000,
  "alerts": 5000000,
  "rows": 21365139,
  "csv_mb": 2248.088671684265,
  "generate_seconds": 7.160080799998468,
  "ingest": {
   "seconds": 46.57715720000124,
   "rows": 21365189,
   "dq_issues": 0,
   "ok": true,
   "peak_mb": 5424.89453125,
   "wall_seconds": 48.65939299999991
  },
  "assess": {
   "seconds": 123.95488170000135,
   "findings": 150,
   "queue": 1500,
   "ok": true,
   "peak_mb": 3750.94921875,
   "wall_seconds": 125.6879313999998
  },
  "pages": {
   "reload_seconds": 15.028397800000675,
   "pages": {
    "/portfolio": {
     "first": 17.444206699999995,
     "repeat_median": 0.08050809999986086
    },
    "/alerts": {
     "first": 0.47464530000070226,
     "repeat_median": 0.4580017999996926
    },
    "/entity/{entity}": {
     "first": 0.12525209999876097,
     "repeat_median": 0.1055506000011519
    },
    "/queue": {
     "first": 0.029784300000756048,
     "repeat_median": 0.02077819999976782
    },
    "/api/v1/entities": {
     "first": 0.06215729999894393,
     "repeat_median": 0.0635061000011774
    }
   },
   "table_loads": 1,
   "requests": 30,
   "ok": true,
   "peak_mb": 3281.3203125,
   "wall_seconds": 39.880950400000074
  },
  "parquet_mb": 221.36116313934326
 }
]
```

### Raw results of the product-brief Phase 5 runs

```json
[
 {
  "entities": 10,
  "alerts_per_entity": 10000,
  "profile": "uniform",
  "largest_entity_alerts": 10000,
  "smallest_entity_alerts": 10000,
  "alerts": 100000,
  "rows": 493004,
  "csv_mb": 47.89201736450195,
  "generate_seconds": 0.7564120999995794,
  "ingest": {
   "seconds": 6.230055600000924,
   "rows": 493014,
   "dq_issues": 0,
   "batch_id": "BATCH-MULTI_CSE-b269a8057c89",
   "ok": true,
   "peak_mb": 362.3359375,
   "wall_seconds": 8.11452300000019
  },
  "assess": {
   "seconds": 6.277307799999107,
   "findings": 29,
   "queue": 300,
   "ok": true,
   "peak_mb": 210.22265625,
   "wall_seconds": 7.842806200002087
  },
  "pages": {
   "reload_seconds": 1.1023435999995854,
   "pages": {
    "/portfolio": {
     "first": 1.8479697000002488,
     "repeat_median": 0.06244399999923189
    },
    "/alerts": {
     "first": 0.0936851000005845,
     "repeat_median": 0.07119289999900502
    },
    "/entity/{entity}": {
     "first": 0.16632469999967725,
     "repeat_median": 0.08095690000118339
    },
    "/queue": {
     "first": 0.07968139999866253,
     "repeat_median": 0.05854420000105165
    },
    "/api/v1/entities": {
     "first": 0.025781399999686982,
     "repeat_median": 0.023441500001354143
    }
   },
   "table_loads": 1,
   "requests": 30,
   "ok": true,
   "peak_mb": 225.64453125,
   "wall_seconds": 7.552210200003174
  },
  "parquet_mb": 6.483203887939453,
  "data_dir_mb": 7.459970474243164,
  "readers": {
   "ok": true,
   "readers": 10,
   "idle": {
    "requests": 200,
    "errors": 0,
    "error_examples": [],
    "p50_ms": 627.0491000032052,
    "p95_ms": 928.0084999991232,
    "max_ms": 1538.602799999353,
    "seconds": 14.318411499996728,
    "per_second": 13.96802990332033
   },
   "during_ingest": {
    "requests": 200,
    "errors": 0,
    "error_examples": [],
    "p50_ms": 588.6159000001498,
    "p95_ms": 1428.4130999985791,
    "max_ms": 3141.551900000195,
    "seconds": 16.846943000000465,
    "per_second": 11.87158999706917,
    "concurrent": {
     "seconds": 3.791507299996738,
     "rows": 98748,
     "dq_issues": 0,
     "batch_id": "BATCH-MULTI_CSE-75b9f8855715",
     "ok": true,
     "peak_mb": 299.546875,
     "wall_seconds": 6.07350790000055
    }
   }
  },
  "repeat": {
   "seconds": 7.210410400002729,
   "status": "success",
   "message": "",
   "alerts_before": 120000,
   "alerts_after": 120000,
   "ok": true,
   "peak_mb": 377.3515625,
   "wall_seconds": 12.942406999998639
  },
  "data_dir_mb_after": 15.29865550994873
 },
 {
  "entities": 10,
  "alerts_per_entity": 10000,
  "profile": "skewed",
  "largest_entity_alerts": 34146,
  "smallest_entity_alerts": 3414,
  "alerts": 100000,
  "rows": 493089,
  "csv_mb": 47.89621448516846,
  "generate_seconds": 1.14137120000305,
  "ingest": {
   "seconds": 5.3753899000003,
   "rows": 493099,
   "dq_issues": 0,
   "batch_id": "BATCH-MULTI_CSE-c2543f229a11",
   "ok": true,
   "peak_mb": 390.76953125,
   "wall_seconds": 7.078087699999742
  },
  "assess": {
   "seconds": 6.170929600000818,
   "findings": 23,
   "queue": 253,
   "ok": true,
   "peak_mb": 214.0859375,
   "wall_seconds": 7.667206300000544
  },
  "pages": {
   "reload_seconds": 4.201300999997329,
   "pages": {
    "/portfolio": {
     "first": 1.2591205999997328,
     "repeat_median": 0.0498325999978988
    },
    "/alerts": {
     "first": 0.06706470000062836,
     "repeat_median": 0.050159300000814255
    },
    "/entity/{entity}": {
     "first": 0.11917560000074445,
     "repeat_median": 0.06240950000210432
    },
    "/queue": {
     "first": 0.0572734000015771,
     "repeat_median": 0.04664119999870309
    },
    "/api/v1/entities": {
     "first": 0.02187709999998333,
     "repeat_median": 0.020182399999612244
    }
   },
   "table_loads": 1,
   "requests": 30,
   "ok": true,
   "peak_mb": 226.00390625,
   "wall_seconds": 9.37979120000091
  },
  "parquet_mb": 6.447922706604004,
  "data_dir_mb": 7.405158042907715,
  "readers": {
   "ok": true,
   "readers": 10,
   "idle": {
    "requests": 200,
    "errors": 0,
    "error_examples": [],
    "p50_ms": 382.9714999992575,
    "p95_ms": 602.6534999982687,
    "max_ms": 977.8127999998105,
    "seconds": 9.288934699998208,
    "per_second": 21.530994291523932
   },
   "during_ingest": {
    "requests": 200,
    "errors": 0,
    "error_examples": [],
    "p50_ms": 409.463500000129,
    "p95_ms": 1543.889600001421,
    "max_ms": 2020.7821000003605,
    "seconds": 11.422342600002594,
    "per_second": 17.509543094947492,
    "concurrent": {
     "seconds": 2.6412147999981244,
     "rows": 98581,
     "dq_issues": 0,
     "batch_id": "BATCH-MULTI_CSE-d46172108d0b",
     "ok": true,
     "peak_mb": 300.921875,
     "wall_seconds": 4.817122399999789
    }
   }
  },
  "repeat": {
   "seconds": 4.994209399999818,
   "status": "success",
   "message": "",
   "alerts_before": 120000,
   "alerts_after": 120000,
   "ok": true,
   "peak_mb": 392.55859375,
   "wall_seconds": 9.878056099998503
  },
  "data_dir_mb_after": 15.190017700195312
 },
 {
  "entities": 10,
  "alerts_per_entity": 10000,
  "profile": "freetext",
  "largest_entity_alerts": 10000,
  "smallest_entity_alerts": 10000,
  "alerts": 100000,
  "rows": 493004,
  "csv_mb": 104.58500576019287,
  "generate_seconds": 0.8162036999965494,
  "ingest": {
   "seconds": 17.11561470000015,
   "rows": 493014,
   "dq_issues": 0,
   "batch_id": "BATCH-MULTI_CSE-94a3d0a80d51",
   "ok": true,
   "peak_mb": 518.2421875,
   "wall_seconds": 18.861788700000034
  },
  "assess": {
   "seconds": 4.674379499996576,
   "findings": 29,
   "queue": 300,
   "ok": true,
   "peak_mb": 222.0546875,
   "wall_seconds": 6.156754799998453
  },
  "pages": {
   "reload_seconds": 1.1250608000009379,
   "pages": {
    "/portfolio": {
     "first": 1.1540929000002507,
     "repeat_median": 0.03797549999944749
    },
    "/alerts": {
     "first": 0.06052529999942635,
     "repeat_median": 0.042070900002727285
    },
    "/entity/{entity}": {
     "first": 0.10986319999938132,
     "repeat_median": 0.04945210000005318
    },
    "/queue": {
     "first": 0.04743129999769735,
     "repeat_median": 0.03726209999877028
    },
    "/api/v1/entities": {
     "first": 0.028737699998600874,
     "repeat_median": 0.01591990000088117
    }
   },
   "table_loads": 1,
   "requests": 30,
   "ok": true,
   "peak_mb": 240.3828125,
   "wall_seconds": 5.872819600001094
  },
  "parquet_mb": 8.574081420898438,
  "data_dir_mb": 9.550848007202148,
  "readers": {
   "ok": true,
   "readers": 10,
   "idle": {
    "requests": 200,
    "errors": 0,
    "error_examples": [],
    "p50_ms": 390.4870000005758,
    "p95_ms": 601.3660999997228,
    "max_ms": 1009.7941999993054,
    "seconds": 9.023857399999542,
    "per_second": 22.163470801301685
   },
   "during_ingest": {
    "requests": 200,
    "errors": 0,
    "error_examples": [],
    "p50_ms": 334.11550000164425,
    "p95_ms": 1260.3893000014068,
    "max_ms": 1620.9276000008686,
    "seconds": 9.749291899999662,
    "per_second": 20.51431037776261,
    "concurrent": {
     "seconds": 5.300220299999637,
     "rows": 98748,
     "dq_issues": 0,
     "batch_id": "BATCH-MULTI_CSE-e0300d6ac584",
     "ok": true,
     "peak_mb": 329.828125,
     "wall_seconds": 7.400623800000176
    }
   }
  },
  "repeat": {
   "seconds": 16.974031599998852,
   "status": "success",
   "message": "",
   "alerts_before": 120000,
   "alerts_after": 120000,
   "ok": true,
   "peak_mb": 543.06640625,
   "wall_seconds": 21.698341999999684
  },
  "data_dir_mb_after": 19.8980073928833
 },
 {
  "entities": 10,
  "alerts_per_entity": 10000,
  "profile": "uneven",
  "largest_entity_alerts": 10000,
  "smallest_entity_alerts": 10000,
  "alerts": 100000,
  "rows": 493004,
  "csv_mb": 47.89201736450195,
  "generate_seconds": 0.6730891999977757,
  "ingest": {
   "seconds": 4.2303664999999455,
   "rows": 493014,
   "dq_issues": 0,
   "batch_id": "BATCH-MULTI_CSE-9e75ad235704",
   "ok": true,
   "peak_mb": 358.640625,
   "wall_seconds": 5.948172299998987
  },
  "assess": {
   "seconds": 4.583755200001178,
   "findings": 29,
   "queue": 300,
   "ok": true,
   "peak_mb": 210.5625,
   "wall_seconds": 6.05605579999974
  },
  "pages": {
   "reload_seconds": 1.1045384999997623,
   "pages": {
    "/portfolio": {
     "first": 1.0971205000023474,
     "repeat_median": 0.03782900000078371
    },
    "/alerts": {
     "first": 0.05956739999965066,
     "repeat_median": 0.04224190000240924
    },
    "/entity/{entity}": {
     "first": 0.10321340000155033,
     "repeat_median": 0.04894430000058492
    },
    "/queue": {
     "first": 0.06371040000158246,
     "repeat_median": 0.03742639999836683
    },
    "/api/v1/entities": {
     "first": 0.028359399999317247,
     "repeat_median": 0.015110399999684887
    }
   },
   "table_loads": 1,
   "requests": 30,
   "ok": true,
   "peak_mb": 225.8203125,
   "wall_seconds": 5.865222300002642
  },
  "parquet_mb": 6.406284332275391,
  "data_dir_mb": 7.383050918579102,
  "readers": {
   "ok": true,
   "readers": 10,
   "idle": {
    "requests": 200,
    "errors": 0,
    "error_examples": [],
    "p50_ms": 373.26019999818527,
    "p95_ms": 508.8517999975011,
    "max_ms": 983.5168000026897,
    "seconds": 8.761664699999528,
    "per_second": 22.826712371224474
   },
   "during_ingest": {
    "requests": 200,
    "errors": 0,
    "error_examples": [],
    "p50_ms": 377.8743000002578,
    "p95_ms": 922.0138999990013,
    "max_ms": 1932.6765999976487,
    "seconds": 10.112091899998632,
    "per_second": 19.778301263265522,
    "concurrent": {
     "seconds": 2.601227300001483,
     "rows": 98748,
     "dq_issues": 0,
     "batch_id": "BATCH-MULTI_CSE-0146b59da9ea",
     "ok": true,
     "peak_mb": 297.16796875,
     "wall_seconds": 4.580171200002951
    }
   }
  },
  "repeat": {
   "seconds": 4.737481899999693,
   "status": "success",
   "message": "",
   "alerts_before": 120000,
   "alerts_after": 120000,
   "ok": true,
   "peak_mb": 374.890625,
   "wall_seconds": 9.355185699998401
  },
  "data_dir_mb_after": 15.129098892211914
 },
 {
  "entities": 10,
  "alerts_per_entity": 50000,
  "profile": "uniform",
  "largest_entity_alerts": 50000,
  "smallest_entity_alerts": 50000,
  "alerts": 500000,
  "rows": 2172437,
  "csv_mb": 226.40796947479248,
  "generate_seconds": 1.2418150999983482,
  "ingest": {
   "seconds": 8.289070599999832,
   "rows": 2172447,
   "dq_issues": 0,
   "batch_id": "BATCH-MULTI_CSE-b89d1f1cea02",
   "ok": true,
   "peak_mb": 871.94921875,
   "wall_seconds": 10.058725600003527
  },
  "assess": {
   "seconds": 13.595414899999014,
   "findings": 30,
   "queue": 300,
   "ok": true,
   "peak_mb": 515.671875,
   "wall_seconds": 15.287718600000517
  },
  "pages": {
   "reload_seconds": 4.959297599998536,
   "pages": {
    "/portfolio": {
     "first": 3.1521511999999348,
     "repeat_median": 0.03767689999949653
    },
    "/alerts": {
     "first": 0.10162770000169985,
     "repeat_median": 0.0695780999994895
    },
    "/entity/{entity}": {
     "first": 0.16172670000014477,
     "repeat_median": 0.0552508000000671
    },
    "/queue": {
     "first": 0.056822800001100404,
     "repeat_median": 0.036763000000064494
    },
    "/api/v1/entities": {
     "first": 0.015110399999684887,
     "repeat_median": 0.01446849999774713
    }
   },
   "table_loads": 1,
   "requests": 30,
   "ok": true,
   "peak_mb": 523.48828125,
   "wall_seconds": 13.465714099998877
  },
  "parquet_mb": 28.365249633789062,
  "data_dir_mb": 29.513891220092773,
  "readers": {
   "ok": true,
   "readers": 10,
   "idle": {
    "requests": 200,
    "errors": 0,
    "error_examples": [],
    "p50_ms": 413.8039999998,
    "p95_ms": 640.7847000009497,
    "max_ms": 1020.667400000093,
    "seconds": 9.931742000000668,
    "per_second": 20.137454235116714
   },
   "during_ingest": {
    "requests": 200,
    "errors": 0,
    "error_examples": [],
    "p50_ms": 458.6732999996457,
    "p95_ms": 988.5548000020208,
    "max_ms": 4452.805400000216,
    "seconds": 14.164580900000146,
    "per_second": 14.119725914375477,
    "concurrent": {
     "seconds": 5.687669599999936,
     "rows": 434602,
     "dq_issues": 0,
     "batch_id": "BATCH-MULTI_CSE-d881befbbd32",
     "ok": true,
     "peak_mb": 741.328125,
     "wall_seconds": 7.818309199999931
    }
   }
  },
  "repeat": {
   "seconds": 10.431505100001232,
   "status": "success",
   "message": "",
   "alerts_before": 600000,
   "alerts_after": 600000,
   "ok": true,
   "peak_mb": 943.875,
   "wall_seconds": 20.99084220000077
  },
  "data_dir_mb_after": 63.53690147399902
 },
 {
  "entities": 40,
  "alerts_per_entity": 50000,
  "profile": "uniform",
  "largest_entity_alerts": 50000,
  "smallest_entity_alerts": 50000,
  "alerts": 2000000,
  "rows": 8692253,
  "csv_mb": 905.7588338851929,
  "generate_seconds": 3.2638363000005484,
  "ingest": {
   "seconds": 31.57629950000046,
   "rows": 8692293,
   "dq_issues": 0,
   "batch_id": "BATCH-MULTI_CSE-b67da1723314",
   "ok": true,
   "peak_mb": 2749.88671875,
   "wall_seconds": 33.397529800000484
  },
  "assess": {
   "seconds": 79.05753539999932,
   "findings": 120,
   "queue": 1200,
   "ok": true,
   "peak_mb": 1603.6875,
   "wall_seconds": 80.74972769999658
  },
  "pages": {
   "reload_seconds": 11.214091099998768,
   "pages": {
    "/portfolio": {
     "first": 11.569986099999369,
     "repeat_median": 0.043968499998300103
    },
    "/alerts": {
     "first": 0.1961529000000155,
     "repeat_median": 0.17847289999917848
    },
    "/entity/{entity}": {
     "first": 0.13055270000040764,
     "repeat_median": 0.07242580000092858
    },
    "/queue": {
     "first": 0.05919519999952172,
     "repeat_median": 0.041199999999662396
    },
    "/api/v1/entities": {
     "first": 0.05907350000052247,
     "repeat_median": 0.016337699998985045
    }
   },
   "table_loads": 1,
   "requests": 30,
   "ok": true,
   "peak_mb": 1597.05078125,
   "wall_seconds": 27.836880499999097
  },
  "parquet_mb": 113.8336181640625,
  "data_dir_mb": 116.84554100036621
 },
 {
  "entities": 50,
  "alerts_per_entity": 100000,
  "profile": "uniform",
  "largest_entity_alerts": 100000,
  "smallest_entity_alerts": 100000,
  "alerts": 5000000,
  "rows": 21365529,
  "csv_mb": 2248.1162853240967,
  "generate_seconds": 9.083945999998832,
  "ingest": {
   "seconds": 96.93810079999821,
   "rows": 21365579,
   "dq_issues": 0,
   "batch_id": "BATCH-MULTI_CSE-0b0c984c3c75",
   "ok": true,
   "peak_mb": 6399.3203125,
   "wall_seconds": 99.53342450000127
  },
  "assess": {
   "seconds": 353.5642795999993,
   "findings": 150,
   "queue": 1500,
   "ok": true,
   "peak_mb": 3800.49609375,
   "wall_seconds": 356.4098774000013
  },
  "pages": {
   "reload_seconds": 41.306112199999916,
   "pages": {
    "/portfolio": {
     "first": 45.8728873,
     "repeat_median": 0.0782997999995132
    },
    "/alerts": {
     "first": 0.8266651000012644,
     "repeat_median": 0.8234959000001254
    },
    "/entity/{entity}": {
     "first": 0.3422817999999097,
     "repeat_median": 0.17938630000207922
    },
    "/queue": {
     "first": 0.12702790000184905,
     "repeat_median": 0.08641329999954905
    },
    "/api/v1/entities": {
     "first": 0.12492869999914546,
     "repeat_median": 0.02809759999945527
    }
   },
   "table_loads": 1,
   "requests": 30,
   "ok": true,
   "peak_mb": 3752.58984375,
   "wall_seconds": 99.2910034000015
  },
  "parquet_mb": 281.05873584747314,
  "data_dir_mb": 285.72300243377686
 }
]
```

## Raw results: performance work (2026-10-20)

100,000-alert profiles and 500,000, with readers:

```json
[
 {
  "entities": 10,
  "alerts_per_entity": 10000,
  "profile": "uniform",
  "largest_entity_alerts": 10000,
  "smallest_entity_alerts": 10000,
  "alerts": 100000,
  "rows": 493004,
  "csv_mb": 47.89201736450195,
  "generate_seconds": 0.751863700003014,
  "ingest": {
   "seconds": 5.2390746000019135,
   "rows": 493014,
   "dq_issues": 0,
   "batch_id": "BATCH-MULTI_CSE-b269a8057c89",
   "ok": true,
   "peak_mb": 336.65234375,
   "wall_seconds": 7.3457606000010855
  },
  "assess": {
   "seconds": 4.878530299996783,
   "findings": 29,
   "queue": 300,
   "ok": true,
   "peak_mb": 214.08984375,
   "wall_seconds": 6.553188199999568
  },
  "pages": {
   "reload_seconds": 1.418489399999089,
   "pages": {
    "/portfolio": {
     "first": 2.020107600001211,
     "repeat_median": 0.06553510000230744
    },
    "/alerts": {
     "first": 0.09688860000460409,
     "repeat_median": 0.07220919999963371
    },
    "/entity/{entity}": {
     "first": 0.17659939999430208,
     "repeat_median": 0.08217270000022836
    },
    "/queue": {
     "first": 0.09494350000022678,
     "repeat_median": 0.06287039999733679
    },
    "/api/v1/entities": {
     "first": 0.02567280000221217,
     "repeat_median": 0.0248624000014388
    }
   },
   "table_loads": 1,
   "requests": 30,
   "ok": true,
   "peak_mb": 239.5703125,
   "wall_seconds": 8.256355000004987
  },
  "parquet_mb": 6.483229637145996,
  "data_dir_mb": 7.459996223449707,
  "readers": {
   "ok": true,
   "readers": 10,
   "idle": {
    "requests": 200,
    "errors": 0,
    "error_examples": [],
    "p50_ms": 634.5063999979175,
    "p95_ms": 780.7288999974844,
    "max_ms": 1231.1406000007992,
    "seconds": 13.9976647999938,
    "per_second": 14.288097540390352
   },
   "during_ingest": {
    "requests": 200,
    "errors": 0,
    "error_examples": [],
    "p50_ms": 697.9617000033613,
    "p95_ms": 1538.9992999989772,
    "max_ms": 3667.677500001446,
    "seconds": 17.02085409999563,
    "per_second": 11.750291661336274,
    "concurrent": {
     "seconds": 1.6872824000020046,
     "rows": 98748,
     "dq_issues": 0,
     "batch_id": "BATCH-MULTI_CSE-75b9f8855715",
     "ok": true,
     "peak_mb": 207.44921875,
     "wall_seconds": 3.999900399998296
    }
   }
  },
  "repeat": {
   "seconds": 4.021373600000516,
   "status": "success",
   "message": "",
   "alerts_before": 120000,
   "alerts_after": 120000,
   "ok": true,
   "peak_mb": 358.90234375,
   "wall_seconds": 10.462380000004487
  },
  "data_dir_mb_after": 15.29869270324707
 },
 {
  "entities": 10,
  "alerts_per_entity": 10000,
  "profile": "skewed",
  "largest_entity_alerts": 34146,
  "smallest_entity_alerts": 3414,
  "alerts": 100000,
  "rows": 493089,
  "csv_mb": 47.89621448516846,
  "generate_seconds": 1.134907400002703,
  "ingest": {
   "seconds": 3.8234940999973333,
   "rows": 493099,
   "dq_issues": 0,
   "batch_id": "BATCH-MULTI_CSE-c2543f229a11",
   "ok": true,
   "peak_mb": 393.25390625,
   "wall_seconds": 5.577889000000141
  },
  "assess": {
   "seconds": 4.363475899997866,
   "findings": 23,
   "queue": 253,
   "ok": true,
   "peak_mb": 215.4140625,
   "wall_seconds": 5.958467900003598
  },
  "pages": {
   "reload_seconds": 1.385285999996995,
   "pages": {
    "/portfolio": {
     "first": 2.0319222000034642,
     "repeat_median": 0.06404689999908442
    },
    "/alerts": {
     "first": 0.09414530000503873,
     "repeat_median": 0.06837599999562372
    },
    "/entity/{entity}": {
     "first": 0.1734435000034864,
     "repeat_median": 0.08401840000442462
    },
    "/queue": {
     "first": 0.07893419999891194,
     "repeat_median": 0.0604209000011906
    },
    "/api/v1/entities": {
     "first": 0.02544299999863142,
     "repeat_median": 0.02502509999612812
    }
   },
   "table_loads": 1,
   "requests": 30,
   "ok": true,
   "peak_mb": 239.89453125,
   "wall_seconds": 8.158759300000384
  },
  "parquet_mb": 6.447968482971191,
  "data_dir_mb": 7.405203819274902,
  "readers": {
   "ok": true,
   "readers": 10,
   "idle": {
    "requests": 200,
    "errors": 0,
    "error_examples": [],
    "p50_ms": 612.0786999963457,
    "p95_ms": 829.0942999956314,
    "max_ms": 1500.8431999958702,
    "seconds": 14.534389299995382,
    "per_second": 13.760468078288197
   },
   "during_ingest": {
    "requests": 200,
    "errors": 0,
    "error_examples": [],
    "p50_ms": 634.9559999944177,
    "p95_ms": 1481.0673000029055,
    "max_ms": 3369.1723000010825,
    "seconds": 16.91746950000379,
    "per_second": 11.822099043828937,
    "concurrent": {
     "seconds": 1.4395425999973668,
     "rows": 98581,
     "dq_issues": 0,
     "batch_id": "BATCH-MULTI_CSE-d46172108d0b",
     "ok": true,
     "peak_mb": 213.37890625,
     "wall_seconds": 3.658555099995283
    }
   }
  },
  "repeat": {
   "seconds": 3.937138599998434,
   "status": "success",
   "message": "",
   "alerts_before": 120000,
   "alerts_after": 120000,
   "ok": true,
   "peak_mb": 390.8515625,
   "wall_seconds": 10.40316530000564
  },
  "data_dir_mb_after": 15.190081596374512
 },
 {
  "entities": 10,
  "alerts_per_entity": 10000,
  "profile": "freetext",
  "largest_entity_alerts": 10000,
  "smallest_entity_alerts": 10000,
  "alerts": 100000,
  "rows": 493004,
  "csv_mb": 104.58500576019287,
  "generate_seconds": 1.6788529999976163,
  "ingest": {
   "seconds": 21.749190499998804,
   "rows": 493014,
   "dq_issues": 0,
   "batch_id": "BATCH-MULTI_CSE-94a3d0a80d51",
   "ok": true,
   "peak_mb": 518.19921875,
   "wall_seconds": 23.45525869999983
  },
  "assess": {
   "seconds": 3.524512500000128,
   "findings": 29,
   "queue": 300,
   "ok": true,
   "peak_mb": 230.92578125,
   "wall_seconds": 5.076410400004534
  },
  "pages": {
   "reload_seconds": 1.3770807000037166,
   "pages": {
    "/portfolio": {
     "first": 1.359895499997947,
     "repeat_median": 0.039113399994676
    },
    "/alerts": {
     "first": 0.06134159999783151,
     "repeat_median": 0.043452799996885005
    },
    "/entity/{entity}": {
     "first": 0.10685590000502998,
     "repeat_median": 0.05033910000202013
    },
    "/queue": {
     "first": 0.05028699999820674,
     "repeat_median": 0.037227699998766184
    },
    "/api/v1/entities": {
     "first": 0.01588330000231508,
     "repeat_median": 0.015598999998474028
    }
   },
   "table_loads": 1,
   "requests": 30,
   "ok": true,
   "peak_mb": 255.57421875,
   "wall_seconds": 6.412370099998952
  },
  "parquet_mb": 8.574085235595703,
  "data_dir_mb": 9.550851821899414,
  "readers": {
   "ok": true,
   "readers": 10,
   "idle": {
    "requests": 200,
    "errors": 0,
    "error_examples": [],
    "p50_ms": 407.8912999975728,
    "p95_ms": 498.9877999978489,
    "max_ms": 911.8403000029502,
    "seconds": 8.919743900005415,
    "per_second": 22.422168421212024
   },
   "during_ingest": {
    "requests": 200,
    "errors": 0,
    "error_examples": [],
    "p50_ms": 348.87480000179494,
    "p95_ms": 996.3693000026979,
    "max_ms": 1825.274700000591,
    "seconds": 10.163053199998103,
    "per_second": 19.679125560420893,
    "concurrent": {
     "seconds": 4.055897099999129,
     "rows": 98748,
     "dq_issues": 0,
     "batch_id": "BATCH-MULTI_CSE-e0300d6ac584",
     "ok": true,
     "peak_mb": 223.8203125,
     "wall_seconds": 6.2594265000007
    }
   }
  },
  "repeat": {
   "seconds": 15.227931100002024,
   "status": "success",
   "message": "",
   "alerts_before": 120000,
   "alerts_after": 120000,
   "ok": true,
   "peak_mb": 542.91015625,
   "wall_seconds": 20.64338129999669
  },
  "data_dir_mb_after": 19.897994995117188
 },
 {
  "entities": 10,
  "alerts_per_entity": 10000,
  "profile": "uneven",
  "largest_entity_alerts": 10000,
  "smallest_entity_alerts": 10000,
  "alerts": 100000,
  "rows": 493004,
  "csv_mb": 47.89201736450195,
  "generate_seconds": 0.6280119000002742,
  "ingest": {
   "seconds": 3.486956000000646,
   "rows": 493014,
   "dq_issues": 0,
   "batch_id": "BATCH-MULTI_CSE-9e75ad235704",
   "ok": true,
   "peak_mb": 339.234375,
   "wall_seconds": 5.283745599997928
  },
  "assess": {
   "seconds": 3.534687399995164,
   "findings": 29,
   "queue": 300,
   "ok": true,
   "peak_mb": 214.421875,
   "wall_seconds": 5.1024527000045055
  },
  "pages": {
   "reload_seconds": 1.3740984000032768,
   "pages": {
    "/portfolio": {
     "first": 1.300359800006845,
     "repeat_median": 0.04003799999918556
    },
    "/alerts": {
     "first": 0.05979530000331579,
     "repeat_median": 0.047435599997697864
    },
    "/entity/{entity}": {
     "first": 0.11113330000080168,
     "repeat_median": 0.05759330000000773
    },
    "/queue": {
     "first": 0.05791239999962272,
     "repeat_median": 0.04117150000092806
    },
    "/api/v1/entities": {
     "first": 0.02105009999650065,
     "repeat_median": 0.01763020000362303
    }
   },
   "table_loads": 1,
   "requests": 30,
   "ok": true,
   "peak_mb": 239.8046875,
   "wall_seconds": 6.518966399999044
  },
  "parquet_mb": 6.406319618225098,
  "data_dir_mb": 7.383086204528809,
  "readers": {
   "ok": true,
   "readers": 10,
   "idle": {
    "requests": 200,
    "errors": 0,
    "error_examples": [],
    "p50_ms": 402.9085000001942,
    "p95_ms": 515.1104000033229,
    "max_ms": 797.2544000003836,
    "seconds": 9.006018400003086,
    "per_second": 22.207371905872574
   },
   "during_ingest": {
    "requests": 200,
    "errors": 0,
    "error_examples": [],
    "p50_ms": 447.1902000004775,
    "p95_ms": 1253.0240999985836,
    "max_ms": 2166.5638999984367,
    "seconds": 12.514394399993762,
    "per_second": 15.981596360755555,
    "concurrent": {
     "seconds": 1.508577000000514,
     "rows": 98748,
     "dq_issues": 0,
     "batch_id": "BATCH-MULTI_CSE-0146b59da9ea",
     "ok": true,
     "peak_mb": 209.1484375,
     "wall_seconds": 3.991489800006093
    }
   }
  },
  "repeat": {
   "seconds": 3.1897461999978987,
   "status": "success",
   "message": "",
   "alerts_before": 120000,
   "alerts_after": 120000,
   "ok": true,
   "peak_mb": 358.5703125,
   "wall_seconds": 8.800073599995812
  },
  "data_dir_mb_after": 15.129148483276367
 },
 {
  "entities": 10,
  "alerts_per_entity": 50000,
  "profile": "uniform",
  "largest_entity_alerts": 50000,
  "smallest_entity_alerts": 50000,
  "alerts": 500000,
  "rows": 2172437,
  "csv_mb": 226.40796947479248,
  "generate_seconds": 1.2770242000042344,
  "ingest": {
   "seconds": 6.439549700000498,
   "rows": 2172447,
   "dq_issues": 0,
   "batch_id": "BATCH-MULTI_CSE-b89d1f1cea02",
   "ok": true,
   "peak_mb": 876.39453125,
   "wall_seconds": 8.33528269999806
  },
  "assess": {
   "seconds": 9.557735499998671,
   "findings": 30,
   "queue": 300,
   "ok": true,
   "peak_mb": 567.53125,
   "wall_seconds": 11.351741099999344
  },
  "pages": {
   "reload_seconds": 3.749894700005825,
   "pages": {
    "/portfolio": {
     "first": 3.76628879999771,
     "repeat_median": 0.041955099994083866
    },
    "/alerts": {
     "first": 0.09176969999680296,
     "repeat_median": 0.07262640000408283
    },
    "/entity/{entity}": {
     "first": 0.10785839999880409,
     "repeat_median": 0.05484530000103405
    },
    "/queue": {
     "first": 0.08047400000214111,
     "repeat_median": 0.04226040000503417
    },
    "/api/v1/entities": {
     "first": 0.016963800000667106,
     "repeat_median": 0.016347199998563156
    }
   },
   "table_loads": 1,
   "requests": 30,
   "ok": true,
   "peak_mb": 593.59375,
   "wall_seconds": 12.053893800002697
  },
  "parquet_mb": 28.365253448486328,
  "data_dir_mb": 29.51389503479004,
  "readers": {
   "ok": true,
   "readers": 10,
   "idle": {
    "requests": 200,
    "errors": 0,
    "error_examples": [],
    "p50_ms": 467.2223000015947,
    "p95_ms": 639.9962000068626,
    "max_ms": 822.7466999960598,
    "seconds": 10.601530100000673,
    "per_second": 18.865201354282558
   },
   "during_ingest": {
    "requests": 200,
    "errors": 0,
    "error_examples": [],
    "p50_ms": 773.8054000001284,
    "p95_ms": 1574.3241000018315,
    "max_ms": 6943.5169999997015,
    "seconds": 23.145112199999858,
    "per_second": 8.641133310211442,
    "concurrent": {
     "seconds": 2.4485490000006394,
     "rows": 434602,
     "dq_issues": 0,
     "batch_id": "BATCH-MULTI_CSE-d881befbbd32",
     "ok": true,
     "peak_mb": 385.44140625,
     "wall_seconds": 4.965526599997247
    }
   }
  },
  "repeat": {
   "seconds": 7.060110499995062,
   "status": "success",
   "message": "",
   "alerts_before": 600000,
   "alerts_after": 600000,
   "ok": true,
   "peak_mb": 883.515625,
   "wall_seconds": 23.917358200000308
  },
  "data_dir_mb_after": 63.53689765930176
 }
]
```

2,000,000:

```json
[
 {
  "entities": 40,
  "alerts_per_entity": 50000,
  "profile": "uniform",
  "largest_entity_alerts": 50000,
  "smallest_entity_alerts": 50000,
  "alerts": 2000000,
  "rows": 8692253,
  "csv_mb": 905.7588338851929,
  "generate_seconds": 3.8833184000031906,
  "ingest": {
   "seconds": 27.188152299997455,
   "rows": 8692293,
   "dq_issues": 0,
   "batch_id": "BATCH-MULTI_CSE-b67da1723314",
   "ok": true,
   "peak_mb": 2769.6328125,
   "wall_seconds": 29.05372690000513
  },
  "assess": {
   "seconds": 49.05329250000068,
   "findings": 120,
   "queue": 1200,
   "ok": true,
   "peak_mb": 1879.16015625,
   "wall_seconds": 50.92490969999926
  },
  "pages": {
   "reload_seconds": 20.620778699994844,
   "pages": {
    "/portfolio": {
     "first": 22.118486699997447,
     "repeat_median": 0.07388029999856371
    },
    "/alerts": {
     "first": 0.3177245999977458,
     "repeat_median": 0.29355989999749
    },
    "/entity/{entity}": {
     "first": 0.2860125000006519,
     "repeat_median": 0.08783470000344096
    },
    "/queue": {
     "first": 0.09369229999720119,
     "repeat_median": 0.07091939999372698
    },
    "/api/v1/entities": {
     "first": 0.027604399998381268,
     "repeat_median": 0.026018799995654263
    }
   },
   "table_loads": 1,
   "requests": 30,
   "ok": true,
   "peak_mb": 1907.5390625,
   "wall_seconds": 49.63372900000104
  },
  "parquet_mb": 113.83352088928223,
  "data_dir_mb": 116.84544372558594
 }
]
```

5,000,000, first run:

```json
[
 {
  "entities": 50,
  "alerts_per_entity": 100000,
  "profile": "uniform",
  "largest_entity_alerts": 100000,
  "smallest_entity_alerts": 100000,
  "alerts": 5000000,
  "rows": 21365529,
  "csv_mb": 2248.1162853240967,
  "generate_seconds": 9.92761029999383,
  "ingest": {
   "seconds": 51.46248249999917,
   "rows": 21365579,
   "dq_issues": 0,
   "batch_id": "BATCH-MULTI_CSE-0b0c984c3c75",
   "ok": true,
   "peak_mb": 6397.90234375,
   "wall_seconds": 53.270544099999825
  },
  "assess": {
   "seconds": 112.74985609999567,
   "findings": 150,
   "queue": 1500,
   "ok": true,
   "peak_mb": 4487.46875,
   "wall_seconds": 115.25782979999349
  },
  "pages": {
   "reload_seconds": 50.35733869999967,
   "pages": {
    "/portfolio": {
     "first": 55.33811059999425,
     "repeat_median": 0.08115040000120644
    },
    "/alerts": {
     "first": 0.7567553000044427,
     "repeat_median": 0.7533729999995558
    },
    "/entity/{entity}": {
     "first": 0.19257140000263462,
     "repeat_median": 0.0961682999986806
    },
    "/queue": {
     "first": 0.11256240000511752,
     "repeat_median": 0.08694680000189692
    },
    "/api/v1/entities": {
     "first": 0.16904219999560155,
     "repeat_median": 0.028354400004900526
    }
   },
   "table_loads": 1,
   "requests": 30,
   "ok": true,
   "peak_mb": 4517.90234375,
   "wall_seconds": 117.25089819999994
  },
  "parquet_mb": 281.0587902069092,
  "data_dir_mb": 285.7230567932129
 }
]
```

5,000,000, repeat run:

```json
[
 {
  "entities": 50,
  "alerts_per_entity": 100000,
  "profile": "uniform",
  "largest_entity_alerts": 100000,
  "smallest_entity_alerts": 100000,
  "alerts": 5000000,
  "rows": 21365529,
  "csv_mb": 2248.1162853240967,
  "generate_seconds": 10.03816260000167,
  "ingest": {
   "seconds": 50.477726500001154,
   "rows": 21365579,
   "dq_issues": 0,
   "batch_id": "BATCH-MULTI_CSE-0b0c984c3c75",
   "ok": true,
   "peak_mb": 6389.5078125,
   "wall_seconds": 52.34332799999538
  },
  "assess": {
   "seconds": 112.07707279999886,
   "findings": 150,
   "queue": 1500,
   "ok": true,
   "peak_mb": 4486.68359375,
   "wall_seconds": 114.51071109999612
  },
  "pages": {
   "reload_seconds": 50.102575299999444,
   "pages": {
    "/portfolio": {
     "first": 55.27276410000195,
     "repeat_median": 0.08311390000017127
    },
    "/alerts": {
     "first": 0.7812498999992386,
     "repeat_median": 0.7565197999938391
    },
    "/entity/{entity}": {
     "first": 0.1943645999999717,
     "repeat_median": 0.09553670000605052
    },
    "/queue": {
     "first": 0.1368640000000596,
     "repeat_median": 0.08905360000062501
    },
    "/api/v1/entities": {
     "first": 0.16618620000372175,
     "repeat_median": 0.027864299998327624
    }
   },
   "table_loads": 1,
   "requests": 30,
   "ok": true,
   "peak_mb": 4518.1953125,
   "wall_seconds": 116.70182719999866
  },
  "parquet_mb": 281.0587577819824,
  "data_dir_mb": 285.72302436828613
 }
]
```
