# SAT-SA Scale Benchmarks

> **Supervisory Notice:** *Indicators requiring supervisory review; not a compliance determination.*

**Current figures: Section "Final code (2026-10-02)" below.** The other sections are the
earlier runs that led to it, kept with their dates. Measured with `scripts/benchmark_scale.py`,
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
