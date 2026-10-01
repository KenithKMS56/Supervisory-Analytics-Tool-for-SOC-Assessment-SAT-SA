# SAT-SA Scale Benchmarks

> **Supervisory Notice:** *Indicators requiring supervisory review; not a compliance determination.*

Measured on 2026-10-01 with `scripts/benchmark_scale.py`, on the machine described below.
Every figure is a measurement from the runs named here; nothing is extrapolated. Timings on
other hardware will differ. Sizes and memory are in MiB (1 MiB = 1,048,576 bytes); earlier
versions of this page labelled the same figures "MB".

Two runs, on the same machine and Python interpreter, one after the other:

- **After** (the current code): `python scripts/benchmark_scale.py --configs 10x50000,50x100000 --out <file> --json <file>`
- **Before** (the code as it was before the Phase 5 ingest change: commit `b371788` plus the
  evidence-ordering fix described in `docs/CHANGES_quality_pass.md`, M14): the same command, run from a copy of that source
  tree, so that its stage processes import the old ingest code.

The tables below are those runs' own output; the raw results of both are at the end.

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

## Ingest before and after the Phase 5 change

| Entities x alerts each | Alerts | Ingest before | Ingest after | Faster by | Ingest peak before | Ingest peak after | Assess before | Assess after |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 10 x 50,000 | 500,000 | 55.1 s | 6.5 s | 8.5x | 1,855 MiB | 1,155 MiB | 13.8 s | 14.8 s |
| 50 x 100,000 | 5,000,000 | 529.7 s | 54.2 s | 9.8x | 13,339 MiB | 5,716 MiB | 165.2 s | 153.8 s |

Against the targets set for this change:

- **Ingest at least 3x faster:** met. 9.8x at 5,000,000 alerts and 8.5x at 500,000.
- **Ingest peak under 6 GB at 5,000,000 alerts:** met, narrowly. 5,716 MiB is 5.99 GB
  (decimal). The peak comes while the largest file (10,000,000 workflow events, 938 MiB of
  CSV) is read; reading that file alone peaks at about 2.8 GiB, with every reader Polars
  offers (measured; a batched or streaming read was no lower).
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

## Results (after: the current code)

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

## Results (before: the code before the Phase 5 change)

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
