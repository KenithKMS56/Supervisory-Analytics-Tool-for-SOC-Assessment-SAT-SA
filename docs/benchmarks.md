# SAT-SA Scale Benchmarks

> **Supervisory Notice:** *Indicators requiring supervisory review; not a compliance determination.*

Measured on 2026-09-30 with `scripts/benchmark_scale.py`. Every figure below is a
measurement from that run on the machine described here; nothing is extrapolated. Timings on
other hardware will differ.

```
python scripts/benchmark_scale.py --configs 10x50000,25x100000,50x100000 --out docs/benchmarks.md
```

## Machine

| | |
|---|---|
| CPU | AMD Ryzen 5 7235HS |
| Logical CPUs | 8 |
| RAM | 23.7 GB |
| OS | Windows 11 (10.0.26200) |
| Python | 3.13.2 |
| DuckDB | 1.5.5 |
| Polars | 1.44.2 |

## What is measured

- **Data:** a generated canonical submission: the 14 tables of `satsa generate-data`, with
  2 workflow events and 1 closure per alert, a case and an escalation for 5% of alerts, and
  40 assets per entity reporting daily log volumes for 181 days. It is clean, uniform data built
  for volume; it says nothing about detection quality. Closure comments are submitted
  pre-hashed (as the generator does), so free-text redaction is not part of the ingest time.
- **Ingest:** `IngestionPipeline.ingest_directory` on the CSV directory (read, normalise,
  pseudonymise, data-quality checks, Parquet write, manifest, audit entry).
- **Assess:** `AssessmentRunner.run_assessment` (all 20 rules for every entity, scoring, review
  queue, persistence).
- **Pages:** the SAT-SA web app through an in-process client, signed in as the analyst. Each
  page is requested 6 times: the first request, and the median of the next 5.
- **Peak memory:** the highest resident memory of the process that ran the stage (each stage
  runs in its own process).

## Results

| Entities x alerts each | Alerts | Rows (all tables) | CSV | Parquet | Ingest | Ingest peak | Assess | Assess peak | Findings |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 10 x 50,000 | 500,000 | 2,171,868 | 226 MB | 23 MB | 65.9 s | 1,858 MB | 16.3 s | 460 MB | 30 |
| 25 x 100,000 | 2,500,000 | 10,681,566 | 1,124 MB | 111 MB | 309.7 s | 6,996 MB | 105.2 s | 1,728 MB | 75 |
| 50 x 100,000 | 5,000,000 | 21,365,139 | 2,248 MB | 221 MB | 603.0 s | 13,248 MB | 310.2 s | 3,314 MB | 150 |

### Page loads

"Reload" is what every request paid before the analytics cache: building a store and
re-reading every Parquet table. It is measured directly here (`DuckDBStore.load_all_tables`)
and is now paid once, on the first analytics request after a run completes or the data changes.

| Entities x alerts each | Reload (old per-request cost) | Page | First request | Repeat (median of 5) | Pages peak |
|---|---:|---|---:|---:|---:|
| 10 x 50,000 | 2.03 s | `/portfolio` | 2,921 ms | 60 ms | 460 MB |
|  |  | `/alerts` | 156 ms | 133 ms |  |
|  |  | `/entity/{entity}` | 149 ms | 107 ms |  |
|  |  | `/queue` | 58 ms | 33 ms |  |
|  |  | `/api/v1/entities` | 44 ms | 40 ms |  |
| | | *30 requests caused 1 table load(s)* | | | |
| 25 x 100,000 | 12.21 s | `/portfolio` | 13,148 ms | 92 ms | 1,704 MB |
|  |  | `/alerts` | 469 ms | 326 ms |  |
|  |  | `/entity/{entity}` | 112 ms | 95 ms |  |
|  |  | `/queue` | 38 ms | 24 ms |  |
|  |  | `/api/v1/entities` | 46 ms | 47 ms |  |
| | | *30 requests caused 1 table load(s)* | | | |
| 50 x 100,000 | 24.49 s | `/portfolio` | 27,021 ms | 95 ms | 3,283 MB |
|  |  | `/alerts` | 644 ms | 673 ms |  |
|  |  | `/entity/{entity}` | 235 ms | 208 ms |  |
|  |  | `/queue` | 63 ms | 39 ms |  |
|  |  | `/api/v1/entities` | 127 ms | 118 ms |  |
| | | *30 requests caused 1 table load(s)* | | | |

## Raw results

```json
[
 {
  "entities": 10,
  "alerts_per_entity": 50000,
  "alerts": 500000,
  "rows": 2171868,
  "csv_mb": 226.37182521820068,
  "generate_seconds": 1.6285036000008404,
  "ingest": {
   "seconds": 65.87302049999926,
   "rows": 2171878,
   "dq_issues": 0,
   "ok": true,
   "peak_mb": 1857.66796875,
   "wall_seconds": 68.03292639999927
  },
  "assess": {
   "seconds": 16.30582510000022,
   "findings": 30,
   "queue": 300,
   "ok": true,
   "peak_mb": 459.76953125,
   "wall_seconds": 17.84258729999965
  },
  "pages": {
   "reload_seconds": 2.0321509999994305,
   "pages": {
    "/portfolio": {
     "first": 2.921289000001707,
     "repeat_median": 0.06022269999994023
    },
    "/alerts": {
     "first": 0.1564635000013368,
     "repeat_median": 0.13282600000093225
    },
    "/entity/{entity}": {
     "first": 0.1489982000002783,
     "repeat_median": 0.1073184000015317
    },
    "/queue": {
     "first": 0.057925900000554975,
     "repeat_median": 0.03311370000119496
    },
    "/api/v1/entities": {
     "first": 0.0442719999991823,
     "repeat_median": 0.0396630000013829
    }
   },
   "table_loads": 1,
   "requests": 30,
   "ok": true,
   "peak_mb": 459.96875,
   "wall_seconds": 10.011583199999222
  },
  "parquet_mb": 22.588565826416016
 },
 {
  "entities": 25,
  "alerts_per_entity": 100000,
  "alerts": 2500000,
  "rows": 10681566,
  "csv_mb": 1123.9759664535522,
  "generate_seconds": 7.252997300000061,
  "ingest": {
   "seconds": 309.69847290000143,
   "rows": 10681591,
   "dq_issues": 0,
   "ok": true,
   "peak_mb": 6995.75,
   "wall_seconds": 312.4359490000006
  },
  "assess": {
   "seconds": 105.1821003999994,
   "findings": 75,
   "queue": 750,
   "ok": true,
   "peak_mb": 1727.5859375,
   "wall_seconds": 107.10313690000112
  },
  "pages": {
   "reload_seconds": 12.209262300000773,
   "pages": {
    "/portfolio": {
     "first": 13.148193799999717,
     "repeat_median": 0.09173509999891394
    },
    "/alerts": {
     "first": 0.4685693999999785,
     "repeat_median": 0.3259929000014381
    },
    "/entity/{entity}": {
     "first": 0.11165020000044024,
     "repeat_median": 0.0951731999994081
    },
    "/queue": {
     "first": 0.03833909999957541,
     "repeat_median": 0.024407000000792323
    },
    "/api/v1/entities": {
     "first": 0.045501799999328796,
     "repeat_median": 0.04695279999941704
    }
   },
   "table_loads": 1,
   "requests": 30,
   "ok": true,
   "peak_mb": 1704.328125,
   "wall_seconds": 32.57493480000085
  },
  "parquet_mb": 110.62328243255615
 },
 {
  "entities": 50,
  "alerts_per_entity": 100000,
  "alerts": 5000000,
  "rows": 21365139,
  "csv_mb": 2248.088671684265,
  "generate_seconds": 15.663228999999774,
  "ingest": {
   "seconds": 603.0352867000001,
   "rows": 21365189,
   "dq_issues": 0,
   "ok": true,
   "peak_mb": 13247.53515625,
   "wall_seconds": 607.5211301999989
  },
  "assess": {
   "seconds": 310.24240199999986,
   "findings": 150,
   "queue": 1500,
   "ok": true,
   "peak_mb": 3313.859375,
   "wall_seconds": 313.10956220000116
  },
  "pages": {
   "reload_seconds": 24.490863900000477,
   "pages": {
    "/portfolio": {
     "first": 27.020739000001413,
     "repeat_median": 0.09460720000060974
    },
    "/alerts": {
     "first": 0.6435961999995925,
     "repeat_median": 0.6734698000000208
    },
    "/entity/{entity}": {
     "first": 0.23495309999998426,
     "repeat_median": 0.2077781000007235
    },
    "/queue": {
     "first": 0.06253490000017337,
     "repeat_median": 0.03917339999861724
    },
    "/api/v1/entities": {
     "first": 0.12723790000018198,
     "repeat_median": 0.11824669999987236
    }
   },
   "table_loads": 1,
   "requests": 30,
   "ok": true,
   "peak_mb": 3283.02734375,
   "wall_seconds": 63.11866369999916
  },
  "parquet_mb": 221.36354637145996
 }
]
```
