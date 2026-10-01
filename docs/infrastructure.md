# SAT-SA Infrastructure & Performance Sizing

> **Supervisory Notice:** *Indicators requiring supervisory review; not a compliance determination.*

This document gives hardware guidance and the **measured** performance of SAT-SA. Every figure
is printed with the command that produced it and the date it was recorded. Nothing is
extrapolated. All data is synthetic and uniform, so real submissions may behave differently.

**Measurement machine (all figures):** AMD Ryzen 5 7235HS (4 cores, 8 threads), 23.7 GB RAM,
Windows 11, Python 3.13.2, DuckDB 1.5.5, Polars 1.44.2.

---

## 1. Hardware Guidance

| Component | Minimum (lab / demo dataset) | Suggested for about 5,000,000 alerts |
|---|---|---|
| **Processor (CPU)** | 4 cores, x86_64 | 4 cores or more. The assessment runs DuckDB on **one thread** (`PRAGMA threads=1`, for reproducible aggregates), so extra cores do not shorten it. |
| **Memory (RAM)** | 8 GB | **16 GB at least, 32 GB suggested**: ingesting 5,000,000 alerts peaked at 13.2 GB (Section 3). |
| **Storage (Disk)** | 10 GB SSD | SSD with room for the submitted CSVs (2.2 GB at 5,000,000 alerts) plus the Parquet store (0.2 GB) and reports. |
| **Network** | None needed; loopback (`127.0.0.1`) | None needed; loopback, or an isolated supervisory subnet with TLS (`docs/deployment_ops.md` Section 1.3) |
| **Operating system** | Windows 10/11 or a current Linux | Measured on Windows 11 only. CI is configured for Python 3.11 and 3.13 on Linux; its results were not checked in this pass. |

The minimum column is guidance, not a measurement; the suggested column follows from the
measurements in Section 3.

---

## 2. Small Dataset: `satsa benchmark`

Run on 2026-10-01 against the default demo dataset (`satsa generate-data`, seed 42):

```bash
uv run satsa benchmark
```

### 2.1 One in-memory aggregation query (not an assessment time)

The command builds a generated alert table in memory and times **one** aggregation query
(median MTTR and MTTA, FP rate and SOAR share per entity and severity) on a DuckDB connection
pinned to one thread, as SAT-SA's own store is. It does not read Parquet, run the rules, score
or persist anything.

| Alerts in the table | Query time | Rows per second |
|---:|---:|---:|
| 50,000 | 0.0363 s | 1,378,234 |
| 200,000 | 0.0302 s | 6,626,774 |
| 1,000,000 | 0.1321 s | 7,570,338 |

A second run the same day, on a clean copy of the repository, gave 7,108,412 rows/s at
1,000,000 rows (0.1407 s) and 2.174 s for the assessment in Section 2.2: expect variation of
several per cent between runs on a laptop.

**Scan speed is not end-to-end time.** Section 3 shows that a full assessment of 5,000,000 alerts
takes about 5 minutes and ingesting them about 10 minutes, far longer than this rate would
suggest.

*Correction (quality pass):* this table used to show 10,623,549 rows/second at 1,000,000 rows.
That figure was measured with DuckDB's default multi-threading, which the assessment does not
use, and the README presented it as letting multi-gigabyte submissions be "evaluated in
seconds". The claim was removed and the benchmark now runs on one thread.

### 2.2 Assessment of the demo dataset

Same command: `AssessmentRunner.run_assessment` (all 20 rules for 10 entities, scoring, review
queue, persistence) on the 16,253-alert demo dataset took **2.038 s** (7,975.5 alerts/s).

*Correction (quality pass):* this section used to report a 0.686 s run on an older 5,650-alert
dataset.

---

## 3. Scale: Measured up to 5,000,000 Alerts

The problem statement asks for "analysis of large datasets spanning multiple entities and time
periods" and gives no figure; 5,000,000 alerts is this project's own target. Recorded on
**2026-09-30** with:

```bash
python scripts/benchmark_scale.py --configs 10x50000,25x100000,50x100000 --out docs/benchmarks.md
```

| Entities x alerts | Alerts | Rows (all tables) | CSV | Parquet | Ingest | Ingest peak | Assess | Assess peak |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 10 x 50,000 | 500,000 | 2,171,868 | 226 MB | 23 MB | 65.9 s | 1,858 MB | 16.3 s | 460 MB |
| 25 x 100,000 | 2,500,000 | 10,681,566 | 1,124 MB | 111 MB | 309.7 s | 6,996 MB | 105.2 s | 1,728 MB |
| 50 x 100,000 | 5,000,000 | 21,365,139 | 2,248 MB | 221 MB | 603.0 s | 13,248 MB | 310.2 s | 3,314 MB |

What this shows:

- 5,000,000 alerts were ingested and assessed in about 15 minutes in total on a laptop.
- **Assessment time grows faster than volume**: 16 s, 105 s, 310 s for 1x, 5x, 10x the alerts.
- **Ingest memory is the limit**: 13.2 GB peak at 5,000,000 alerts.
- The first web page after a run or an ingest reloads every table (27 s at 5,000,000 alerts);
  repeat page loads stayed under 0.7 s (`docs/benchmarks.md`, page-load table).
- The data is uniform, clean synthetic data. Closure comments were pre-hashed, so free-text
  redaction cost is not included.

*Correction:* an earlier version of this section divided 5,000,000 by the throughput of a
5,650-alert run and promised 10.1 minutes, "comfortably" 6 to 8 on 8 cores. That was an
extrapolation. It also described "partition pruning" and "column projections"; the assessment
in fact loads every table into an in-memory DuckDB database (`docs/architecture.md` Section 3).

These figures are due to be re-measured later in this quality pass, after the ingest changes;
`docs/benchmarks.md` will then hold before-and-after tables.

---

## 4. Storage

Measured sizes (same run as Section 3, recorded 2026-09-30): the canonical CSV submission for
5,000,000 alerts was 2,248 MB and the Parquet store 221 MB (about 10 to 1). The SQLite state
database (`data/satsa.db`) was not measured at that scale.

*Correction:* this section used to give unmeasured row and size estimates and called the tool
"ideal for self-contained air-gapped forensic laptops and low-profile appliances". Both were
removed.
