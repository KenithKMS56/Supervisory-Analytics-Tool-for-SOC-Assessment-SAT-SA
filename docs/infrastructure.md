# SAT-SA Infrastructure & Performance Sizing

> **Supervisory Notice:** *Indicators requiring supervisory review; not a compliance determination.*

This document gives hardware guidance and the **measured** performance of SAT-SA. Every figure
is printed with the command that produced it and the date it was recorded. Nothing is
extrapolated. All data is synthetic and uniform, so real submissions may behave differently.

**Measurement machine (all figures):** AMD Ryzen 5 7235HS (4 cores, 8 threads), 23.7 GB RAM,
Windows 11, DuckDB 1.5.5, Polars 1.44.2; Python 3.11.16 for Section 3, 3.13.2 for the earlier
run kept in Section 3.2.

---

## 1. Hardware Guidance

| Component | Minimum (lab / demo dataset) | Suggested for about 5,000,000 alerts |
|---|---|---|
| **Processor (CPU)** | 4 cores, x86_64 | 4 cores or more. The assessment runs DuckDB on **one thread** (`PRAGMA threads=1`, for reproducible aggregates), so extra cores do not shorten it. |
| **Memory (RAM)** | 8 GB | **16 GB suggested**: ingesting 5,000,000 alerts peaked at 5,425 MiB (5.7 GB) and assessing them at 3,751 MiB (Section 3), on top of the operating system. |
| **Storage (Disk)** | 10 GB SSD | SSD with room for the submitted CSVs (2.2 GB at 5,000,000 alerts) plus the Parquet store (0.2 GB) and reports. |
| **Network** | None needed; loopback (`127.0.0.1`) | None needed; loopback, or an isolated supervisory subnet with TLS (`docs/deployment_ops.md` Section 1.3) |
| **Operating system** | Windows 10/11 or a current Linux | Measured on Windows 11 only. CI is configured for Python 3.11 and 3.13 on Linux; it has not been run. |

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
takes about 2 minutes and ingesting them under 1 minute, far longer than this rate would suggest.

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
periods" and gives no figure; 5,000,000 alerts is this project's own target.

### 3.1 Final code of the quality pass (recorded 2026-10-02)

```bash
python scripts/benchmark_scale.py --configs 10x50000,50x100000 --workdir build/bench --out <file> --json <file>
```

| Entities x alerts | Alerts | Rows (all tables) | CSV | Parquet | Ingest | Ingest peak | Assess | Assess peak |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 10 x 50,000 | 500,000 | 2,171,868 | 226 MiB | 23 MiB | 6.5 s | 805 MiB | 10.6 s | 488 MiB |
| 50 x 100,000 | 5,000,000 | 21,365,139 | 2,248 MiB | 221 MiB | 46.6 s | 5,425 MiB | 124.0 s | 3,751 MiB |

What this shows:

- 5,000,000 alerts were ingested and assessed in under 3 minutes in total on a laptop.
- **Ingest** is about 10x faster than before the quality pass's columnar normalisation: in a
  same-session before/after comparison at 5,000,000 alerts it fell from 529.7 s to 54.2 s, and
  its peak from 13,339 to 5,716 MiB (`docs/benchmarks.md`, Phase 5 tables; the peak was lowered
  further afterwards).
- **Assessment time varies between runs** on this machine: before the anomaly scan was added,
  the same assessment code took 106 s to 191 s at 5,000,000 alerts on different runs
  (`docs/benchmarks.md`). The assessment now includes the scan (124 s, 3,751 MiB peak, in one
  run). Treat it as one measurement, not a typical value.
- The first web page after a run or an ingest reloads every table (17.4 s here at 5,000,000
  alerts, 22.7 to 27.0 s in earlier runs); repeat page loads stayed under 0.5 s.
- The data is uniform, clean synthetic data. Closure comments were pre-hashed, so free-text
  redaction cost is not included.

### 3.2 Earlier run (recorded 2026-09-30, before the ingest change)

`python scripts/benchmark_scale.py --configs 10x50000,25x100000,50x100000 --out docs/benchmarks.md`,
Python 3.13.2. Kept for the 25 x 100,000 size, which was not re-run.

| Entities x alerts | Alerts | Rows (all tables) | CSV | Parquet | Ingest | Ingest peak | Assess | Assess peak |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 10 x 50,000 | 500,000 | 2,171,868 | 226 MB | 23 MB | 65.9 s | 1,858 MB | 16.3 s | 460 MB |
| 25 x 100,000 | 2,500,000 | 10,681,566 | 1,124 MB | 111 MB | 309.7 s | 6,996 MB | 105.2 s | 1,728 MB |
| 50 x 100,000 | 5,000,000 | 21,365,139 | 2,248 MB | 221 MB | 603.0 s | 13,248 MB | 310.2 s | 3,314 MB |

("MB" in this table is MiB, as the script computes it.)

*Correction:* an earlier version of this section divided 5,000,000 by the throughput of a
5,650-alert run and promised 10.1 minutes, "comfortably" 6 to 8 on 8 cores. That was an
extrapolation. It also described "partition pruning" and "column projections"; the assessment
in fact loads every table into an in-memory DuckDB database (`docs/architecture.md` Section 3).

---

## 4. Storage

Measured sizes (Section 3.1, recorded 2026-10-02; the same in the 2026-09-30 run): the canonical
CSV submission for 5,000,000 alerts was 2,248 MiB and the Parquet store 221 MiB (about 10 to 1). The SQLite state
database (`data/satsa.db`) was not measured at that scale.

*Correction:* this section used to give unmeasured row and size estimates and called the tool
"ideal for self-contained air-gapped forensic laptops and low-profile appliances". Both were
removed.
