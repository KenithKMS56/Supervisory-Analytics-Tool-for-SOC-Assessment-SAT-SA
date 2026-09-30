# SAT-SA Hard-Set Validation Report

> **Supervisory Notice:** *Indicators requiring supervisory review; not a compliance determination.*

Generated 2026-09-30 by `python scripts/validate_hard.py --out docs/validation_hard_report.md --json C:/Users/SANJAY~1/AppData/Local/Temp/claude/c--Users-SANJAYRAMNATHAN-Downloads-Supervisory-Analytics-Tool-for-SOC-Assessment-SAT-SA/23b52793-75a1-42f0-9255-ad71c55e82fc/scratchpad/hard_runs.json`. Every figure is counted from the runs
listed at the end. **All data is synthetic**: these figures show how the rules behave under
other random seeds, lower volumes and near-threshold cases. They are not real-world accuracy;
see `docs/validation_summary.md`.

The primary (easy) set is seed 42 at 1,500 alerts per entity and is reported separately in
`docs/validation_report.md`; no run here uses that seed.

## 1. Portfolio generator under other seeds and volumes

### 1,500 base alerts per entity (8 seeds)

- Runs: 8 | injected defects: 168
- Recall: 99.4% (167/168; 95% CI 96.7%-99.9%)
- Precision: 98.8% (167/169; 95% CI 95.8%-99.7%)
- Clean entities with at least one finding: 0.0% (0/24; 95% CI 0.0%-13.8%)

| Rule | Injected | Detected | Missed | False positives | Recall (95% CI) | Precision (95% CI) |
|---|---:|---:|---:|---:|---|---|
| `EG01` | 8 | 8 | 0 | 0 | 100.0% (8/8; 95% CI 67.6%-100.0%) | 100.0% (8/8; 95% CI 67.6%-100.0%) |
| `EG03` | 8 | 8 | 0 | 0 | 100.0% (8/8; 95% CI 67.6%-100.0%) | 100.0% (8/8; 95% CI 67.6%-100.0%) |
| `EG04` | 8 | 8 | 0 | 0 | 100.0% (8/8; 95% CI 67.6%-100.0%) | 100.0% (8/8; 95% CI 67.6%-100.0%) |
| `EG05` | 8 | 8 | 0 | 0 | 100.0% (8/8; 95% CI 67.6%-100.0%) | 100.0% (8/8; 95% CI 67.6%-100.0%) |
| `EG06` | 8 | 8 | 0 | 0 | 100.0% (8/8; 95% CI 67.6%-100.0%) | 100.0% (8/8; 95% CI 67.6%-100.0%) |
| `EG07` | 8 | 8 | 0 | 0 | 100.0% (8/8; 95% CI 67.6%-100.0%) | 100.0% (8/8; 95% CI 67.6%-100.0%) |
| `EG08` | 8 | 8 | 0 | 0 | 100.0% (8/8; 95% CI 67.6%-100.0%) | 100.0% (8/8; 95% CI 67.6%-100.0%) |
| `EG09` | 8 | 7 | 1 | 0 | 87.5% (7/8; 95% CI 52.9%-97.8%) | 100.0% (7/7; 95% CI 64.6%-100.0%) |
| `EG10` | 8 | 8 | 0 | 2 | 100.0% (8/8; 95% CI 67.6%-100.0%) | 80.0% (8/10; 95% CI 49.0%-94.3%) |
| `EG11` | 8 | 8 | 0 | 0 | 100.0% (8/8; 95% CI 67.6%-100.0%) | 100.0% (8/8; 95% CI 67.6%-100.0%) |
| `EG12` | 8 | 8 | 0 | 0 | 100.0% (8/8; 95% CI 67.6%-100.0%) | 100.0% (8/8; 95% CI 67.6%-100.0%) |
| `NS01` | 24 | 24 | 0 | 0 | 100.0% (24/24; 95% CI 86.2%-100.0%) | 100.0% (24/24; 95% CI 86.2%-100.0%) |
| `NS02` | 8 | 8 | 0 | 0 | 100.0% (8/8; 95% CI 67.6%-100.0%) | 100.0% (8/8; 95% CI 67.6%-100.0%) |
| `NS03` | 8 | 8 | 0 | 0 | 100.0% (8/8; 95% CI 67.6%-100.0%) | 100.0% (8/8; 95% CI 67.6%-100.0%) |
| `NS04` | 8 | 8 | 0 | 0 | 100.0% (8/8; 95% CI 67.6%-100.0%) | 100.0% (8/8; 95% CI 67.6%-100.0%) |
| `NS05` | 8 | 8 | 0 | 0 | 100.0% (8/8; 95% CI 67.6%-100.0%) | 100.0% (8/8; 95% CI 67.6%-100.0%) |
| `NS06` | 8 | 8 | 0 | 0 | 100.0% (8/8; 95% CI 67.6%-100.0%) | 100.0% (8/8; 95% CI 67.6%-100.0%) |
| `NS07` | 8 | 8 | 0 | 0 | 100.0% (8/8; 95% CI 67.6%-100.0%) | 100.0% (8/8; 95% CI 67.6%-100.0%) |
| `NS08` | 8 | 8 | 0 | 0 | 100.0% (8/8; 95% CI 67.6%-100.0%) | 100.0% (8/8; 95% CI 67.6%-100.0%) |

Missed (entity:rule @ seed): CSE-05:EG09 @ 808

False positives (entity:rule @ seed): CSE-07:EG10 @ 505, CSE-07:EG10 @ 707

### 600 base alerts per entity (8 seeds)

- Runs: 8 | injected defects: 168
- Recall: 99.4% (167/168; 95% CI 96.7%-99.9%)
- Precision: 97.7% (167/171; 95% CI 94.1%-99.1%)
- Clean entities with at least one finding: 0.0% (0/24; 95% CI 0.0%-13.8%)

| Rule | Injected | Detected | Missed | False positives | Recall (95% CI) | Precision (95% CI) |
|---|---:|---:|---:|---:|---|---|
| `EG01` | 8 | 8 | 0 | 0 | 100.0% (8/8; 95% CI 67.6%-100.0%) | 100.0% (8/8; 95% CI 67.6%-100.0%) |
| `EG03` | 8 | 7 | 1 | 0 | 87.5% (7/8; 95% CI 52.9%-97.8%) | 100.0% (7/7; 95% CI 64.6%-100.0%) |
| `EG04` | 8 | 8 | 0 | 0 | 100.0% (8/8; 95% CI 67.6%-100.0%) | 100.0% (8/8; 95% CI 67.6%-100.0%) |
| `EG05` | 8 | 8 | 0 | 0 | 100.0% (8/8; 95% CI 67.6%-100.0%) | 100.0% (8/8; 95% CI 67.6%-100.0%) |
| `EG06` | 8 | 8 | 0 | 0 | 100.0% (8/8; 95% CI 67.6%-100.0%) | 100.0% (8/8; 95% CI 67.6%-100.0%) |
| `EG07` | 8 | 8 | 0 | 0 | 100.0% (8/8; 95% CI 67.6%-100.0%) | 100.0% (8/8; 95% CI 67.6%-100.0%) |
| `EG08` | 8 | 8 | 0 | 0 | 100.0% (8/8; 95% CI 67.6%-100.0%) | 100.0% (8/8; 95% CI 67.6%-100.0%) |
| `EG09` | 8 | 8 | 0 | 0 | 100.0% (8/8; 95% CI 67.6%-100.0%) | 100.0% (8/8; 95% CI 67.6%-100.0%) |
| `EG10` | 8 | 8 | 0 | 4 | 100.0% (8/8; 95% CI 67.6%-100.0%) | 66.7% (8/12; 95% CI 39.1%-86.2%) |
| `EG11` | 8 | 8 | 0 | 0 | 100.0% (8/8; 95% CI 67.6%-100.0%) | 100.0% (8/8; 95% CI 67.6%-100.0%) |
| `EG12` | 8 | 8 | 0 | 0 | 100.0% (8/8; 95% CI 67.6%-100.0%) | 100.0% (8/8; 95% CI 67.6%-100.0%) |
| `NS01` | 24 | 24 | 0 | 0 | 100.0% (24/24; 95% CI 86.2%-100.0%) | 100.0% (24/24; 95% CI 86.2%-100.0%) |
| `NS02` | 8 | 8 | 0 | 0 | 100.0% (8/8; 95% CI 67.6%-100.0%) | 100.0% (8/8; 95% CI 67.6%-100.0%) |
| `NS03` | 8 | 8 | 0 | 0 | 100.0% (8/8; 95% CI 67.6%-100.0%) | 100.0% (8/8; 95% CI 67.6%-100.0%) |
| `NS04` | 8 | 8 | 0 | 0 | 100.0% (8/8; 95% CI 67.6%-100.0%) | 100.0% (8/8; 95% CI 67.6%-100.0%) |
| `NS05` | 8 | 8 | 0 | 0 | 100.0% (8/8; 95% CI 67.6%-100.0%) | 100.0% (8/8; 95% CI 67.6%-100.0%) |
| `NS06` | 8 | 8 | 0 | 0 | 100.0% (8/8; 95% CI 67.6%-100.0%) | 100.0% (8/8; 95% CI 67.6%-100.0%) |
| `NS07` | 8 | 8 | 0 | 0 | 100.0% (8/8; 95% CI 67.6%-100.0%) | 100.0% (8/8; 95% CI 67.6%-100.0%) |
| `NS08` | 8 | 8 | 0 | 0 | 100.0% (8/8; 95% CI 67.6%-100.0%) | 100.0% (8/8; 95% CI 67.6%-100.0%) |

Missed (entity:rule @ seed): CSE-03:EG03 @ 808

False positives (entity:rule @ seed): CSE-07:EG10 @ 101, CSE-07:EG10 @ 202, CSE-07:EG10 @ 505, CSE-07:EG10 @ 808

### 300 base alerts per entity (8 seeds)

- Runs: 8 | injected defects: 168
- Recall: 100.0% (168/168; 95% CI 97.8%-100.0%)
- Precision: 97.7% (168/172; 95% CI 94.2%-99.1%)
- Clean entities with at least one finding: 0.0% (0/24; 95% CI 0.0%-13.8%)

| Rule | Injected | Detected | Missed | False positives | Recall (95% CI) | Precision (95% CI) |
|---|---:|---:|---:|---:|---|---|
| `EG01` | 8 | 8 | 0 | 0 | 100.0% (8/8; 95% CI 67.6%-100.0%) | 100.0% (8/8; 95% CI 67.6%-100.0%) |
| `EG03` | 8 | 8 | 0 | 0 | 100.0% (8/8; 95% CI 67.6%-100.0%) | 100.0% (8/8; 95% CI 67.6%-100.0%) |
| `EG04` | 8 | 8 | 0 | 0 | 100.0% (8/8; 95% CI 67.6%-100.0%) | 100.0% (8/8; 95% CI 67.6%-100.0%) |
| `EG05` | 8 | 8 | 0 | 0 | 100.0% (8/8; 95% CI 67.6%-100.0%) | 100.0% (8/8; 95% CI 67.6%-100.0%) |
| `EG06` | 8 | 8 | 0 | 0 | 100.0% (8/8; 95% CI 67.6%-100.0%) | 100.0% (8/8; 95% CI 67.6%-100.0%) |
| `EG07` | 8 | 8 | 0 | 0 | 100.0% (8/8; 95% CI 67.6%-100.0%) | 100.0% (8/8; 95% CI 67.6%-100.0%) |
| `EG08` | 8 | 8 | 0 | 0 | 100.0% (8/8; 95% CI 67.6%-100.0%) | 100.0% (8/8; 95% CI 67.6%-100.0%) |
| `EG09` | 8 | 8 | 0 | 0 | 100.0% (8/8; 95% CI 67.6%-100.0%) | 100.0% (8/8; 95% CI 67.6%-100.0%) |
| `EG10` | 8 | 8 | 0 | 4 | 100.0% (8/8; 95% CI 67.6%-100.0%) | 66.7% (8/12; 95% CI 39.1%-86.2%) |
| `EG11` | 8 | 8 | 0 | 0 | 100.0% (8/8; 95% CI 67.6%-100.0%) | 100.0% (8/8; 95% CI 67.6%-100.0%) |
| `EG12` | 8 | 8 | 0 | 0 | 100.0% (8/8; 95% CI 67.6%-100.0%) | 100.0% (8/8; 95% CI 67.6%-100.0%) |
| `NS01` | 24 | 24 | 0 | 0 | 100.0% (24/24; 95% CI 86.2%-100.0%) | 100.0% (24/24; 95% CI 86.2%-100.0%) |
| `NS02` | 8 | 8 | 0 | 0 | 100.0% (8/8; 95% CI 67.6%-100.0%) | 100.0% (8/8; 95% CI 67.6%-100.0%) |
| `NS03` | 8 | 8 | 0 | 0 | 100.0% (8/8; 95% CI 67.6%-100.0%) | 100.0% (8/8; 95% CI 67.6%-100.0%) |
| `NS04` | 8 | 8 | 0 | 0 | 100.0% (8/8; 95% CI 67.6%-100.0%) | 100.0% (8/8; 95% CI 67.6%-100.0%) |
| `NS05` | 8 | 8 | 0 | 0 | 100.0% (8/8; 95% CI 67.6%-100.0%) | 100.0% (8/8; 95% CI 67.6%-100.0%) |
| `NS06` | 8 | 8 | 0 | 0 | 100.0% (8/8; 95% CI 67.6%-100.0%) | 100.0% (8/8; 95% CI 67.6%-100.0%) |
| `NS07` | 8 | 8 | 0 | 0 | 100.0% (8/8; 95% CI 67.6%-100.0%) | 100.0% (8/8; 95% CI 67.6%-100.0%) |
| `NS08` | 8 | 8 | 0 | 0 | 100.0% (8/8; 95% CI 67.6%-100.0%) | 100.0% (8/8; 95% CI 67.6%-100.0%) |

False positives (entity:rule @ seed): CSE-07:EG10 @ 202, CSE-07:EG10 @ 303, CSE-07:EG10 @ 606, CSE-07:EG10 @ 707

## 2. Stress scenario under many seeds

### Borderline EG04, ambiguous EG02/EG04, noisy clean entity

- Runs: 20 | injected defects: 60
- Recall: 100.0% (60/60; 95% CI 94.0%-100.0%)
- Precision: 93.8% (60/64; 95% CI 85.0%-97.5%)
- Clean entities with at least one finding: 20.0% (4/20; 95% CI 8.1%-41.6%)

| Rule | Injected | Detected | Missed | False positives | Recall (95% CI) | Precision (95% CI) |
|---|---:|---:|---:|---:|---|---|
| `EG02` | 20 | 20 | 0 | 0 | 100.0% (20/20; 95% CI 83.9%-100.0%) | 100.0% (20/20; 95% CI 83.9%-100.0%) |
| `EG04` | 40 | 40 | 0 | 0 | 100.0% (40/40; 95% CI 91.2%-100.0%) | 100.0% (40/40; 95% CI 91.2%-100.0%) |
| `EG05` | 0 | 0 | 0 | 4 | n/a | 0.0% (0/4; 95% CI 0.0%-49.0%) |

False positives (entity:rule @ seed): STRESS-03:EG05 @ 3, STRESS-03:EG05 @ 10, STRESS-03:EG05 @ 14, STRESS-03:EG05 @ 15

## 3. Fragile thresholds

Each tunable threshold was moved by -20% and +20%, one at a time, in every run. A row below
is a threshold whose move changed what its rule detected in at least one run: the injected
defect or clean entity sits within 20% of it.

### Portfolio runs

| Rule | Threshold | Moved by | Runs where the outcome changed | Detections lost | New false positives |
|---|---|---|---:|---:|---:|
| `EG05` | `min_unaddressed_pairs` | +20% | 24 of 24 | 24 | 0 |
| `EG07` | `min_closures_per_analyst_hour` | +20% | 24 of 24 | 24 | 0 |
| `NS05` | `max_dormant_share` | +20% | 24 of 24 | 24 | 0 |
| `NS08` | `review_period_months` | -20% | 24 of 24 | 24 | 0 |
| `EG05` | `min_unaddressed_pairs` | -20% | 5 of 24 | 0 | 8 |
| `EG09` | `min_stale_cases` | +20% | 4 of 24 | 4 | 0 |
| `EG05` | `min_repeat_count` | -20% | 1 of 24 | 0 | 1 |
| `EG09` | `min_stale_cases` | -20% | 1 of 24 | 0 | 0 |
| `EG12` | `min_skipped_cases` | +20% | 1 of 24 | 1 | 0 |
| `NS03` | `max_robust_z` | -20% | 1 of 24 | 0 | 1 |

### Stress runs

| Rule | Threshold | Moved by | Runs where the outcome changed | Detections lost | New false positives |
|---|---|---|---:|---:|---:|
| `EG04` | `max_comment_hash_share` | +20% | 20 of 20 | 40 | 0 |
| `EG04` | `min_hash_group_size` | +20% | 20 of 20 | 20 | 0 |
| `EG05` | `min_unaddressed_pairs` | -20% | 16 of 20 | 0 | 16 |
| `EG05` | `min_repeat_count` | +20% | 4 of 20 | 0 | 0 |
| `EG05` | `min_unaddressed_pairs` | +20% | 4 of 20 | 0 | 0 |

## 4. Runs

| Scenario | Seed | Base alerts per entity | Injected | Detected | Missed | False positives | Seconds |
|---|---:|---:|---:|---:|---:|---:|---:|
| portfolio | 101 | 1500 | 21 | 21 | 0 | 0 | 30.6 |
| portfolio | 202 | 1500 | 21 | 21 | 0 | 0 | 28.9 |
| portfolio | 303 | 1500 | 21 | 21 | 0 | 0 | 25.9 |
| portfolio | 404 | 1500 | 21 | 21 | 0 | 0 | 21.7 |
| portfolio | 505 | 1500 | 21 | 21 | 0 | 1 | 19.6 |
| portfolio | 606 | 1500 | 21 | 21 | 0 | 0 | 19.8 |
| portfolio | 707 | 1500 | 21 | 21 | 0 | 1 | 20.2 |
| portfolio | 808 | 1500 | 21 | 20 | 1 | 0 | 28.5 |
| portfolio | 101 | 600 | 21 | 21 | 0 | 1 | 25.4 |
| portfolio | 202 | 600 | 21 | 21 | 0 | 1 | 26.7 |
| portfolio | 303 | 600 | 21 | 21 | 0 | 0 | 27.1 |
| portfolio | 404 | 600 | 21 | 21 | 0 | 0 | 27.6 |
| portfolio | 505 | 600 | 21 | 21 | 0 | 1 | 27.8 |
| portfolio | 606 | 600 | 21 | 21 | 0 | 0 | 29.0 |
| portfolio | 707 | 600 | 21 | 21 | 0 | 0 | 30.2 |
| portfolio | 808 | 600 | 21 | 20 | 1 | 1 | 28.9 |
| portfolio | 101 | 300 | 21 | 21 | 0 | 0 | 27.1 |
| portfolio | 202 | 300 | 21 | 21 | 0 | 1 | 26.6 |
| portfolio | 303 | 300 | 21 | 21 | 0 | 1 | 27.1 |
| portfolio | 404 | 300 | 21 | 21 | 0 | 0 | 26.5 |
| portfolio | 505 | 300 | 21 | 21 | 0 | 0 | 16.9 |
| portfolio | 606 | 300 | 21 | 21 | 0 | 1 | 21.7 |
| portfolio | 707 | 300 | 21 | 21 | 0 | 1 | 26.2 |
| portfolio | 808 | 300 | 21 | 21 | 0 | 0 | 24.7 |
| stress | 1 |  | 3 | 3 | 0 | 0 | 5.4 |
| stress | 2 |  | 3 | 3 | 0 | 0 | 5.1 |
| stress | 3 |  | 3 | 3 | 0 | 1 | 5.8 |
| stress | 4 |  | 3 | 3 | 0 | 0 | 5.6 |
| stress | 5 |  | 3 | 3 | 0 | 0 | 5.6 |
| stress | 6 |  | 3 | 3 | 0 | 0 | 5.1 |
| stress | 7 |  | 3 | 3 | 0 | 0 | 5.0 |
| stress | 8 |  | 3 | 3 | 0 | 0 | 4.9 |
| stress | 9 |  | 3 | 3 | 0 | 0 | 5.5 |
| stress | 10 |  | 3 | 3 | 0 | 1 | 5.6 |
| stress | 11 |  | 3 | 3 | 0 | 0 | 5.2 |
| stress | 12 |  | 3 | 3 | 0 | 0 | 5.0 |
| stress | 13 |  | 3 | 3 | 0 | 0 | 5.6 |
| stress | 14 |  | 3 | 3 | 0 | 1 | 5.5 |
| stress | 15 |  | 3 | 3 | 0 | 1 | 5.3 |
| stress | 16 |  | 3 | 3 | 0 | 0 | 4.7 |
| stress | 17 |  | 3 | 3 | 0 | 0 | 4.6 |
| stress | 18 |  | 3 | 3 | 0 | 0 | 5.8 |
| stress | 19 |  | 3 | 3 | 0 | 0 | 5.8 |
| stress | 20 |  | 3 | 3 | 0 | 0 | 5.6 |
