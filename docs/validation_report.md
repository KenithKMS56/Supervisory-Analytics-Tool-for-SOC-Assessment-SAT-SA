# SAT-SA Detector-Implementation Correctness Report

> **Supervisory Notice:** *Indicators requiring supervisory review; not a compliance determination.*

**Run ID:** `RUN-20260930083424990902-51a9c31c` | **Validation Engine:** Fully Deterministic (No AI/ML)

## 1. Executive Summary & Verification Criteria
This report documents whether each detection rule's code correctly implements its own specified logic, measured against a synthetic ground-truth dataset across 10 Critical Sector Entities (CSEs) whose injected defects are deliberately built to clearly exceed each rule's threshold. High scores here demonstrate implementation correctness on an unambiguous dataset, not real-world detection accuracy -- see docs/validation.md Section 0 for the harder, more realistic 'stress scenario' (`satsa validate-stress`) and Section 5 for the Shadow-Pilot mode against real historical findings.

Precision counts every finding whose (entity, rule) pair is not an injected defect as a false positive, on any entity and for any rule, with no exempt rules.

| Assessment Axis | Empirical Result | Target | Status |
|---|---|---|---|
| **Entity Rank Precision@k** | 100.0% | ≥ 90% | PASS |
| **Entity Rank Recall@k** | 100.0% | ≥ 90% | PASS |
| **Injected Defect Recall** | 100.0% (21/21) | ≥ 90% | PASS |
| **Overall Defect Precision** | 100.0% (21/21) | ≥ 85% | PASS |
| **Overall Defect F1 Score** | 1.0000 | ≥ 0.85 | PASS |
| **Ranking Stability (±20% domain weights)** | Spearman ρ = 1.0000 / 1.0000 | ≥ 0.85 | PASS |
| **Cryptographic Audit Log Integrity** | Audit chain verified successfully (2 entries intact). | intact | PASS |

## 2. Entity-Level Ranking & Confounder Discrimination
- **Top-k Ranked Entities (k = injected entity count):** CSE-02, CSE-08, CSE-03, CSE-05, CSE-07, CSE-09, CSE-10
- **Remaining Entities:** CSE-01, CSE-04, CSE-06
- **Clean Entities Ranked in Top-k:** none
- **Confounder Checks (measured from this run's findings):**
  * **SOAR Automation:** 0 EG01/EG02 finding(s) on entities with no injected fast-closure defect.
  * **Small Entity Band (CSE-08, CSE-10):** 0 finding(s) for rules not injected there.

## 3. Rule Detection Accuracy (Execution Gaps & Negative Space)
- **Findings Raised:** 21 (entity, rule) pairs
- **Injected Defects Detected:** 21 of 21
- **Missed Defects (False Negatives):** 0
- **False Positives on Clean Entities:** 0
- **False Positives on Defect Entities (rule not injected there):** 0

### Per-Rule Empirical Breakdown
| Rule ID | True Positives (TP) | False Negatives (FN) | False Positives (FP) |
|---|---|---|---|
| `EG01` | 1 | 0 | 0 |
| `EG03` | 1 | 0 | 0 |
| `EG04` | 1 | 0 | 0 |
| `EG05` | 1 | 0 | 0 |
| `EG06` | 1 | 0 | 0 |
| `EG07` | 1 | 0 | 0 |
| `EG08` | 1 | 0 | 0 |
| `EG09` | 1 | 0 | 0 |
| `EG10` | 1 | 0 | 0 |
| `EG11` | 1 | 0 | 0 |
| `EG12` | 1 | 0 | 0 |
| `NS01` | 3 | 0 | 0 |
| `NS02` | 1 | 0 | 0 |
| `NS03` | 1 | 0 | 0 |
| `NS04` | 1 | 0 | 0 |
| `NS05` | 1 | 0 | 0 |
| `NS06` | 1 | 0 | 0 |
| `NS07` | 1 | 0 | 0 |
| `NS08` | 1 | 0 | 0 |

## 4. Review-Effort Lift Analysis
Review-effort lift compares the share of defect-affected alerts among the review queue's top alert items with the share among all alerts (what random sampling would find), at budgets of 1%, 2% and 5% of total alerts. Both sides count alert records only. The queue holds 119 alert items (147 items in total); where a budget exceeds that, only the items that exist are counted as examined.

| Audit Budget (% of Alerts) | Budget (alerts) | Queue Alerts Examined | Affected Alerts Found | Queue Hit Rate | Random Sampling Rate | Lift Factor |
|---|---|---|---|---|---|---|
| **1%** | 162 | 119 (queue exhausted) | 19 | 16.0% | 2.67% | **5.98x** |
| **2%** | 325 | 119 (queue exhausted) | 19 | 16.0% | 2.67% | **5.98x** |
| **5%** | 812 | 119 (queue exhausted) | 19 | 16.0% | 2.67% | **5.98x** |

Lift by queue depth (alert items in score order; these depths always fit inside the queue):

| Top queue alerts examined | Affected Alerts Found | Hit Rate | Lift Factor |
|---|---|---|---|
| 10 | 4 | 40.0% | **14.98x** |
| 25 | 14 | 56.0% | **20.97x** |
| 50 | 17 | 34.0% | **12.73x** |
| 100 | 19 | 19.0% | **7.12x** |
| 119 | 19 | 16.0% | **5.98x** |

## 5. Shadow-Pilot Integration Method
The `ShadowPilotAdapter` class allows regulatory examiners to validate SAT-SA against historical manual examination findings.
Examiners provide historical CSV logs with schema `(entity_id, record_id, rule_id, label)`. The harness calculates:
1. **Historical finding recall**: Percentage of prior manually confirmed supervisory findings detected by SAT-SA.
2. **Queue discovery efficiency**: Overlap between past examiner investigations and SAT-SA's top-k review queue.
3. **Workpaper precision**: Of the SAT-SA findings the workpaper adjudicates, the share examiners confirmed. Findings the workpaper does not mention are listed as unadjudicated, not counted as false positives.

### Shadow-Pilot Results
Workpaper `shadow_pilot_standin.csv`, evaluated 2026-09-30T08:34:40.159669+00:00 by cli. These figures are only as independent as the workpaper labels supplied: labels taken from real historical examiner findings are evidence; synthetic or stand-in labels only rehearse the pipeline (see docs/validation.md Section 5A).

| Measure | Value |
|---|---|
| Workpaper rows | 122 (47 confirmed) |
| Historical finding recall | 100.0% (47/47) |
| Queue record recall | 57.5% (27/47) |
| Workpaper precision | 100.0% (21/21 adjudicated findings) (95% CI 85–100%) |
| Findings not adjudicated by the workpaper | 0 |
| Cleared records still in the review queue | 0/15 |

Per rule, at (entity, rule) level, over 10 assessed entities (rule config hash `d05e7086d1cfafe6`):

| Rule | Recall (reproduced / confirmed) | Precision (confirmed / adjudicated) | Not adjudicated | Fires on |
|---|---|---|---|---|
| `EG01` | 100.0% (1/1) (95% CI 21–100%) | 100.0% (1/1) (95% CI 21–100%) | 0 | 10.0% of entities |
| `EG02` | n/a (0/0) | n/a (0/0) | 0 | 0.0% of entities |
| `EG03` | 100.0% (1/1) (95% CI 21–100%) | 100.0% (1/1) (95% CI 21–100%) | 0 | 10.0% of entities |
| `EG04` | 100.0% (1/1) (95% CI 21–100%) | 100.0% (1/1) (95% CI 21–100%) | 0 | 10.0% of entities |
| `EG05` | 100.0% (1/1) (95% CI 21–100%) | 100.0% (1/1) (95% CI 21–100%) | 0 | 10.0% of entities |
| `EG06` | 100.0% (1/1) (95% CI 21–100%) | 100.0% (1/1) (95% CI 21–100%) | 0 | 10.0% of entities |
| `EG07` | 100.0% (1/1) (95% CI 21–100%) | 100.0% (1/1) (95% CI 21–100%) | 0 | 10.0% of entities |
| `EG08` | 100.0% (1/1) (95% CI 21–100%) | 100.0% (1/1) (95% CI 21–100%) | 0 | 10.0% of entities |
| `EG09` | 100.0% (1/1) (95% CI 21–100%) | 100.0% (1/1) (95% CI 21–100%) | 0 | 10.0% of entities |
| `EG10` | 100.0% (1/1) (95% CI 21–100%) | 100.0% (1/1) (95% CI 21–100%) | 0 | 10.0% of entities |
| `EG11` | 100.0% (1/1) (95% CI 21–100%) | 100.0% (1/1) (95% CI 21–100%) | 0 | 10.0% of entities |
| `EG12` | 100.0% (1/1) (95% CI 21–100%) | 100.0% (1/1) (95% CI 21–100%) | 0 | 10.0% of entities |
| `NS01` | 100.0% (3/3) (95% CI 44–100%) | 100.0% (3/3) (95% CI 44–100%) | 0 | 30.0% of entities |
| `NS02` | 100.0% (1/1) (95% CI 21–100%) | 100.0% (1/1) (95% CI 21–100%) | 0 | 10.0% of entities |
| `NS03` | 100.0% (1/1) (95% CI 21–100%) | 100.0% (1/1) (95% CI 21–100%) | 0 | 10.0% of entities |
| `NS04` | 100.0% (1/1) (95% CI 21–100%) | 100.0% (1/1) (95% CI 21–100%) | 0 | 10.0% of entities |
| `NS05` | 100.0% (1/1) (95% CI 21–100%) | 100.0% (1/1) (95% CI 21–100%) | 0 | 10.0% of entities |
| `NS06` | 100.0% (1/1) (95% CI 21–100%) | 100.0% (1/1) (95% CI 21–100%) | 0 | 10.0% of entities |
| `NS07` | 100.0% (1/1) (95% CI 21–100%) | 100.0% (1/1) (95% CI 21–100%) | 0 | 10.0% of entities |
| `NS08` | 100.0% (1/1) (95% CI 21–100%) | 100.0% (1/1) (95% CI 21–100%) | 0 | 10.0% of entities |

## 6. Sensitivity & Robustness Analysis
- Evaluated with **±20%** perturbation of the scoring **domain weights** only.
- Spearman rank correlation with +20% weights: **1.0000**
- Spearman rank correlation with -20% weights: **1.0000**
- **Conclusion:** The entity ranking is stable under this domain-weight perturbation. This does not move rule detection thresholds; Section 7 does.

## 7. Rule Threshold Sensitivity
Each tunable rule threshold is moved by -20% and +20% on its own, and that rule is re-run on every entity and scored against the ground truth. A changed outcome means an injected defect or a clean entity sits within 20% of that threshold. The synthetic defects were built with the thresholds in hand, so this measures their margin, not real-world robustness.

3 of 64 single-threshold perturbations (±20%) changed that rule's outcome.

| Rule | Threshold | Baseline | Tested | Outcome at baseline | Outcome when tested |
|---|---|---|---|---|---|
| `EG01` | `fast_share_threshold` | 0.15 | 0.12 (-20%) | TP 1 / FN 0 / FP 0 | TP 1 / FN 0 / FP 0 |
| `EG01` | `fast_share_threshold` | 0.15 | 0.18 (+20%) | TP 1 / FN 0 / FP 0 | TP 1 / FN 0 / FP 0 |
| `EG01` | `min_fast_count` | 5 | 4 (-20%) | TP 1 / FN 0 / FP 0 | TP 1 / FN 0 / FP 0 |
| `EG01` | `min_fast_count` | 5 | 6 (+20%) | TP 1 / FN 0 / FP 0 | TP 1 / FN 0 / FP 0 |
| `EG02` | `max_uninvestigated_share` | 0.15 | 0.12 (-20%) | TP 0 / FN 0 / FP 0 | TP 0 / FN 0 / FP 0 |
| `EG02` | `max_uninvestigated_share` | 0.15 | 0.18 (+20%) | TP 0 / FN 0 / FP 0 | TP 0 / FN 0 / FP 0 |
| `EG02` | `min_uninvestigated_count` | 5 | 4 (-20%) | TP 0 / FN 0 / FP 0 | TP 0 / FN 0 / FP 0 |
| `EG02` | `min_uninvestigated_count` | 5 | 6 (+20%) | TP 0 / FN 0 / FP 0 | TP 0 / FN 0 / FP 0 |
| `EG04` | `max_comment_hash_share` | 0.25 | 0.2 (-20%) | TP 1 / FN 0 / FP 0 | TP 1 / FN 0 / FP 0 |
| `EG04` | `max_comment_hash_share` | 0.25 | 0.3 (+20%) | TP 1 / FN 0 / FP 0 | TP 1 / FN 0 / FP 0 |
| `EG04` | `min_hash_group_size` | 10 | 8 (-20%) | TP 1 / FN 0 / FP 0 | TP 1 / FN 0 / FP 0 |
| `EG04` | `min_hash_group_size` | 10 | 12 (+20%) | TP 1 / FN 0 / FP 0 | TP 1 / FN 0 / FP 0 |
| `EG05` | `min_repeat_count` | 8 | 6 (-20%) | TP 1 / FN 0 / FP 0 | TP 1 / FN 0 / FP 0 |
| `EG05` | `min_repeat_count` | 8 | 10 (+20%) | TP 1 / FN 0 / FP 0 | TP 1 / FN 0 / FP 0 |
| `EG05` | `min_unaddressed_pairs` | 2 | 1 (-20%) | TP 1 / FN 0 / FP 0 | TP 1 / FN 0 / FP 0 |
| `EG05` | `min_unaddressed_pairs` | 2 | 3 (+20%) | TP 1 / FN 0 / FP 0 | TP 0 / FN 1 / FP 0 (missed CSE-09) **changed** |
| `EG05` | `max_chance_pairs` | 0.5 | 0.4 (-20%) | TP 1 / FN 0 / FP 0 | TP 1 / FN 0 / FP 0 |
| `EG05` | `max_chance_pairs` | 0.5 | 0.6 (+20%) | TP 1 / FN 0 / FP 0 | TP 1 / FN 0 / FP 0 |
| `EG06` | `min_bulk_closures_per_minute` | 8 | 6 (-20%) | TP 1 / FN 0 / FP 0 | TP 1 / FN 0 / FP 0 |
| `EG06` | `min_bulk_closures_per_minute` | 8 | 10 (+20%) | TP 1 / FN 0 / FP 0 | TP 1 / FN 0 / FP 0 |
| `EG06` | `max_deadline_hugging_share` | 0.25 | 0.2 (-20%) | TP 1 / FN 0 / FP 0 | TP 1 / FN 0 / FP 0 |
| `EG06` | `max_deadline_hugging_share` | 0.25 | 0.3 (+20%) | TP 1 / FN 0 / FP 0 | TP 1 / FN 0 / FP 0 |
| `EG07` | `min_closures_per_analyst_hour` | 30 | 24 (-20%) | TP 1 / FN 0 / FP 0 | TP 1 / FN 0 / FP 0 |
| `EG07` | `min_closures_per_analyst_hour` | 30 | 36 (+20%) | TP 1 / FN 0 / FP 0 | TP 0 / FN 1 / FP 0 (missed CSE-08) **changed** |
| `EG08` | `min_unacknowledged_escalations` | 3 | 2 (-20%) | TP 1 / FN 0 / FP 0 | TP 1 / FN 0 / FP 0 |
| `EG08` | `min_unacknowledged_escalations` | 3 | 4 (+20%) | TP 1 / FN 0 / FP 0 | TP 1 / FN 0 / FP 0 |
| `EG09` | `stale_case_days` | 14 | 11 (-20%) | TP 1 / FN 0 / FP 0 | TP 1 / FN 0 / FP 0 |
| `EG09` | `stale_case_days` | 14 | 17 (+20%) | TP 1 / FN 0 / FP 0 | TP 1 / FN 0 / FP 0 |
| `EG09` | `min_stale_cases` | 3 | 2 (-20%) | TP 1 / FN 0 / FP 0 | TP 1 / FN 0 / FP 0 |
| `EG09` | `min_stale_cases` | 3 | 4 (+20%) | TP 1 / FN 0 / FP 0 | TP 1 / FN 0 / FP 0 |
| `EG10` | `mttr_gap_ratio_threshold` | 0.6 | 0.48 (-20%) | TP 1 / FN 0 / FP 0 | TP 1 / FN 0 / FP 0 |
| `EG10` | `mttr_gap_ratio_threshold` | 0.6 | 0.72 (+20%) | TP 1 / FN 0 / FP 0 | TP 1 / FN 0 / FP 0 |
| `EG11` | `min_alert_volume` | 200 | 160 (-20%) | TP 1 / FN 0 / FP 0 | TP 1 / FN 0 / FP 0 |
| `EG11` | `min_alert_volume` | 200 | 240 (+20%) | TP 1 / FN 0 / FP 0 | TP 1 / FN 0 / FP 0 |
| `EG11` | `max_robust_z` | 3.5 | 2.8 (-20%) | TP 1 / FN 0 / FP 0 | TP 1 / FN 0 / FP 0 |
| `EG11` | `max_robust_z` | 3.5 | 4.2 (+20%) | TP 1 / FN 0 / FP 0 | TP 1 / FN 0 / FP 0 |
| `EG11` | `min_spread` | 0.01 | 0.008 (-20%) | TP 1 / FN 0 / FP 0 | TP 1 / FN 0 / FP 0 |
| `EG11` | `min_spread` | 0.01 | 0.012 (+20%) | TP 1 / FN 0 / FP 0 | TP 1 / FN 0 / FP 0 |
| `EG11` | `max_fp_rate` | 0.98 | 0.784 (-20%) | TP 1 / FN 0 / FP 0 | TP 1 / FN 0 / FP 0 |
| `EG11` | `max_fp_rate` | 0.98 | 1.0 (+20%) | TP 1 / FN 0 / FP 0 | TP 1 / FN 0 / FP 0 |
| `EG12` | `min_skipped_cases` | 2 | 1 (-20%) | TP 1 / FN 0 / FP 0 | TP 1 / FN 0 / FP 0 |
| `EG12` | `min_skipped_cases` | 2 | 3 (+20%) | TP 1 / FN 0 / FP 0 | TP 1 / FN 0 / FP 0 |
| `NS01` | `min_silent_days` | 3 | 2 (-20%) | TP 3 / FN 0 / FP 0 | TP 3 / FN 0 / FP 0 |
| `NS01` | `min_silent_days` | 3 | 4 (+20%) | TP 3 / FN 0 / FP 0 | TP 3 / FN 0 / FP 0 |
| `NS01` | `min_asset_criticality` | 3 | 2 (-20%) | TP 3 / FN 0 / FP 0 | TP 3 / FN 0 / FP 0 |
| `NS01` | `min_asset_criticality` | 3 | 4 (+20%) | TP 3 / FN 0 / FP 0 | TP 3 / FN 0 / FP 0 |
| `NS02` | `min_peer_share` | 0.6 | 0.48 (-20%) | TP 1 / FN 0 / FP 0 | TP 1 / FN 0 / FP 0 |
| `NS02` | `min_peer_share` | 0.6 | 0.72 (+20%) | TP 1 / FN 0 / FP 0 | TP 1 / FN 0 / FP 0 |
| `NS03` | `max_night_share` | 0.03 | 0.024 (-20%) | TP 1 / FN 0 / FP 0 | TP 1 / FN 0 / FP 0 |
| `NS03` | `max_night_share` | 0.03 | 0.036 (+20%) | TP 1 / FN 0 / FP 0 | TP 1 / FN 0 / FP 0 |
| `NS03` | `min_alert_volume` | 100 | 80 (-20%) | TP 1 / FN 0 / FP 0 | TP 1 / FN 0 / FP 0 |
| `NS03` | `min_alert_volume` | 100 | 120 (+20%) | TP 1 / FN 0 / FP 0 | TP 1 / FN 0 / FP 0 |
| `NS03` | `max_robust_z` | 3.5 | 2.8 (-20%) | TP 1 / FN 0 / FP 0 | TP 1 / FN 0 / FP 0 |
| `NS03` | `max_robust_z` | 3.5 | 4.2 (+20%) | TP 1 / FN 0 / FP 0 | TP 1 / FN 0 / FP 0 |
| `NS03` | `min_spread` | 0.02 | 0.016 (-20%) | TP 1 / FN 0 / FP 0 | TP 1 / FN 0 / FP 0 |
| `NS03` | `min_spread` | 0.02 | 0.024 (+20%) | TP 1 / FN 0 / FP 0 | TP 1 / FN 0 / FP 0 |
| `NS04` | `min_tp_without_case` | 3 | 2 (-20%) | TP 1 / FN 0 / FP 0 | TP 1 / FN 0 / FP 0 |
| `NS04` | `min_tp_without_case` | 3 | 4 (+20%) | TP 1 / FN 0 / FP 0 | TP 1 / FN 0 / FP 0 |
| `NS05` | `max_dormant_share` | 0.4 | 0.32 (-20%) | TP 1 / FN 0 / FP 0 | TP 1 / FN 0 / FP 0 |
| `NS05` | `max_dormant_share` | 0.4 | 0.48 (+20%) | TP 1 / FN 0 / FP 0 | TP 0 / FN 1 / FP 0 (missed CSE-09) **changed** |
| `NS05` | `min_dormant_rules` | 5 | 4 (-20%) | TP 1 / FN 0 / FP 0 | TP 1 / FN 0 / FP 0 |
| `NS05` | `min_dormant_rules` | 5 | 6 (+20%) | TP 1 / FN 0 / FP 0 | TP 1 / FN 0 / FP 0 |
| `NS06` | `min_ghost_assets` | 2 | 1 (-20%) | TP 1 / FN 0 / FP 0 | TP 1 / FN 0 / FP 0 |
| `NS06` | `min_ghost_assets` | 2 | 3 (+20%) | TP 1 / FN 0 / FP 0 | TP 1 / FN 0 / FP 0 |

Not covered: EG03, NS07, NS08 have no tunable threshold (no `params` in `config/rules.yaml`): EG03 and NS07 are zero-tolerance and NS08 checks the fixed 6-month review period. A rule showing TP 0 / FN 0 has no injected defect in this dataset.