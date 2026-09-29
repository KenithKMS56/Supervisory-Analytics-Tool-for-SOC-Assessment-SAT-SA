# SAT-SA Detector-Implementation Correctness Report

> **Supervisory Notice:** *Indicators requiring supervisory review; not a compliance determination.*

**Run ID:** `RUN-20260929160403009485-d5980d82` | **Validation Engine:** Fully Deterministic (No AI/ML)

## 1. Executive Summary & Verification Criteria
This report documents whether each detection rule's code correctly implements its own specified logic, measured against a synthetic ground-truth dataset across 10 Critical Sector Entities (CSEs) whose injected defects are deliberately built to clearly exceed each rule's threshold. High scores here demonstrate implementation correctness on an unambiguous dataset, not real-world detection accuracy -- see docs/validation.md Section 0 for the harder, more realistic 'stress scenario' (`satsa validate-stress`) and Section 5 for the Shadow-Pilot mode against real historical findings.

Precision counts every finding whose (entity, rule) pair is not an injected defect as a false positive, on any entity and for any rule, with no exempt rules.

| Assessment Axis | Empirical Result | Target | Status |
|---|---|---|---|
| **Entity Rank Precision@k** | 100.0% | ≥ 90% | PASS |
| **Entity Rank Recall@k** | 100.0% | ≥ 90% | PASS |
| **Injected Defect Recall** | 100.0% (13/13) | ≥ 90% | PASS |
| **Overall Defect Precision** | 100.0% (13/13) | ≥ 85% | PASS |
| **Overall Defect F1 Score** | 1.0000 | ≥ 0.85 | PASS |
| **Ranking Stability (±20% domain weights)** | Spearman ρ = 1.0000 / 1.0000 | ≥ 0.85 | PASS |
| **Cryptographic Audit Log Integrity** | Audit chain verified successfully (114 entries intact). | intact | PASS |

## 2. Entity-Level Ranking & Confounder Discrimination
- **Top-k Ranked Entities (k = injected entity count):** CSE-02, CSE-03, CSE-07, CSE-08, CSE-09, CSE-05, CSE-10
- **Remaining Entities:** CSE-01, CSE-04, CSE-06
- **Clean Entities Ranked in Top-k:** none
- **Confounder Checks (measured from this run's findings):**
  * **SOAR Automation:** 0 EG01/EG02 finding(s) on entities with no injected fast-closure defect.
  * **Small Entity Band (CSE-08, CSE-10):** 0 finding(s) for rules not injected there.

## 3. Rule Detection Accuracy (Execution Gaps & Negative Space)
- **Findings Raised:** 13 (entity, rule) pairs
- **Injected Defects Detected:** 13 of 13
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
| `EG10` | 1 | 0 | 0 |
| `NS01` | 3 | 0 | 0 |
| `NS02` | 1 | 0 | 0 |
| `NS03` | 1 | 0 | 0 |
| `NS04` | 1 | 0 | 0 |
| `NS06` | 1 | 0 | 0 |

## 4. Review-Effort Lift Analysis
Review-effort lift compares the share of defect-affected alerts among the review queue's top alert items with the share among all alerts (what random sampling would find), at budgets of 1%, 2% and 5% of total alerts. Both sides count alert records only. The queue holds 109 alert items (120 items in total); where a budget exceeds that, only the items that exist are counted as examined.

| Audit Budget (% of Alerts) | Budget (alerts) | Queue Alerts Examined | Affected Alerts Found | Queue Hit Rate | Random Sampling Rate | Lift Factor |
|---|---|---|---|---|---|---|
| **1%** | 162 | 109 (queue exhausted) | 14 | 12.8% | 1.20% | **10.69x** |
| **2%** | 324 | 109 (queue exhausted) | 14 | 12.8% | 1.20% | **10.69x** |
| **5%** | 811 | 109 (queue exhausted) | 14 | 12.8% | 1.20% | **10.69x** |

## 5. Shadow-Pilot Integration Method
The `ShadowPilotAdapter` class allows regulatory examiners to validate SAT-SA against historical manual examination findings.
Examiners provide historical CSV logs with schema `(entity_id, record_id, rule_id, label)`. The harness calculates:
1. **Historical finding recall**: Percentage of prior manually confirmed supervisory findings detected by SAT-SA.
2. **Queue discovery efficiency**: Overlap between past examiner investigations and SAT-SA's top-k review queue.
3. **Workpaper precision**: Of the SAT-SA findings the workpaper adjudicates, the share examiners confirmed. Findings the workpaper does not mention are listed as unadjudicated, not counted as false positives.

### Shadow-Pilot Results
Workpaper `shadow_pilot_standin.csv`, evaluated 2026-09-29T16:04:08.200189+00:00 by cli. These figures are only as independent as the workpaper labels supplied: labels taken from real historical examiner findings are evidence; synthetic or stand-in labels only rehearse the pipeline (see docs/validation.md Section 5A).

| Measure | Value |
|---|---|
| Workpaper rows | 97 (22 confirmed) |
| Historical finding recall | 100.0% (22/22) |
| Queue record recall | 54.5% (12/22) |
| Workpaper precision | 100.0% (13/13 adjudicated findings) |
| Findings not adjudicated by the workpaper | 0 |
| Cleared records still in the review queue | 0/15 |

## 6. Sensitivity & Robustness Analysis
- Evaluated with **±20%** perturbation of the scoring **domain weights** only.
- Spearman rank correlation with +20% weights: **1.0000**
- Spearman rank correlation with -20% weights: **1.0000**
- **Conclusion:** The entity ranking is stable under this domain-weight perturbation. Rule detection thresholds were not perturbed, so this says nothing about how findings change as thresholds move.