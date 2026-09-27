# SAT-SA Detector-Implementation Correctness Report

> **Supervisory Notice:** *Indicators requiring supervisory review; not a compliance determination.*

**Run ID:** `RUN-20260925111515531894-d9a74b92` | **Validation Engine:** Fully Deterministic (No AI/ML)

## 1. Executive Summary & Verification Criteria
This report documents whether each detection rule's code correctly implements its own specified logic, measured against a synthetic ground-truth dataset across 10 Critical Sector Entities (CSEs) whose injected defects are deliberately built to clearly exceed each rule's threshold. High scores here demonstrate implementation correctness on an unambiguous dataset, not real-world detection accuracy -- see docs/validation.md Section 0 for the harder, more realistic 'stress scenario' (`satsa validate-stress`) and Section 5 for the Shadow-Pilot mode against real historical findings.

| Assessment Axis | Empirical Result | Status |
|---|---|---|
| **Entity Rank Precision@7** | 100.0% | PASS |
| **Entity Rank Recall@7** | 100.0% | PASS |
| **Injected Defect Recall** | 100.0% (13/13) | PASS |
| **Overall Defect Precision** | 100.0% | PASS |
| **Overall Defect F1 Score** | 1.0000 | PASS |
| **Ranking Stability (±20% Perturbation)** | Spearman ρ = 1.0000 / 1.0000 | PASS |
| **Cryptographic Audit Log Integrity** | Audit chain verified successfully (5 entries intact). | PASS |

## 2. Entity-Level Ranking & Confounder Discrimination
- **Injected Entities Flagged at Top-k:** CSE-08, CSE-03, CSE-07, CSE-02, CSE-09, CSE-05, CSE-10
- **Clean Baseline Entities (Kept Low/Moderate):** CSE-01, CSE-04, CSE-06
- **Confounder Checks:**
  * **SOAR Automation:** High-velocity playbook closures did not produce spurious analyst implausibility or SLA penalties.
  * **Small Entity Band (CSE-08):** Properly benchmarked against peer size band without volume-collapse false positives.

## 3. Rule Detection Accuracy (Execution Gaps & Negative Space)
- **Injected Defects Detected:** 13 of 13
- **Missed Defects (False Negatives):** 0
- **Spurious Findings on Clean Entities (False Positives):** 0

### Per-Rule Empirical Breakdown
| Rule ID | True Positives (TP) | False Negatives (FN) | False Positives (FP) |
|---|---|---|---|
| `EG10` | 1 | 0 | 0 |
| `EG01` | 1 | 0 | 0 |
| `EG03` | 1 | 0 | 0 |
| `NS01` | 3 | 0 | 0 |
| `NS06` | 1 | 0 | 0 |
| `EG04` | 1 | 0 | 0 |
| `EG06` | 1 | 0 | 0 |
| `NS02` | 1 | 0 | 0 |
| `NS04` | 1 | 0 | 0 |
| `EG05` | 1 | 0 | 0 |
| `NS03` | 1 | 0 | 0 |

## 4. Review-Effort Lift Analysis
Review-effort lift measures the operational advantage of reviewing SAT-SA's prioritized queue over unassisted random sampling of the same size at fixed supervisory audit budgets (1%, 2%, and 5% of total alerts).

| Audit Budget (% of Alerts) | Records Examined | Defects Found (SAT-SA) | Queue Hit Rate | Random Sampling Rate | Lift Factor |
|---|---|---|---|---|---|
| **1%** | 162 | 13 | 8.0% | 1.34% | **5.97x** |
| **2%** | 324 | 18 | 5.6% | 1.34% | **4.13x** |
| **5%** | 810 | 18 | 2.2% | 1.34% | **1.65x** |

## 5. Shadow-Pilot Integration Method
The `ShadowPilotAdapter` class allows regulatory examiners to validate SAT-SA against historical manual examination findings.
Examiners provide historical CSV logs with schema `(entity_id, record_id, rule_id, label)`. The harness calculates:
1. **Historical finding recall**: Percentage of prior manually confirmed supervisory findings detected by SAT-SA.
2. **Queue discovery efficiency**: Overlap between past examiner investigations and SAT-SA's top-k review queue.

## 6. Sensitivity & Robustness Analysis
- Evaluated with **±20%** parameter perturbation on domain weights.
- Spearman rank correlation with +20% weights: **1.0000**
- Spearman rank correlation with -20% weights: **1.0000**
- **Conclusion:** The ranking order is stable and invariant to minor threshold changes, confirming mathematical robustness.