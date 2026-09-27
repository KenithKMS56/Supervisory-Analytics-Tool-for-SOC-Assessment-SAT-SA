# SAT-SA Stress Scenario Validation Report

> This is the HARDER, more realistic companion to docs/validation.md. Unlike the primary
> synthetic dataset (whose injected defects clearly exceed each rule's threshold by design),
> this scenario injects a borderline-threshold case, an ambiguous dual-rule case, and a
> noisy true-negative case. These numbers are NOT expected to be 100%.

**Run ID:** `RUN-20260925111522399264-a2db5f4d` | **Seed:** `9901`

| Metric | Result |
|---|---|
| Entity Rank Precision@k | 100.0% |
| Entity Rank Recall@k | 100.0% |
| Injected Defect Recall | 100.0% (3/3) |
| Overall Defect Precision | 60.0% |
| False Positives | 2 |

## Per-rule breakdown
| Rule ID | TP | FN | FP |
|---|---|---|---|
| `EG04` | 2 | 0 | 0 |
| `EG02` | 1 | 0 | 0 |
| `EG05` | 0 | 0 | 1 |
| `NS08` | 0 | 0 | 1 |