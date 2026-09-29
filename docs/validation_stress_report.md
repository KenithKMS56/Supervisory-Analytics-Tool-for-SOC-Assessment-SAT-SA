# SAT-SA Stress Scenario Validation Report

> Companion to docs/validation.md. Unlike the primary synthetic dataset (whose injected
> defects clearly exceed each rule's threshold by design), this scenario injects a
> borderline-threshold case, an ambiguous dual-rule case, and a noisy true-negative case.
> It is still synthetic and built against the rules' own thresholds, so a perfect score
> shows the rules behave as specified near those thresholds, not real-world accuracy.

**Run ID:** `RUN-20260929175408400764-ff0a1683` | **Seed:** `9901`

| Metric | Result |
|---|---|
| Entity Rank Precision@k | 100.0% |
| Entity Rank Recall@k | 100.0% |
| Injected Defect Recall | 100.0% (3/3) |
| Overall Defect Precision | 100.0% (3 of 3 findings) |
| False Positives | 0 |

Every finding whose (entity, rule) pair is not an injected defect counts as a false positive, on any
entity and for any rule.

- False positives on the clean entity: none
- False positives on defect entities (rule not injected there): none
- Missed defects: none

## Per-rule breakdown
| Rule ID | TP | FN | FP |
|---|---|---|---|
| `EG02` | 1 | 0 | 0 |
| `EG04` | 2 | 0 | 0 |