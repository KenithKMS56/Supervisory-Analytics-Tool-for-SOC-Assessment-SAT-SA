# SAT-SA Stress Scenario Validation Report

> Companion to docs/validation.md. Unlike the primary synthetic dataset (whose injected
> defects clearly exceed each rule's threshold by design), this scenario injects a
> borderline-threshold case, an ambiguous dual-rule case, and a noisy true-negative case.
> It is still synthetic and built against the rules' own thresholds, so a perfect score
> shows the rules behave as specified near those thresholds, not real-world accuracy.

**Run ID:** `RUN-20260930113545529122-77e8686a` | **Seed:** `9901`

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

## Threshold sensitivity

3 of 64 single-threshold perturbations (±20%) changed that rule's outcome.

| Rule | Threshold | Baseline | Tested | Outcome at baseline | Outcome when tested |
|---|---|---|---|---|---|
| `EG01` | `fast_share_threshold` | 0.15 | 0.12 (-20%) | TP 0 / FN 0 / FP 0 | TP 0 / FN 0 / FP 0 |
| `EG01` | `fast_share_threshold` | 0.15 | 0.18 (+20%) | TP 0 / FN 0 / FP 0 | TP 0 / FN 0 / FP 0 |
| `EG01` | `min_fast_count` | 5 | 4 (-20%) | TP 0 / FN 0 / FP 0 | TP 0 / FN 0 / FP 0 |
| `EG01` | `min_fast_count` | 5 | 6 (+20%) | TP 0 / FN 0 / FP 0 | TP 0 / FN 0 / FP 0 |
| `EG02` | `max_uninvestigated_share` | 0.15 | 0.12 (-20%) | TP 1 / FN 0 / FP 0 | TP 1 / FN 0 / FP 0 |
| `EG02` | `max_uninvestigated_share` | 0.15 | 0.18 (+20%) | TP 1 / FN 0 / FP 0 | TP 1 / FN 0 / FP 0 |
| `EG02` | `min_uninvestigated_count` | 5 | 4 (-20%) | TP 1 / FN 0 / FP 0 | TP 1 / FN 0 / FP 0 |
| `EG02` | `min_uninvestigated_count` | 5 | 6 (+20%) | TP 1 / FN 0 / FP 0 | TP 1 / FN 0 / FP 0 |
| `EG04` | `max_comment_hash_share` | 0.25 | 0.2 (-20%) | TP 2 / FN 0 / FP 0 | TP 2 / FN 0 / FP 0 |
| `EG04` | `max_comment_hash_share` | 0.25 | 0.3 (+20%) | TP 2 / FN 0 / FP 0 | TP 0 / FN 2 / FP 0 (missed STRESS-01, STRESS-02) **changed** |
| `EG04` | `min_hash_group_size` | 10 | 8 (-20%) | TP 2 / FN 0 / FP 0 | TP 2 / FN 0 / FP 0 |
| `EG04` | `min_hash_group_size` | 10 | 12 (+20%) | TP 2 / FN 0 / FP 0 | TP 1 / FN 1 / FP 0 (missed STRESS-01) **changed** |
| `EG05` | `min_repeat_count` | 8 | 6 (-20%) | TP 0 / FN 0 / FP 0 | TP 0 / FN 0 / FP 0 |
| `EG05` | `min_repeat_count` | 8 | 10 (+20%) | TP 0 / FN 0 / FP 0 | TP 0 / FN 0 / FP 0 |
| `EG05` | `min_unaddressed_pairs` | 2 | 1 (-20%) | TP 0 / FN 0 / FP 0 | TP 0 / FN 0 / FP 1 (false alarm STRESS-03) **changed** |
| `EG05` | `min_unaddressed_pairs` | 2 | 3 (+20%) | TP 0 / FN 0 / FP 0 | TP 0 / FN 0 / FP 0 |
| `EG05` | `max_chance_pairs` | 0.5 | 0.4 (-20%) | TP 0 / FN 0 / FP 0 | TP 0 / FN 0 / FP 0 |
| `EG05` | `max_chance_pairs` | 0.5 | 0.6 (+20%) | TP 0 / FN 0 / FP 0 | TP 0 / FN 0 / FP 0 |
| `EG06` | `min_bulk_closures_per_minute` | 8 | 6 (-20%) | TP 0 / FN 0 / FP 0 | TP 0 / FN 0 / FP 0 |
| `EG06` | `min_bulk_closures_per_minute` | 8 | 10 (+20%) | TP 0 / FN 0 / FP 0 | TP 0 / FN 0 / FP 0 |
| `EG06` | `max_deadline_hugging_share` | 0.25 | 0.2 (-20%) | TP 0 / FN 0 / FP 0 | TP 0 / FN 0 / FP 0 |
| `EG06` | `max_deadline_hugging_share` | 0.25 | 0.3 (+20%) | TP 0 / FN 0 / FP 0 | TP 0 / FN 0 / FP 0 |
| `EG07` | `min_closures_per_analyst_hour` | 30 | 24 (-20%) | TP 0 / FN 0 / FP 0 | TP 0 / FN 0 / FP 0 |
| `EG07` | `min_closures_per_analyst_hour` | 30 | 36 (+20%) | TP 0 / FN 0 / FP 0 | TP 0 / FN 0 / FP 0 |
| `EG08` | `min_unacknowledged_escalations` | 3 | 2 (-20%) | TP 0 / FN 0 / FP 0 | TP 0 / FN 0 / FP 0 |
| `EG08` | `min_unacknowledged_escalations` | 3 | 4 (+20%) | TP 0 / FN 0 / FP 0 | TP 0 / FN 0 / FP 0 |
| `EG09` | `stale_case_days` | 14 | 11 (-20%) | TP 0 / FN 0 / FP 0 | TP 0 / FN 0 / FP 0 |
| `EG09` | `stale_case_days` | 14 | 17 (+20%) | TP 0 / FN 0 / FP 0 | TP 0 / FN 0 / FP 0 |
| `EG09` | `min_stale_cases` | 3 | 2 (-20%) | TP 0 / FN 0 / FP 0 | TP 0 / FN 0 / FP 0 |
| `EG09` | `min_stale_cases` | 3 | 4 (+20%) | TP 0 / FN 0 / FP 0 | TP 0 / FN 0 / FP 0 |
| `EG10` | `mttr_gap_ratio_threshold` | 0.6 | 0.48 (-20%) | TP 0 / FN 0 / FP 0 | TP 0 / FN 0 / FP 0 |
| `EG10` | `mttr_gap_ratio_threshold` | 0.6 | 0.72 (+20%) | TP 0 / FN 0 / FP 0 | TP 0 / FN 0 / FP 0 |
| `EG11` | `min_alert_volume` | 200 | 160 (-20%) | TP 0 / FN 0 / FP 0 | TP 0 / FN 0 / FP 0 |
| `EG11` | `min_alert_volume` | 200 | 240 (+20%) | TP 0 / FN 0 / FP 0 | TP 0 / FN 0 / FP 0 |
| `EG11` | `max_robust_z` | 3.5 | 2.8 (-20%) | TP 0 / FN 0 / FP 0 | TP 0 / FN 0 / FP 0 |
| `EG11` | `max_robust_z` | 3.5 | 4.2 (+20%) | TP 0 / FN 0 / FP 0 | TP 0 / FN 0 / FP 0 |
| `EG11` | `min_spread` | 0.01 | 0.008 (-20%) | TP 0 / FN 0 / FP 0 | TP 0 / FN 0 / FP 0 |
| `EG11` | `min_spread` | 0.01 | 0.012 (+20%) | TP 0 / FN 0 / FP 0 | TP 0 / FN 0 / FP 0 |
| `EG11` | `max_fp_rate` | 0.98 | 0.784 (-20%) | TP 0 / FN 0 / FP 0 | TP 0 / FN 0 / FP 0 |
| `EG11` | `max_fp_rate` | 0.98 | 1.0 (+20%) | TP 0 / FN 0 / FP 0 | TP 0 / FN 0 / FP 0 |
| `EG12` | `min_skipped_cases` | 2 | 1 (-20%) | TP 0 / FN 0 / FP 0 | TP 0 / FN 0 / FP 0 |
| `EG12` | `min_skipped_cases` | 2 | 3 (+20%) | TP 0 / FN 0 / FP 0 | TP 0 / FN 0 / FP 0 |
| `NS01` | `min_silent_days` | 3 | 2 (-20%) | TP 0 / FN 0 / FP 0 | TP 0 / FN 0 / FP 0 |
| `NS01` | `min_silent_days` | 3 | 4 (+20%) | TP 0 / FN 0 / FP 0 | TP 0 / FN 0 / FP 0 |
| `NS01` | `min_asset_criticality` | 3 | 2 (-20%) | TP 0 / FN 0 / FP 0 | TP 0 / FN 0 / FP 0 |
| `NS01` | `min_asset_criticality` | 3 | 4 (+20%) | TP 0 / FN 0 / FP 0 | TP 0 / FN 0 / FP 0 |
| `NS02` | `min_peer_share` | 0.6 | 0.48 (-20%) | TP 0 / FN 0 / FP 0 | TP 0 / FN 0 / FP 0 |
| `NS02` | `min_peer_share` | 0.6 | 0.72 (+20%) | TP 0 / FN 0 / FP 0 | TP 0 / FN 0 / FP 0 |
| `NS03` | `max_night_share` | 0.03 | 0.024 (-20%) | TP 0 / FN 0 / FP 0 | TP 0 / FN 0 / FP 0 |
| `NS03` | `max_night_share` | 0.03 | 0.036 (+20%) | TP 0 / FN 0 / FP 0 | TP 0 / FN 0 / FP 0 |
| `NS03` | `min_alert_volume` | 100 | 80 (-20%) | TP 0 / FN 0 / FP 0 | TP 0 / FN 0 / FP 0 |
| `NS03` | `min_alert_volume` | 100 | 120 (+20%) | TP 0 / FN 0 / FP 0 | TP 0 / FN 0 / FP 0 |
| `NS03` | `max_robust_z` | 3.5 | 2.8 (-20%) | TP 0 / FN 0 / FP 0 | TP 0 / FN 0 / FP 0 |
| `NS03` | `max_robust_z` | 3.5 | 4.2 (+20%) | TP 0 / FN 0 / FP 0 | TP 0 / FN 0 / FP 0 |
| `NS03` | `min_spread` | 0.02 | 0.016 (-20%) | TP 0 / FN 0 / FP 0 | TP 0 / FN 0 / FP 0 |
| `NS03` | `min_spread` | 0.02 | 0.024 (+20%) | TP 0 / FN 0 / FP 0 | TP 0 / FN 0 / FP 0 |
| `NS04` | `min_tp_without_case` | 3 | 2 (-20%) | TP 0 / FN 0 / FP 0 | TP 0 / FN 0 / FP 0 |
| `NS04` | `min_tp_without_case` | 3 | 4 (+20%) | TP 0 / FN 0 / FP 0 | TP 0 / FN 0 / FP 0 |
| `NS05` | `max_dormant_share` | 0.4 | 0.32 (-20%) | TP 0 / FN 0 / FP 0 | TP 0 / FN 0 / FP 0 |
| `NS05` | `max_dormant_share` | 0.4 | 0.48 (+20%) | TP 0 / FN 0 / FP 0 | TP 0 / FN 0 / FP 0 |
| `NS05` | `min_dormant_rules` | 5 | 4 (-20%) | TP 0 / FN 0 / FP 0 | TP 0 / FN 0 / FP 0 |
| `NS05` | `min_dormant_rules` | 5 | 6 (+20%) | TP 0 / FN 0 / FP 0 | TP 0 / FN 0 / FP 0 |
| `NS06` | `min_ghost_assets` | 2 | 1 (-20%) | TP 0 / FN 0 / FP 0 | TP 0 / FN 0 / FP 0 |
| `NS06` | `min_ghost_assets` | 2 | 3 (+20%) | TP 0 / FN 0 / FP 0 | TP 0 / FN 0 / FP 0 |

Not covered: EG03, NS07, NS08 have no tunable threshold (no `params` in `config/rules.yaml`): EG03 and NS07 are zero-tolerance and NS08 checks the fixed 6-month review period. A rule showing TP 0 / FN 0 has no injected defect in this dataset.