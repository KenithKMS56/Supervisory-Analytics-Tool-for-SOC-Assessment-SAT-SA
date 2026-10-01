# SAT-SA Validation on an Independent Generator

> **Supervisory Notice:** *Indicators requiring supervisory review; not a compliance determination.*

> **Synthetic data only; a real-data pilot is still pending.** This is a second synthetic
> generator, written separately from the first; it is not real SOC data.

Generated 2026-10-01 by:

```
satsa validate-independent --seeds 20 --start-seed 1
```

Generator `independent/1` (`src/satsa/synth/independent.py`), 20 seeds (1-20), 15 entities per seed. Python 3.11.16. Every number below is computed by that command from those runs.

## 1. How the data was built

The generator was written from the rule descriptions in README.md and
docs/analytics_methodology.md Section 3 and the thresholds stated there; it imports nothing
from the original generator or the rules. Per seed: 15 entities `ORG-A`..`ORG-O` (every
sector at every size band), April-September 2026, 350-3,500 alerts each (lognormal), 4-22
analysts each, every rule's defect placed on a random entity and built 1.08-1.9x over its
documented threshold, a **decoy** for most rules built just under it on another entity, a
three-entity systemic group and a two-entity systemic decoy. EG11 has two documented forms
and is built in either, chosen per seed: no true positives at all, or a skewed
false-positive rate with a few true positives (1-2.5% of alerts), which only the robust-z
branch can catch. For NS03, EG11 and EG05 the generator then computes each rule's
documented criterion on the data it built and labels the ground truth by it (Section 6).

## 2. Engine results (all seeds pooled, 95% Wilson intervals)

| Measure | Result |
|---|---|
| Recall (defects detected) | 100.0% (487/487; 95% CI 99.2-100.0%) |
| Precision (findings that are a defect) | 100.0% (487/487; 95% CI 99.2-100.0%) |
| Decoys flagged (built just under a threshold) | 0.0% (0/245; 95% CI 0.0-1.5%) |
| False positives not on a decoy | 0 |
| Clean entities flagged by any rule | 0.0% (0/57; 95% CI 0.0-6.3%) |
| Entity ranking precision@k (k = defect entities) | 100.0% (243/243; 95% CI 98.4-100.0%) |

### Per rule

| Rule | Detected | Recall (95% CI) | False positives | Precision (95% CI) | Decoys flagged |
|---|---:|---|---:|---|---|
| EG01 | 20/20 | 100.0% (20/20; 95% CI 83.9-100.0%) | 0 | 100.0% (20/20; 95% CI 83.9-100.0%) | 0/14 |
| EG02 | 20/20 | 100.0% (20/20; 95% CI 83.9-100.0%) | 0 | 100.0% (20/20; 95% CI 83.9-100.0%) | 0/16 |
| EG03 | 20/20 | 100.0% (20/20; 95% CI 83.9-100.0%) | 0 | 100.0% (20/20; 95% CI 83.9-100.0%) | 0/0 |
| EG04 | 20/20 | 100.0% (20/20; 95% CI 83.9-100.0%) | 0 | 100.0% (20/20; 95% CI 83.9-100.0%) | 0/16 |
| EG05 | 26/26 | 100.0% (26/26; 95% CI 87.1-100.0%) | 0 | 100.0% (26/26; 95% CI 87.1-100.0%) | 0/8 |
| EG06 | 20/20 | 100.0% (20/20; 95% CI 83.9-100.0%) | 0 | 100.0% (20/20; 95% CI 83.9-100.0%) | 0/16 |
| EG07 | 20/20 | 100.0% (20/20; 95% CI 83.9-100.0%) | 0 | 100.0% (20/20; 95% CI 83.9-100.0%) | 0/12 |
| EG08 | 36/36 | 100.0% (36/36; 95% CI 90.4-100.0%) | 0 | 100.0% (36/36; 95% CI 90.4-100.0%) | 0/14 |
| EG09 | 20/20 | 100.0% (20/20; 95% CI 83.9-100.0%) | 0 | 100.0% (20/20; 95% CI 83.9-100.0%) | 0/19 |
| EG10 | 20/20 | 100.0% (20/20; 95% CI 83.9-100.0%) | 0 | 100.0% (20/20; 95% CI 83.9-100.0%) | 0/16 |
| EG11 | 28/28 | 100.0% (28/28; 95% CI 87.9-100.0%) | 0 | 100.0% (28/28; 95% CI 87.9-100.0%) | 0/1 |
| EG12 | 39/39 | 100.0% (39/39; 95% CI 91.0-100.0%) | 0 | 100.0% (39/39; 95% CI 91.0-100.0%) | 0/17 |
| NS01 | 20/20 | 100.0% (20/20; 95% CI 83.9-100.0%) | 0 | 100.0% (20/20; 95% CI 83.9-100.0%) | 0/13 |
| NS02 | 20/20 | 100.0% (20/20; 95% CI 83.9-100.0%) | 0 | 100.0% (20/20; 95% CI 83.9-100.0%) | 0/0 |
| NS03 | 33/33 | 100.0% (33/33; 95% CI 89.6-100.0%) | 0 | 100.0% (33/33; 95% CI 89.6-100.0%) | 0/9 |
| NS04 | 20/20 | 100.0% (20/20; 95% CI 83.9-100.0%) | 0 | 100.0% (20/20; 95% CI 83.9-100.0%) | 0/16 |
| NS05 | 20/20 | 100.0% (20/20; 95% CI 83.9-100.0%) | 0 | 100.0% (20/20; 95% CI 83.9-100.0%) | 0/17 |
| NS06 | 20/20 | 100.0% (20/20; 95% CI 83.9-100.0%) | 0 | 100.0% (20/20; 95% CI 83.9-100.0%) | 0/16 |
| NS07 | 45/45 | 100.0% (45/45; 95% CI 92.1-100.0%) | 0 | 100.0% (45/45; 95% CI 92.1-100.0%) | 0/13 |
| NS08 | 20/20 | 100.0% (20/20; 95% CI 83.9-100.0%) | 0 | 100.0% (20/20; 95% CI 83.9-100.0%) | 0/12 |

### Recall by how far over the threshold a defect was built (EG01, EG02, EG04, NS05)

| Built at (x threshold) | Detected |
|---|---|
| 1.08-1.30 | 100.0% (20/20; 95% CI 83.9-100.0%) |
| 1.30-1.60 | 100.0% (36/36; 95% CI 90.4-100.0%) |
| 1.60-1.90 | 100.0% (24/24; 95% CI 86.2-100.0%) |

### Systemic (cross-entity) detector

Expected groups detected: 20 of 20. Systemic decoy pairs (2 entities, below the 3-entity minimum) flagged: 0 of 20. Other systemic findings: 0.

## 3. Naive baselines on the same data

Each baseline is one fixed threshold on one metric (`src/satsa/validate/baselines.py`), scored
against the ground truth of the engine rule that tests the same idea.

| Baseline | Compared with | Baseline recall | Baseline precision | Baseline decoys flagged | Engine recall | Engine precision | Engine decoys flagged |
|---|---|---|---|---|---|---|---|
| `fast_closure` (human High/Critical closed within 10 min > 10%) | EG01 | 100.0% (20/20; 95% CI 83.9-100.0%) | 87.0% (20/23; 95% CI 67.9-95.5%) | 3 | 100.0% (20/20; 95% CI 83.9-100.0%) | 100.0% (20/20; 95% CI 83.9-100.0%) | 0 |
| `short_comment` (human closures with comment < 25 chars > 10%) | EG02 | 100.0% (20/20; 95% CI 83.9-100.0%) | 76.9% (20/26; 95% CI 58.0-89.0%) | 6 | 100.0% (20/20; 95% CI 83.9-100.0%) | 100.0% (20/20; 95% CI 83.9-100.0%) | 0 |
| `no_escalation` (any Critical alert without an escalation) | EG03 | 100.0% (20/20; 95% CI 83.9-100.0%) | 6.7% (20/300; 95% CI 4.4-10.1%) | 0 | 100.0% (20/20; 95% CI 83.9-100.0%) | 100.0% (20/20; 95% CI 83.9-100.0%) | 0 |

- `fast_closure` vs EG01: the baseline **ties** on recall and **loses** on precision.
- `short_comment` vs EG02: the baseline **ties** on recall and **loses** on precision.
- `no_escalation` vs EG03: the baseline **ties** on recall and **loses** on precision.

Entity ranking by number of baseline flags (ties averaged): precision@k 81.8% (198.9/243; 95% CI 76.6-86.2%); engine: 100.0% (243/243; 95% CI 98.4-100.0%).

## 4. Ablation: one rule family removed

The same stores, scored again without one family (dry run). Defects of the removed family
count as missed. Removing the systemic detector changes no per-entity finding; its own
result is in Section 2.

| Configuration | Recall | Precision | False positives | Clean entities flagged | Ranking precision@k |
|---|---|---|---:|---|---|
| All 20 rules | 100.0% (487/487; 95% CI 99.2-100.0%) | 100.0% (487/487; 95% CI 99.2-100.0%) | 0 | 0/57 | 100.0% (243/243; 95% CI 98.4-100.0%) |
| Without Execution gaps (EG01-EG12) | 40.7% (198/487; 95% CI 36.4-45.1%) | 100.0% (198/198; 95% CI 98.1-100.0%) | 0 | 0/57 | 86.3% (209.7/243; 95% CI 81.5-90.2%) |
| Without Negative space (NS01-NS08) | 59.3% (289/487; 95% CI 54.9-63.6%) | 100.0% (289/289; 95% CI 98.7-100.0%) | 0 | 0/57 | 90.6% (220.2/243; 95% CI 86.2-93.6%) |

## 5. Threshold sweep (+/-20%, one threshold at a time)

For each tunable threshold, in how many seeds a 20% move changed which entities the rule flags,
and how many defects it lost and false alarms (decoys included) it added in total.

| Rule | Threshold | Move | Seeds changed | Defects lost | False alarms added |
|---|---|---|---:|---:|---:|
| EG01 | `fast_share_threshold` | +20% | 5 of 20 | 5 | 0 |
| EG02 | `max_uninvestigated_share` | +20% | 4 of 20 | 4 | 0 |
| EG04 | `max_comment_hash_share` | +20% | 1 of 20 | 1 | 0 |
| EG04 | `min_hash_group_size` | -20% | 4 of 20 | 0 | 4 |
| EG05 | `max_chance_pairs` | +20% | 1 of 20 | 0 | 1 |
| EG05 | `max_chance_pairs` | -20% | 1 of 20 | 1 | 0 |
| EG05 | `min_repeat_count` | +20% | 6 of 20 | 8 | 0 |
| EG05 | `min_repeat_count` | -20% | 2 of 20 | 0 | 2 |
| EG05 | `min_unaddressed_pairs` | +20% | 10 of 20 | 13 | 0 |
| EG05 | `min_unaddressed_pairs` | -20% | 14 of 20 | 0 | 18 |
| EG06 | `min_bulk_closures_per_minute` | +20% | 6 of 20 | 6 | 0 |
| EG06 | `min_bulk_closures_per_minute` | -20% | 10 of 20 | 0 | 10 |
| EG07 | `min_closures_per_analyst_hour` | +20% | 5 of 20 | 5 | 0 |
| EG07 | `min_closures_per_analyst_hour` | -20% | 3 of 20 | 0 | 3 |
| EG08 | `min_unacknowledged_escalations` | +20% | 9 of 20 | 11 | 0 |
| EG08 | `min_unacknowledged_escalations` | -20% | 14 of 20 | 0 | 14 |
| EG09 | `min_stale_cases` | +20% | 6 of 20 | 6 | 0 |
| EG09 | `min_stale_cases` | -20% | 10 of 20 | 0 | 10 |
| EG10 | `mttr_gap_ratio_threshold` | +20% | 1 of 20 | 1 | 0 |
| EG11 | `max_robust_z` | +20% | 6 of 20 | 6 | 0 |
| EG11 | `max_robust_z` | -20% | 5 of 20 | 0 | 6 |
| EG11 | `min_spread` | +20% | 3 of 20 | 3 | 0 |
| EG11 | `min_spread` | -20% | 3 of 20 | 0 | 3 |
| EG12 | `min_skipped_cases` | +20% | 8 of 20 | 10 | 0 |
| EG12 | `min_skipped_cases` | -20% | 17 of 20 | 0 | 17 |
| NS01 | `min_asset_criticality` | +20% | 15 of 20 | 15 | 0 |
| NS01 | `min_asset_criticality` | -20% | 2 of 20 | 0 | 2 |
| NS01 | `min_silent_days` | +20% | 1 of 20 | 1 | 0 |
| NS01 | `min_silent_days` | -20% | 7 of 20 | 0 | 7 |
| NS03 | `max_robust_z` | +20% | 4 of 20 | 4 | 0 |
| NS03 | `max_robust_z` | -20% | 6 of 20 | 0 | 6 |
| NS03 | `min_spread` | +20% | 3 of 20 | 3 | 0 |
| NS03 | `min_spread` | -20% | 1 of 20 | 0 | 1 |
| NS04 | `min_tp_without_case` | +20% | 8 of 20 | 8 | 0 |
| NS04 | `min_tp_without_case` | -20% | 16 of 20 | 0 | 16 |
| NS05 | `max_dormant_share` | +20% | 8 of 20 | 8 | 0 |
| NS06 | `min_ghost_assets` | +20% | 4 of 20 | 4 | 0 |
| NS06 | `min_ghost_assets` | -20% | 16 of 20 | 0 | 16 |
| NS08 | `review_period_months` | -20% | 20 of 20 | 20 | 0 |

Moves not listed changed nothing in any seed.

## 6. Ground truth relabelled by the documented criterion

| Rule: built as -> labelled | Times |
|---|---:|
| EG05: baseline -> defect | 1 |
| EG05: decoy -> defect | 5 |
| EG11: baseline -> defect | 9 |
| EG11: defect -> decoy | 1 |
| NS03: baseline -> defect | 8 |
| NS03: decoy -> defect | 5 |

A *baseline -> defect* row means an entity that nobody built a defect into meets the
documented criterion by chance. These count as defects in Section 2: the rule is right to
flag them under its own specification, which says something about the specification
(`docs/threshold_rationale.md`).

## 7. Per seed

| Seed | Defects | Decoys | Detected | False positives | Missed | Seconds |
|---:|---:|---:|---:|---:|---|---:|
| 1 | 24 | 10 | 24 | 0 | - | 37.2 |
| 2 | 23 | 14 | 23 | 0 | - | 33.6 |
| 3 | 24 | 15 | 24 | 0 | - | 33.7 |
| 4 | 25 | 15 | 25 | 0 | - | 33.2 |
| 5 | 24 | 11 | 24 | 0 | - | 31.3 |
| 6 | 25 | 11 | 25 | 0 | - | 31.8 |
| 7 | 26 | 12 | 26 | 0 | - | 31.9 |
| 8 | 24 | 12 | 24 | 0 | - | 31.0 |
| 9 | 26 | 12 | 26 | 0 | - | 31.3 |
| 10 | 25 | 10 | 25 | 0 | - | 29.8 |
| 11 | 23 | 12 | 23 | 0 | - | 24.8 |
| 12 | 24 | 15 | 24 | 0 | - | 32.3 |
| 13 | 24 | 14 | 24 | 0 | - | 33.2 |
| 14 | 25 | 12 | 25 | 0 | - | 34.3 |
| 15 | 23 | 11 | 23 | 0 | - | 34.2 |
| 16 | 24 | 11 | 24 | 0 | - | 32.1 |
| 17 | 23 | 13 | 23 | 0 | - | 32.5 |
| 18 | 25 | 15 | 25 | 0 | - | 34.1 |
| 19 | 25 | 8 | 25 | 0 | - | 32.0 |
| 20 | 25 | 12 | 25 | 0 | - | 31.0 |

False positives per seed: 1: -; 2: -; 3: -; 4: -; 5: -; 6: -; 7: -; 8: -; 9: -; 10: -; 11: -; 12: -; 13: -; 14: -; 15: -; 16: -; 17: -; 18: -; 19: -; 20: -

## 8. What this does and does not prove

**It does show:**

- Whether the rules, as implemented, flag the conditions their documentation describes when the
  data comes from a generator written from that documentation rather than from the rule code:
  different entity names, volumes, mixes, timing and defect sizes, chosen per seed.
- How the rules behave just under their thresholds (decoys), not only well over them.
- Whether the 20-rule engine does better than one-line rules on the same data, and what each rule
  family contributes (Sections 3 and 4).
- Where documentation and code disagree: a rule whose recall or precision falls short here either
  has a defect or a specification that does not say what the code does.

**It does not show:**

- **Accuracy on real SOC data.** Both generators are synthetic. Real submissions have missing
  fields, tool-specific workflows and defects nobody wrote down.
- **Independence of mind.** The generator was written by the same AI-assisted team that wrote the
  rules, in a session that had read the rule code. It is independent of the original generator's
  code, not of knowledge of the thresholds. Where the documentation was silent about a column
  (for example which closure column holds the comment length), the canonical schema was used.
- **That the thresholds are right.** Decoys sit just under the documented thresholds; whether those
  thresholds separate good and poor SOC practice is a question for real data
  (`docs/threshold_rationale.md`).
- **The base rate of defects.** Every seed carries at least one defect for every rule, far more
  than a real portfolio would; precision on real data would differ.
- **Recall for defect types outside the rule catalogue.** The generator builds only what the
  documentation describes.

