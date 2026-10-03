# Threshold Rationale: EG04, EG05, EG07, NS05, NS08 (and EG11)

> **Synthetic data only; a real-data pilot is still pending.** Nothing here changes `config/`.
> Every option below is a **proposal** for the people who own the thresholds. Each one has been
> evaluated on the independent synthetic set only, and none has been applied.

## Sources (both run on 2026-10-01, seeds 1-20, 15 entities per seed = 300 entity-seeds)

- **[V]** `uv run satsa validate-independent --seeds 20 --start-seed 1`, which produces
  `docs/validation_independent_report.md` (engine results, the ±20% sweep in Section 5, the
  relabelled ground truth in Section 6). Add `--output-json FILE` for the per-seed raw results.
- **[P]** `uv run python scripts/threshold_probe.py --seeds 20`. On the same scenarios, it computes
  the quantity each rule compares with its threshold, per entity, using the rule's own SQL. It
  labels each value defect, decoy or neither (from the generator's ground truth), then counts
  flags at a few candidate values. At every current value it reproduces the engine's result in
  [V]: all defects flagged, no decoys flagged and no other entities flagged. That agreement is
  the check that the probe and the engine compute the same thing.

## Read this first: what the independent set can and cannot say about a threshold

The independent generator builds each defect **1.08-1.9x over** the documented threshold and
each decoy **0.4-0.8x of** it. The gap between defects and decoys is therefore partly put there
by construction, so a threshold anywhere in that gap scores perfectly here. What the set *can*
show:

1. how far a threshold can move before it starts losing built defects or flagging decoys;
2. whether healthy entities ever come close to the threshold by chance;
3. where a parameter does not behave like a sensitivity knob at all (NS08);
4. where the documented criterion flags entities nobody built a defect into (EG05, EG11, NS03).

What it cannot show is where good and poor SOC practice actually separate. That needs real
submissions: the distribution of each statistic across real entities, plus examiner judgement on
a sample. Point 2 has a further caveat: healthy entities in this generator are cleaner than real
SOCs. They have no boilerplate comments and no dormant detection rules.

## EG04 Template-driven investigations: `max_comment_hash_share` 0.25 (`min_hash_group_size` 10)

**Statistic:** the share of human closures whose normalised comment hash is in a group of 10 or
more.

| Population [P] | n | min | median | max |
|---|---:|---:|---:|---:|
| Built defects | 20 | 0.278 | 0.393 | 0.463 |
| Decoys | 16 | 0.000 | 0.139 | 0.184 |
| All other entities | 264 | 0.000 | 0.000 | 0.000 |

| `max_comment_hash_share` [P] | Defects flagged | Decoys flagged | Others flagged |
|---|---|---|---|
| 0.15 | 20/20 | 7/16 | 0/264 |
| 0.20 | 20/20 | 0/16 | 0/264 |
| **0.25 (current)** | 20/20 | 0/16 | 0/264 |
| 0.30 | 19/20 | 0/16 | 0/264 |
| 0.35 | 17/20 | 0/16 | 0/264 |

Sweep [V]: moving the share by +20% lost 1 defect (in 1 of 20 seeds), and -20% changed nothing.
Moving **`min_hash_group_size`** by -20% (to 8) added 4 false alarms in 4 seeds.

**Reading.** The share has room between 0.20 and 0.25 here. On this data the group size is the
more sensitive of the two parameters: a smaller group turns ordinary repeats into "boilerplate".
The group size is a fixed count, so an entity with more human closures reaches it more easily.
Healthy entities here have no repeated comments at all, while real SOCs use closure macros, so
the 0.000 median for healthy entities is not evidence about real data.

**Proposals (not applied):**
- Keep 0.25.
- Before any change, measure the share on real submissions with known macro use; the README's
  benign explanation ("mandatory standardized dropdown resolution codes") is exactly the case a
  real distribution would reveal.
- Consider stating `min_hash_group_size` relative to the human-closure volume (for example a
  share of it, with a floor of 10). This has *not* been evaluated: it would need a code change,
  which this pass does not make.

## EG05 Repeat alerts without root cause: `min_unaddressed_pairs` 2

**Statistic:** the number of (asset, rule) pairs that repeat at least *k* times, are always closed
benign/false positive and have no remediation record. *k* is the larger of 8 and the entity's
chance level.

| Population [P] | n | min | median | max |
|---|---:|---:|---:|---:|
| Defects | 26 | 2 | 2.5 | 4 |
| Decoys (built with one pair) | 8 | 1 | 1 | 1 |
| All other entities | 266 | 0 | 0 | 1 |

| `min_unaddressed_pairs` [P] | Defects flagged | Decoys flagged | Others flagged |
|---|---|---|---|
| 1 | 26/26 | 8/8 | **10/266** |
| **2 (current)** | 26/26 | 0/8 | 0/266 |
| 3 | 13/26 | 0/8 | 0/266 |
| 4 | 6/26 | 0/8 | 0/266 |

Relabelled ground truth [V §6]: 5 decoys built with one qualifying pair picked up a second pair
by chance and meet the documented criterion, and 1 untouched entity met it by chance (6 of 300
entity-seeds).

**Reading.** The chance-level repeat floor does not stop isolated chance pairs: 10 of 266
non-defect entities (3.8%) had exactly one qualifying pair [P]. Requiring two pairs is what keeps
them out. Requiring three would miss half of the defects built here (13/26 flagged). Six
entities reached two pairs by chance [V §6], so even two pairs is not proof of neglect. The
finding's own examiner check, a review of tuning tickets, is the right safeguard.

**Proposal (not applied):** keep 2. Revisit only with real data on how many always-benign
repeating pairs a well-run SOC carries.

## EG07 Analyst implausibility: `min_closures_per_analyst_hour` 30

**Statistic:** the most human closures by one analyst in one clock hour.

| Population [P] | n | min | median | max |
|---|---:|---:|---:|---:|
| Defects | 20 | 31 | 40 | 45 |
| Decoys | 12 | 20 | 23 | 26 |
| All other entities | 268 | 1 | 2 | 14 |

| `min_closures_per_analyst_hour` [P] | Defects flagged | Decoys flagged | Others flagged |
|---|---|---|---|
| 15 | 20/20 | 12/12 | 0/268 |
| 20 | 20/20 | 12/12 | 0/268 |
| 25 | 20/20 | 2/12 | 0/268 |
| **30 (current)** | 20/20 | 0/12 | 0/268 |
| 36 | 15/20 | 0/12 | 0/268 |
| 40 | 11/20 | 0/12 | 0/268 |

Sweep [V]: +20% lost 5 defects (5 seeds); -20% added 3 false alarms (3 seeds).

**Reading.** 30 an hour is one closure every two minutes sustained for an hour. On this data no
healthy analyst-hour exceeded 14, so the rule has a wide margin against normal work. That margin
is the generator's assumption, though. A shift catch-up (the README's first benign explanation)
or bulk closure of a known false-positive storm can produce 25-30 legitimate closures in an hour,
and the threshold sits just above the decoys built to look like that.

**Proposals (not applied):**
- Keep 30.
- A complementary, peer-relative form (robust z of the analyst-hour maximum against the entity's
  own analysts) would adapt to tooling that legitimately speeds triage. This has not been
  evaluated: it needs a code change.

## NS05 Rule coverage gaps: `max_dormant_share` 0.40 (`min_dormant_rules` 5)

**Statistic:** the share of enabled detection rules that never fired in the period.

| Population [P] | n | min | median | max |
|---|---:|---:|---:|---:|
| Defects | 20 | 0.436 | 0.505 | 0.605 |
| Decoys | 17 | 0.147 | 0.214 | 0.269 |
| All other entities | 263 | 0.000 | 0.000 | 0.000 |

| `max_dormant_share` [P] | Defects flagged | Decoys flagged | Others flagged |
|---|---|---|---|
| 0.25 | 20/20 | 5/17 | 0/263 |
| 0.30 | 20/20 | 0/17 | 0/263 |
| 0.35 | 20/20 | 0/17 | 0/263 |
| **0.40 (current)** | 20/20 | 0/17 | 0/263 |
| 0.45 | 18/20 | 0/17 | 0/263 |
| 0.50 | 10/20 | 0/17 | 0/263 |

Sweep [V]: +20% (0.48) lost 8 defects in 8 seeds; -20% changed nothing.

**Reading.** This is the threshold the synthetic data says least about. Every healthy entity
here fires every enabled rule (median dormant share 0.000). Real SIEM catalogues contain many
high-fidelity rules that rightly stay silent for months, which is the README's own benign
explanation. On real data, 0.40 could flag a large part of a portfolio, or it could be right. This
set cannot tell which.

**Proposals (not applied):**
- Keep 0.40 for now.
- In the real-data pilot, report the dormant-share distribution across entities before reading
  any NS05 finding.
- Consider excluding rules created during the period, which have had less time to fire. This has
  not been evaluated; it needs a code change.

## NS08 Submission completeness: `review_period_months` 6

**Statistic:** the months covered by the entity's alerts, against `min(review_period_months,
months the portfolio covers)`.

| Population [P] | n | Months covered |
|---|---:|---|
| Defects (one month withheld) | 20 | 5 (all) |
| Decoys | 12 | 6 (all) |
| All other entities | 268 | 6 (all) |

| `review_period_months` [P] | Defects flagged | Decoys flagged | Others flagged |
|---|---|---|---|
| 3 | 0/20 | 0/12 | 0/268 |
| 4 | 0/20 | 0/12 | 0/268 |
| 5 | 0/20 | 0/12 | 0/268 |
| **6 (current)** | 20/20 | 0/12 | 0/268 |
| 12 | 20/20 | 0/12 | 0/268 |

Sweep [V]: -20% lost all 20 defects in all 20 seeds; +20% changed nothing.

**Reading.** This is not a sensitivity threshold. It is the length of the supervisory review
period:
- Set below the period actually submitted, it stops NS08 from seeing a missing month at all.
- Set above it, it has no effect, because it is capped at the months the portfolio covers. That
  cap is why 12 behaves like 6.

The ±20% sweep result is therefore expected and not a fragility. It does mean the value must
match the review cycle.

**Proposal (not applied):** document `review_period_months` as "set to the review cycle in
months", not as a tunable, and set it per assessment. The code already rejects out-of-range
values when the rule is loaded.

## EG11 Disposition extremes: `min_spread` 0.01 (added because the independent set raised it)

EG11 has two documented forms: no true positives at all, or a false-positive/benign rate with
robust z >= 3.5 against peers. The robust z uses `max(1.4826 x peer MAD, min_spread)` as the
spread, so `min_spread` decides how small a difference can count as extreme when peers agree.

**What the independent set contains [V §6, P].** 28 EG11 ground-truth defects in 300
entity-seeds. The ranges below are read from [P]'s per-defect table ("points above peer
median" is the FP/benign rate minus the median of the listed peer rates).

| Kind | n | True positives | FP/benign rate | Peer MAD | Points above peer median | Robust z |
|---|---:|---|---|---|---|---|
| Built, no true positives | 9 | 0 | 1.000 | 0.0020-0.0174 | 12.3-13.8 | 5.30-13.60 |
| Built, skewed rate | 10 | 7-32 | 0.979-0.991 | 0.0077-0.0193 | 9.8-14.8 | 3.98-12.92 |
| Met by chance (nothing built) | 9 | 61-281 | 0.882-0.916 | 0.0024-0.0093 | 3.7-5.8 | 3.62-5.79 |

One further built skewed defect fell short of the criterion and was relabelled a decoy
[V §6: "EG11: defect -> decoy 1"]; it is flagged at no value below.

| `min_spread` [P] | Defects flagged | Which | Decoys flagged | Others flagged |
|---|---|---|---|---|
| **0.01 (current)** | 28/28 | all | 0/1 | 0/271 |
| 0.02 | 19/28 | all 19 built (both forms); none of the 9 chance cases | 0/1 | 0/271 |
| 0.03 | 18/28 | loses one skewed defect (seed 4, z 3.98 at 0.01) | 0/1 | 0/271 |
| 0.05 | 9/28 | only the 9 no-true-positive defects; every skewed defect lost | 0/1 | 0/271 |

Sweep [V]: `min_spread` +20% (0.012) lost 3 chance-case defects in 3 seeds and -20% added 3
false alarms in 3 seeds; `max_robust_z` +20% lost 6 defects (6 seeds) and -20% added 6 false alarms (5 seeds).

**Reading.** With a floor of 0.01, about 3.5 points above the peer median is enough for
z >= 3.5 whenever peers agree to within a point or two, and 9 untouched entities (3% of
entity-seeds) crossed it by chance. A floor of 0.02 separates them from every built defect
here; 0.03 begins to lose skewed defects, and at 0.05 the robust-z branch catches nothing here
that the zero-true-positive branch would not. The separation at 0.02 is partly by construction: the
skewed defects were built at FP/benign rates of 0.979-0.991 against peer rates of 0.823-0.909
[P], 9.8-14.8 points above the peer median, a much wider gap than the chance cases. Peers
whose false-positive rates agree this closely are probably rare among real SOCs, where disposition practice differs between teams and tools.

**Proposal (not applied):** consider raising `min_spread` to 0.02 once real peer FP-rate spreads
are known. Evaluated here [P]: it drops all 9 chance flags, flags nothing else and keeps all 19
built defects of both forms; 0.03 already loses one. Under the current specification the 9
chance cases count as defects, so [V] would report EG11 recall falling from 28/28 to 19/28.
That is a change to the specification, not a fix to the engine. NS03 shows the same pattern:
8 untouched entities met its night-share robust-z criterion [V §6]. Its `min_spread` deserves
the same review, which has not been probed here.

## Summary

| Rule | Parameter | Current | Proposal (not applied) | Evaluated on the independent set? |
|---|---|---|---|---|
| EG04 | `max_comment_hash_share` | 0.25 | Keep; calibrate on real macro use | Yes [P]: 0.20-0.25 flag all defects and no decoys |
| EG04 | `min_hash_group_size` | 10 | Consider scaling with volume | Sweep only [V]: -20% added 4 false alarms; scaling not evaluated |
| EG05 | `min_unaddressed_pairs` | 2 | Keep | Yes [P]: 1 flags 10/266 non-defect entities, 3 misses 13/26 defects |
| EG07 | `min_closures_per_analyst_hour` | 30 | Keep; peer-relative variant later | Yes [P]: 25 flags 2/12 decoys, 36 misses 5/20 defects |
| NS05 | `max_dormant_share` | 0.40 | Keep; measure the real distribution first | Yes [P], but the healthy data here has no dormant rules |
| NS08 | `review_period_months` | 6 | Treat as the review-cycle length, not a tunable | Yes [P]: any value below 6 misses every defect |
| EG11 | `min_spread` | 0.01 | 0.02 after real spreads are known | Yes [P]: 0.02 drops the 9 chance flags and keeps all 19 built defects; 0.03 loses one skewed defect |
