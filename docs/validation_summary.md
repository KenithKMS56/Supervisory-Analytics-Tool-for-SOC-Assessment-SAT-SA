# SAT-SA Validation Summary

> **Supervisory Notice:** *Indicators requiring supervisory review; not a compliance determination.*

> **Synthetic data only; a real-data pilot is pending.**

Primary, stress and hard sets measured on 2026-09-30; the independent-generator set re-run on
2026-10-02 on the final code of the quality pass. This page says what was tested, what the
numbers are, what they do and do not prove, and what a real-data pilot still has to supply.
Detail is in the reports it cites.

## 1. The one thing to know first

**Every number on this page comes from synthetic data.** The alerts, cases, analysts and
defects were produced by this project's own generators, by people who knew the rules'
thresholds. No alert, case or examiner finding from a real SOC has been run through SAT-SA.
These results show that the rules do what their specification says, and how they behave when
the synthetic conditions are made less convenient. They are not a measurement of accuracy on
real SOC data, and no such figure exists yet.

## 2. What was tested

| Set | What it is | Command | Report |
|---|---|---|---|
| Primary ("easy") | 10 entities, seed 42, 1,500 base alerts each, 21 defects (one or more per rule), each well over its threshold; 3 clean entities | `satsa validate` | `docs/validation_report.md` |
| Stress | 3 entities: an EG04 defect one alert over its threshold, a case that satisfies EG02 and EG04 at once, a noisy clean entity | `satsa validate-stress` | `docs/validation_stress_report.md` |
| Hard | The portfolio generator under 8 other seeds at 1,500, 600 and 300 base alerts per entity (24 runs), and the stress scenario under 20 seeds (20 runs). Kept apart from the primary set; no run uses its seed. | `python scripts/validate_hard.py` | `docs/validation_hard_report.md` |
| Independent generator | A second generator written from the documentation only (no shared code with the first): 20 seeds x 15 entities, different names, volumes and timing, defects built 1.08-1.9x over threshold and **decoys built just under it**; compared with three one-line baselines and with each rule family removed | `satsa validate-independent --seeds 20` | `docs/validation_independent_report.md` |
| Threshold sweep | Every tunable threshold moved by -20% and +20%, one at a time, in every run above | part of each command | Section 7 of the first two reports; Section 3 of the hard report; Section 5 of the independent report |
| Shadow-pilot rehearsal | The shadow-pilot evaluation run on a stand-in workpaper built from the generator's ground truth | `python scripts/build_shadow_standin.py`, then `satsa validate --shadow-csv ...` | `docs/validation_report.md` Section 5 |
| Product exports | Hand-built Splunk ES, ServiceNow SIR and TheHive 5 sample exports, ingested and assessed | `tests/test_connectors.py` | `docs/connectors.md` |

## 3. Results

### 3.1 Primary set (one seed, large margins)

| Measure | Result |
|---|---|
| Injected defects detected | 21 of 21 |
| Findings that are not an injected defect | 0 of 21 |
| Entity ranking, top 7 | 7 of 7 defect-bearing entities |
| Threshold sweep | 4 of 66 moves change an outcome |
| Review-queue lift over random sampling | 19.5x in the top 25 queue alerts, 12.0x in the top 50, 5.2x over the whole 130-alert queue |

A perfect score here is expected by construction. It confirms the code implements its rules.

### 3.2 Hard set: other seeds and lower volumes (24 portfolio runs, 504 injected defects)

| Base alerts per entity | Recall (95% CI) | Precision (95% CI) | Clean entities flagged |
|---|---|---|---|
| 1,500 | 100.0% (168/168; 97.8%-100.0%) | 100.0% (168/168; 97.8%-100.0%) | 0 of 24 |
| 600 | 100.0% (167/167; 97.8%-100.0%) | 100.0% (167/167; 97.8%-100.0%) | 0 of 24 |
| 300 | 100.0% (168/168; 97.8%-100.0%) | 100.0% (168/168; 97.8%-100.0%) | 0 of 24 |
| **All 24 runs** | **100.0% (503/503)** | **100.0% (503/503)** | **0 of 72** |

**Before the root-cause fixes** the same 24 runs gave recall 99.6% (502/504) and precision
98.0% (502/512): 10 EG10 false positives on CSE-07, one EG09 miss and one EG03 miss (both seed
808). All three traced to the **generator**, not to a rule or a threshold:

- **EG10 on CSE-07.** The "month-end bulk closure" injection stamped the first 15 CSE-07 alerts
  as closed on 31 March whatever their creation date, so some closed up to 90 days before they
  were raised (-130,000 minutes) and others months after. One to six such alerts swung the
  entity's mean closure time by hundreds of minutes, so EG10 fired or not by seed. The
  CSE-09 repeat-alert injection also drew creation and closure hours independently, so some
  closed before they were created. Both now produce possible timestamps.
- **EG09 @ 808.** "Four cases left open since spring" picked cases by id; two had been opened
  1 and 7 days before period end, so only two were stale and the threshold is three. The rule
  was right. The injection now picks the four opened earliest.
- **EG03 @ 808, 600 alerts.** The injection touched no critical true-positive alert, yet the
  ground truth still listed the defect. It is now recorded only when something was injected,
  which is why the 600-alert total is 167, not 168.

One rule change came with it: **EG01 and EG10 ignore alerts closed before they were created**
(and so do the KPI reconciliation view and the metrics engine). Real exports with clock skew
contain such records; they are already reported by the `close_before_create` data-quality
check, and a negative duration is not a closure time. Tested in `tests/test_edge_paths.py`.
No threshold was changed.

Per rule, 8 defects per volume is a small sample: a rule with 8 of 8 detected has a 95%
interval of 67.6% to 100%. The per-rule tables say "no failure seen in 8", not "reliable".

### 3.3 Hard set: stress scenario under 20 seeds (60 injected defects)

| Measure | Result (95% CI) |
|---|---|
| Recall | 100.0% (60/60; 94.0%-100.0%) |
| Precision | 93.8% (60/64; 85.0%-97.5%) |
| Runs in which the noisy clean entity was flagged | 4 of 20 (20.0%; 8.1%-41.6%) |

All four false positives are **EG05 (repeat alerts without root cause) on the clean entity**.
The entity is built with one untuned pair repeating 9 times (EG05 needs two such pairs). Under
seeds 3, 10, 14 and 15 one of its random (asset, rule) pairs also reaches exactly 8 repeats,
all benign and never tuned, so the entity has two and the rule fires. This is the rule working
as specified at the edge of its chance model, not a generator fault. Removing it would mean
changing `min_unaddressed_pairs`, `min_repeat_count` or `max_chance_pairs`; that was not done,
because the only data to judge it on is the data it would be tuned to. The single published
stress seed (9901) happens to be one where it does not fire.

### 3.4 Fragile thresholds

A threshold is fragile when moving it 20% changes what its rule detects.

| Rule and threshold | What the sweep showed |
|---|---|
| EG05 `min_unaddressed_pairs` | +20% loses the defect in 24 of 24 portfolio runs; -20% adds 8 false positives across 5 portfolio runs and 16 across 16 of 20 stress runs. The most fragile threshold in the rule set, in both directions. |
| EG07 `min_closures_per_analyst_hour` | +20% loses the defect in 24 of 24 runs: the injected burst is 35 closures against a threshold of 30. |
| NS05 `max_dormant_share` | +20% loses the defect in 24 of 24 runs. |
| NS08 `review_period_months` | -20% (6 to 5 months) loses the defect in 24 of 24 runs: the injected gap is one month. |
| EG04 `max_comment_hash_share`, `min_hash_group_size` | +20% loses the stress defects in 20 of 20 runs (they are built one alert over the threshold). |
| EG12 `min_skipped_cases`, NS03 `max_robust_z`, EG05 `min_repeat_count` | each changes an outcome in 1 of 24 runs. |

EG09 `min_stale_cases` was fragile (4 of 24) only while its injected cases were not all stale.

These say where the synthetic defects sit relative to the thresholds. They do not say the
thresholds are right: that needs real data. **No threshold was changed in this pass.**

### 3.5 Shadow-pilot rehearsal

122 workpaper rows, 47 marked confirmed: finding recall 100% (47/47), precision 100%, and
59.6% (28/47) of the confirmed records appear in the review queue. The stand-in workpaper is
derived from the generator's ground truth, so this shows the evaluation pipeline works end to
end and reports per-rule figures with intervals. It is **not** independent evidence: the
"examiner" is the generator.

### 3.6 Found by running something closer to real data

Running hand-built product exports through the tool found four defects that no synthetic set
had shown, because the synthetic data never contained the conditions:

- EG02 and EG04 counted alerts that were still open as closures (the synthetic sets have no
  open alerts). On the Splunk-style sample EG02 reported 59 of 198 instead of 36 of 164.
- Analyst names were stored unpseudonymised when a source had no closer-type column.
- Raw closure comments and unknown source columns were written to the Parquet store.
- Comment shingles were stored as readable words.

All four are fixed and tested. The point for validation is that **the first contact with
realistic exports found rule and privacy defects at once**; a real pilot should be expected to
find more.

### 3.7 Independent generator (20 seeds, 487 defects, 245 decoys)

`satsa validate-independent --seeds 20 --start-seed 1`, re-run on 2026-10-02 (409 s); every
result was the same as in its first run on 2026-10-01 (only timings differ).

| Measure | Result (95% CI) |
|---|---|
| Recall | 100.0% (487/487; 99.2-100.0%) |
| Precision | 100.0% (487/487; 99.2-100.0%) |
| Decoys flagged (built just under a threshold) | 0 of 245 (0.0-1.5%) |
| Clean entities flagged | 0 of 57 (0.0-6.3%) |
| Entity ranking precision@k | 100.0% (243/243) |

- **Against one-line baselines** on the same data, each baseline ties its rule on recall and
  loses on precision: fast closures 87.0% (EG01: 100%), short comments 76.9% (EG02: 100%),
  critical alerts without escalation 6.7% (EG03: 100%). Ranking entities by baseline flags gives
  precision@k 81.8%, against 100% for the engine.
- **Ablation:** without the execution-gap rules recall falls to 40.7%; without the
  negative-space rules, to 59.3%. Neither family is redundant on this data.
- **Threshold sweep:** NS08 `review_period_months` -20% loses every defect (20 of 20 seeds);
  EG05 `min_unaddressed_pairs`, EG08, EG12, NS04 and NS06 add false alarms in 14 to 17 of 20
  seeds when lowered 20%. `docs/threshold_rationale.md` discusses them; no threshold was changed.
- **Relabelled by the documented criterion:** for EG05, EG11 and NS03 some entities built
  without a defect met the documented criterion by chance (1, 9 and 8 times). They count as
  defects, because the rule is right to flag them under its own specification.

What it adds to the sets above: data whose shape the rule authors did not choose for the
original generator, and defects placed just under the thresholds as well as over them. What it
does not add: independence of mind. The same AI-assisted team wrote it after reading the rule
code, so 100% here means the code does what its documentation says, not that it is accurate.

## 4. What these numbers do and do not prove

**They do show:**

- Each of the 20 rules fires on a defect built for it and stays quiet otherwise across 25
  seeds and three volumes, with one exception (EG05 on the noisy stress entity), and on a
  second, separately written generator across 20 more seeds, including decoys built just under
  each threshold.
- The 20-rule engine is more precise than one-line rules testing the same ideas, on the same
  synthetic data (Section 3.7).
- Results are reproducible: same data and configuration, same findings (no rule reads the
  clock; the assessment date is recorded).
- Where the rules are closest to failing: EG05's thresholds, EG07's and NS05's margins.
- That a generator can be wrong. Three of the four hard-set failures were impossible or
  missing injected records, found only by tracing each failure to its records.

**They do not show:**

- **Accuracy on real SOC data.** Real alerts have missing fields, inconsistent dispositions,
  tool-specific workflows and defects nobody has injected. None of that is in a generator.
- **That the thresholds are right.** They were chosen by the authors and the synthetic defects
  were built around them.
- **That a finding means a real weakness.** No examiner has judged a SAT-SA finding against a
  real SOC's records.
- **The false-positive rate an examiner would see.** The synthetic clean entities are cleaner
  than a real SOC; the noisy one was flagged in 20% of seeds.
- **Recall for defect types nobody thought of.** Recall is measured only against the 21 defect
  types the generator knows.

## 5. What a real-data pilot still needs

1. **Real submissions**: alert, case, workflow and escalation exports from at least a handful
   of CSEs covering a full review period, through the connectors or the canonical layout.
2. **Independent examiner findings** for the same entities and period, recorded before the
   examiners see SAT-SA's output (the shadow-pilot workpaper, `docs/shadow_pilot_runbook.md`).
3. **Adjudication of every SAT-SA finding** as confirmed, not confirmed or undetermined, so
   precision is measured on all findings and not only on those the examiners had already made.
4. **Enough cases per rule** for the intervals to mean something: at 8 observations a perfect
   score still allows a true rate below 70%.
5. **Threshold review on that data**, with a held-out portion, and any change logged with
   before-and-after figures.
6. **Connector verification against live exports** of each product in use.

Until that is done, SAT-SA's accuracy on real data is unknown.
