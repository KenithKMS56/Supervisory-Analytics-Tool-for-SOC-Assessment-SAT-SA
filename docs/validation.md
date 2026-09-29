# SAT-SA Validation Methodology & Results

> **Supervisory Notice:** *Indicators requiring supervisory review; not a compliance determination.*

This document details SAT-SA's validation methodology and results, and is explicit about what
kind of evidence each result actually is.

---

## 0. What This Validation Is -- and Is Not

**Everything in Sections 2–4 is synthetic.** No run against real NCIIPC/CSE data has been done.
The only mode that can measure real-world accuracy is the Shadow-Pilot mode in Section 5, run on
real historical examiner workpapers.

Section 2 is a **detector-implementation correctness check**: it confirms that each rule's code
implements its own specified logic against a synthetic dataset whose injected defects are
deliberately built to clearly exceed each rule's threshold. Precision and recall near 100% there
are close to **guaranteed by construction**. They show the code does what it says, not that the
detection logic would perform well on real SOC submissions with realistic noise, borderline cases
or ambiguous evidence.

Section 2A adds a **stress scenario**: a second synthetic dataset with a borderline-threshold case,
a case ambiguous between two rules, and a noisy clean entity. It is still built against the rules'
own thresholds, so it tests threshold behaviour near the edge, not real-world accuracy.

Rule coverage: every one of the 20 rules has at least one injected defect (19 in the primary
dataset, EG02 in the stress scenario), enforced by `tests/test_validation_integrity.py`. Until
September 2026, 8 rules (EG07, EG08, EG09, EG11, EG12, NS05, NS07, NS08) had none and were only
ever shown to stay quiet. Their new defects are, like the rest of Section 2, built to clearly
exceed each threshold; only EG04 and EG02 are tested near a threshold (Section 2A).

What neither synthetic scenario covers:
- **Threshold sensitivity.** No rule threshold is perturbed (Section 4 perturbs scoring weights
  only), so nothing here says how precision and recall move as thresholds move.
- **Scale.** 21 injected (entity, rule) defects and 3 clean entities; one finding more or less moves
  precision by several points.

### 0.1 Correction: how precision was previously counted (September 2026)

Earlier versions of this document reported **100% precision** on the primary dataset and **60%**
on the stress scenario. Both figures were wrong, in opposite directions:

- **The primary 100% came from the scoring, not the detectors.** The harness counted a false
  positive only when a finding landed on one of the three clean entities, and even there exempted
  NS05, EG12 and EG10. The run behind that figure actually produced **34 findings for 13 injected
  defects**: 15 extra findings on defect entities were never examined, and 6 on clean entities were
  exempted. Counting every finding, precision was **38% (13/34)**.
- **The stress 60% came from generator artifacts, not rule noise.** Stress entities covered about
  one month of data, so NS08 (6-month submission completeness) fired on all three of them; only the
  clean entity's hit was counted. The "clean" STRESS-03 was a single asset with every alert closed
  benign and no remediation tickets, which is EG05's own defect definition, so EG05 firing there was
  a correct detection mislabelled as a false positive.

Tracing the 21 uncounted primary findings found generator bugs and one rule defect, all fixed:

| Symptom | Cause | Fix |
|---|---|---|
| NS05 (dormant rules) fired on all 10 entities | Alerts used rule IDs (`RULE-<CAT>-01..05`) outside each entity's declared rule catalog, so most catalog rules never fired | Alerts draw rule IDs from the entity's own catalog |
| EG12 (workflow non-conformance) fired on all 10 entities | The generator wrote no case workflow events, so every critical case "skipped containment" | Cases get a triage → investigate → contain → close lifecycle |
| EG02 and EG03 fired on CSE-08 (the small-entity confounder) | CSE-08's alert IDs were renumbered after their closures, workflow events and escalations were created, orphaning them | Child records follow the renumbering |
| EG10 fired on CSE-06 and CSE-08 once no longer exempt | **Rule defect:** EG10 compared empirical High+Critical MTTR with whatever severities were declared; the generator declared Critical only, so every entity sat near the threshold | EG10 compares declared severities only, weighted by alert count; the generator declares realistic High and Critical MTTR |

The harness now counts **every** finding whose (entity, rule) pair is not an injected defect as a
false positive, on any entity and for any rule, with no exemptions, and lists each one. The report
verdicts (PASS/FAIL) are computed against the targets instead of being hardcoded. Regression tests
for each fix are in `tests/test_validation_integrity.py`.

With those fixes the measured precision is 100% on both datasets (Sections 2 and 2A). **That is
not a stronger claim than before.** It shows the corrected generator and the rules agree; it is
still synthetic, still built against the rules' own thresholds, and still says nothing about real
submissions.

---

## 1. Experimental Methodology & Ground Truth Design

To evaluate the rule implementations without circular self-scoring, SAT-SA pairs with a
deterministic synthetic generator (`satsa generate-data`) that models 10 Critical Sector Entities
(CSE-01 through CSE-10) over a 6-month period across 5 critical infrastructure sectors.

### 1.1 Injected Operational Defects (Positive Cases)
Ground truth injects 21 (entity, rule) defects into 7 entities:
- **CSE-02 (Banking Large):** Declared High/Critical MTTR of 35 min against an empirical MTTR of
  roughly 45 min (critical) / 90 min (high) recomputed from its own alert timestamps $\to$ **EG10**.
- **CSE-03 (Telecom Large):** Premature rubber-stamp closures ($<240$s) $\to$ **EG01**; Critical True Positives closed without escalation $\to$ **EG03**.
- **CSE-02, CSE-05, CSE-09 (shared MSSP):** Criticality-4 assets silent for the same 15-day window $\to$ **NS01** (and the systemic cross-entity finding).
- **CSE-05 (Transport Medium):** Ghost inventory assets absent from telemetry $\to$ **NS06**.
- **CSE-07 (Banking Large):** Identical repetitive closure comments ($60\%$ share vs EG04's 25% threshold) $\to$ **EG04**; SLA deadline hugging and month-end bulk closures $\to$ **EG06**.
- **CSE-08 (Telecom Small):** Complete absence of peer threat categories (Malware, DoS, Phishing) $\to$ **NS02**; High/Critical TP alerts with no case record $\to$ **NS04**. (CSE-08 also has an injected alert-ID sequence gap; that is reported by the ingest data-quality checks, not by NS04.)
- **CSE-09 (Oil & Gas Large):** High repeat alert pairs without root-cause remediation tickets $\to$ **EG05**.
- **CSE-10 (Transport Small):** Total nighttime logging collapse (zero 24x7 coverage) and mid-period volume drop $\to$ **NS03**.

Added in September 2026 so that every rule has a positive case (each sized to cross only its own rule):
- **CSE-08:** One analyst closes 35 alerts inside a single hour (spread over distinct minutes, so not EG06's bulk pattern) $\to$ **EG07**.
- **CSE-03:** Four escalations with no Tier-2 acknowledgement $\to$ **EG08**.
- **CSE-05:** Four high-severity cases left open for months $\to$ **EG09**.
- **CSE-07:** No true positive recorded in six months (every alert closed FP/benign) $\to$ **EG11**.
- **CSE-09:** Three critical cases closed without the mandatory 'contain' stage $\to$ **EG12**; 25 enabled legacy rules that never fired (45% of its catalog) $\to$ **NS05**.
- **CSE-02:** Two critical incidents with no external NCIIPC report $\to$ **NS07**.
- **CSE-10:** No alerts submitted for June 2026 $\to$ **NS08**.

### 1.2 Clean Baselines & Controlled Confounders (Negative Cases)
- **Clean Baselines (CSE-01, CSE-04, CSE-06):** Entities operating with disciplined triage, timely escalations, balanced dispositions, and consistent 24x7 logging.
- **Confounder 1 (SOAR Automation):** 12% of closures across all entities are fast automated playbook closures (`closed_by_type='automation'`). The report counts any EG01/EG02 finding on an entity with no injected fast-closure defect.
- **Confounder 2 (Small Entity Scale):** CSE-08 and CSE-10 are small-band entities with lower alert volumes. The report counts any finding on them for a rule not injected there.

---

## 2. Detector-Implementation Correctness Results (Primary Dataset)

`satsa validate` against the ground truth in Section 1, with every finding counted (see
Section 0.1). Figures from run `RUN-20260929175400749877-b3723c48`; regenerate with
`satsa validate`, and see `docs/validation_report.md` for the per-rule table.

| Evaluation Metric | Measured Result | Benchmark Target | Verdict |
|---|---|---|---|
| **Entity Rank Precision@7** | **100.0%** (7/7) | $\ge 90.0\%$ | **PASS** |
| **Entity Rank Recall@7** | **100.0%** (7/7) | $\ge 90.0\%$ | **PASS** |
| **Injected Defect Recall** | **100.0%** (21/21) | $\ge 90.0\%$ | **PASS** |
| **Overall Defect Precision** | **100.0%** (21 of 21 findings; 0 false positives on any entity) | $\ge 85.0\%$ | **PASS** |
| **Overall Defect F1 Score** | **1.0000** | $\ge 0.8500$ | **PASS** |
| **Ranking Stability (±20% domain weights)** | **Spearman $\rho = 1.0000$ / $1.0000$** | $\ge 0.8500$ | **PASS** |
| **Cryptographic Audit Chain** | **Intact** | Zero Tampering | **PASS** |

Confounder checks (measured): 0 EG01/EG02 findings on entities without an injected fast-closure
defect; 0 findings on the small-band entities (CSE-08, CSE-10) for rules not injected there.

These are correctness-check results, not a real-world accuracy benchmark; see Section 0.

### 2.1 Entity Ranking Confirmation
- **Top 7 Ranked Entities (All Injected):** CSE-02, CSE-03, CSE-07, CSE-09, CSE-08, CSE-05, CSE-10
- **Bottom 3 Entities (All Clean Baselines):** CSE-01, CSE-04, CSE-06

*(Exact risk indices vary slightly between regenerations of the synthetic dataset; run `satsa validate` for the current run's numbers.)*

---

## 2A. Stress Scenario (Borderline, Ambiguous and Noisy Cases)

Run via `satsa validate-stress`. This uses a second, independent dataset (`satsa/synth/stress.py`)
with three entities, each spanning the full 6-month period over four assets, evaluated in a fully
isolated store so it never perturbs the numbers in Section 2:

- **STRESS-01:** EG04 defect injected at 27.5% comment-hash repeat share -- only ~2.5 points over
  EG04's 25% threshold, versus CSE-07's deliberately blown-out 60% in the primary dataset.
- **STRESS-02:** the SAME 12/40 closures simultaneously satisfy EG02 (ack without investigation)
  and EG04 (template closures) -- genuinely ambiguous which rule should be credited.
- **STRESS-03:** a "clean" entity with realistic jitter (variable closure durations, unique
  comments, mixed day/night hours, varied rules and assets, a few true positives) plus two
  near-miss repeat-alert patterns: one noisy (asset, rule) pair with a tuning ticket, and one
  without, which alone is below EG05's two-pair minimum.

Results (seed 9901; regenerate with `satsa validate-stress`; numbers are not curated):

| Metric | Result |
|---|---|
| Entity Rank Precision@k | 100.0% |
| Injected Defect Recall | 100.0% (3/3) |
| Overall Defect Precision | 100.0% (3 of 3 findings) |
| False Positives | 0 |

The borderline and ambiguous defects both crossed their thresholds, and the noisy clean entity
produced no finding. The previously reported 60% precision and its two false positives were
generator artifacts (Section 0.1). Because STRESS-01's borderline share and STRESS-03's near misses
were built with the thresholds in hand, this scenario confirms that the thresholds are implemented
as specified at the edge; it does not estimate how often real submissions land near them.

---

## 3. Operational Review-Effort Lift

Review-effort lift compares the share of defect-affected alerts among the review queue's alert
items with the share among all alerts (what random sampling of alerts would find), at budgets of
1%, 2% and 5% of total alerts. Both sides count alert records only; asset, category and KPI queue
items and non-alert ground-truth IDs are excluded from both.

| Audit Budget (% of Alerts) | Budget | Queue Alerts Examined | Affected Alerts Found | Queue Hit Rate | Random Sampling Rate | Lift Factor |
|---|---|---|---|---|---|---|
| **1%** | 162 | 109 (queue exhausted) | 16 | **14.7%** | 2.67% | **5.50x** |
| **2%** | 325 | 109 (queue exhausted) | 16 | **14.7%** | 2.67% | **5.50x** |
| **5%** | 812 | 109 (queue exhausted) | 16 | **14.7%** | 2.67% | **5.50x** |

*Reading this table:* the queue holds only 109 alert items (134 items in total), fewer than even
the 1% budget, so every budget examines the whole queue and reports the same figure. The lift is
therefore "the whole queue vs. random", not a curve over budgets. The figure moves with the ground
truth: adding the EG11 defect (about 200 CSE-07 alerts relabelled, all counted as affected) raised
the random baseline from 1.20% to 2.67% and cut lift from 10.69x to 5.50x without any change to the
queue. As with Section 2, treat it as a design check of the prioritisation logic on synthetic data,
not a real-world lift guarantee.

*Correction history:* this table previously reported 16.60x (stale, older dataset) and then
5.97x / 4.13x / 1.65x. The 5.97x-era calculation counted non-alert ground-truth IDs (asset IDs,
comment hashes, marker IDs) in the random baseline, matched mixed record types in the queue, and
divided by the full budget even when the queue was shorter than the budget ("810 records examined"
from a 275-item queue). The queue is also smaller now because the spurious findings in Section 0.1
no longer feed it.

---

## 4. Sensitivity & Ranking Stability

The harness perturbed all 8 capability domain **weights** by **$\pm 20\%$** on the primary dataset:
- **+20% Perturbation:** Spearman rank correlation $\rho = \mathbf{1.0000}$.
- **-20% Perturbation:** Spearman rank correlation $\rho = \mathbf{1.0000}$.
- **Conclusion:** on this dataset, the entity ranking is stable under domain-weight changes. Rule
  detection thresholds were **not** perturbed, so this says nothing about how findings (and
  therefore precision and recall) change as thresholds move.

---

## 5. Shadow-Pilot Validation Mode

The integrated `ShadowPilotAdapter` allows supervisory teams to validate SAT-SA against historical
manual examination workpapers -- **real evidence**, unlike Sections 2 and 2A which are both
synthetic. This is the recommended way to obtain an actual real-world accuracy estimate before
relying on SAT-SA operationally.

### Usage:
1. Prepare past audit CSV with columns: `entity_id,record_id,rule_id,label`.
   - `confirmed` rows are issues the examiner found.
   - `not_an_issue` rows **with a `rule_id`** mean the examiner checked that rule for that entity and
     found no issue; a SAT-SA finding for the pair is a false positive. These rows drive precision.
   - `not_an_issue` rows **without a `rule_id`** clear a single record; they count toward "cleared
     records still in the review queue".
2. Run validation:
   ```bash
   satsa validate --shadow-csv path/to/historical_reviews.csv
   ```
   Or, in the app, sign in as the analyst and open **Config & Audit → Shadow Pilot** (`/shadow-pilot`)
   to upload the CSV. It is evaluated against the latest assessment run.
3. The harness computes:
   - **historical finding recall**: confirmed (entity, rule) issues reproduced as findings;
   - **queue record recall**: confirmed records present in the review queue;
   - **workpaper precision**: of the SAT-SA findings the workpaper adjudicates (confirmed or
     cleared by rule), the share examiners confirmed;
   - **unadjudicated findings**: SAT-SA findings the workpaper never mentions. These are listed,
     not counted as false positives: a workpaper is not a complete audit, so silence is not
     evidence either way. An examiner must adjudicate them before precision is meaningful.
4. Every evaluation is stored (`shadow_pilot_results` table) with its workpaper name, time and
   actor. The `/shadow-pilot` page lists them, and `satsa validate` writes the latest one for the
   report's run into Section 5 of `docs/validation_report.md` and `.html`.

No shadow-pilot run against real NCIIPC/CSE data has been executed as of this writing; Sections 2
and 2A remain synthetic-only until one is. Section 5A below is a rehearsal of the pipeline, not
such a run.

**What a convincing real pilot looks like.** Freeze the rule thresholds (and record the
`config/rules.yaml` hash) before looking at the workpapers; use entities that were not used for
tuning; have examiners adjudicate every unadjudicated finding blind to SAT-SA's score; report
per-rule recall and precision with confidence intervals (with a handful of entities they will be
wide); and report each rule's firing rate across the portfolio, since a rule that fires on nearly
every entity carries little information.

### 5A. Shadow-Pilot Rehearsal (synthetic stand-in -- NOT independent evidence)

This is a pipeline rehearsal, not a third validation tier. It checks that a workpaper CSV flows
through `satsa validate --shadow-csv` end to end and shows what the adapter reports. It says
**nothing** about real-world accuracy.

**Where the "examiner labels" come from.** The stand-in CSV
(`data/generated/shadow_pilot_standin.csv`, built by `scripts/build_shadow_standin.py`) is made
from the synthetic generator's own injected defects, the same `ground_truth.json` that Section 2
uses, relabelled as workpaper rows:
- **47 `confirmed` rows**: each of the 21 injected defects, carrying up to 5 of its affected
  record IDs (the first by sort order).
- **60 rule-level `not_an_issue` rows**: every one of the 20 rules cleared for each of the three
  clean entities (nothing was injected there).
- **15 record-level `not_an_issue` rows**: 5 alerts each from the three clean entities.

These are not historical examiner findings. They are also deliberately **not** taken from
SAT-SA's own findings: labels copied from the tool's output would make recall and precision 100%
by construction.

**Result** (primary dataset, run `RUN-20260929175400749877-b3723c48`):

| Measure | Value | What it means |
|---|---|---|
| `rule_finding_recall` | **1.0** (47/47 confirmed rows) | Restates Section 2's 21/21 recall in workpaper form (same ground truth). Not new evidence. |
| `queue_record_recall` | **0.532** (25/47) | 25 labelled records are in the review queue. |
| `workpaper_precision` | **1.0** (21/21 adjudicated findings) | Restates Section 2's precision: the cleared rows come from the same ground truth. Not new evidence. |
| Unadjudicated findings | **0** | The stand-in adjudicates every entity it names; a real workpaper will not. |
| Cleared records in the queue | **0/15** | None of the individually cleared clean-entity alerts were queued. |
| Queue coverage of *all* affected IDs | 44/498; at least one queue item for 13 of 21 defects | Computed by the build script over every affected ID, not just the capped sample. |

**Reading the queue figure.** The review queue samples up to 30 items per entity (70% top-risk,
30% stratified random; 134 items in this run). It is built to put *examples* of each triggered rule
in front of an examiner, not to list every affected record, so record-level recall is expected to be
low for large defects: 14 of the 195 EG01 fast-closure alerts and 2 of the 204 EG11 relabelled
alerts are queued. EG07's burst alerts (0/35) are not queued because EG07's evidence is the analyst,
not the alerts, and NS05's dormant rules (0/25) are not queue records. Entity-level defects such as
EG10, EG04, EG06, NS03, NS04 and NS08 have marker IDs that are not queue records.

**What still requires real data.** Actual historical NCIIPC/CSE examiner workpapers. Until
SAT-SA is run against those, this section and Sections 2 and 2A are synthetic only.
