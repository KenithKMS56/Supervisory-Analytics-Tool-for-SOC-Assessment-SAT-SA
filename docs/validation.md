# SAT-SA Validation Methodology & Results

> **Supervisory Notice:** *Indicators requiring supervisory review; not a compliance determination.*

This document details SAT-SA's validation methodology and results, and is explicit about what
kind of evidence each result actually is.

---

## 0. What This Validation Is -- and Is Not

Section 2 below is a **detector-implementation correctness check**: it confirms that each rule's
code correctly implements its own specified logic (e.g. "flag entities where >25% of human-closed
alerts share an identical comment hash") against a synthetic dataset whose injected defects are
deliberately built to clearly exceed each rule's threshold. Because the defects are constructed to
be unambiguous by design, precision and recall near 100% are close to **guaranteed by
construction** -- they demonstrate the code does what it says, not that the underlying detection
logic would perform well on real-world SOC submissions with realistic signal-to-noise ratios,
borderline cases, or ambiguous evidence.

Section 2A adds a **stress scenario**: a second, independent, deliberately harder synthetic dataset
with a borderline-threshold case, a case ambiguous between two rules, and a noisy true-negative
case. Its precision/recall numbers are genuinely imperfect (see Section 2A) and are the closer
proxy for what to expect on messier real submissions -- though neither scenario is a substitute
for the Shadow-Pilot Mode in Section 5, which is the only mode that validates against real
historical examiner findings.

Previous drafts of this document described Section 2's results as an "empirical benchmark" and
used "Exceeded" language. That framing has been corrected here: the numbers are real (they are
the actual measured output of `satsa validate` against the stated dataset), but what they are
evidence *of* is implementation correctness on an intentionally easy dataset, not real-world
detection accuracy.

---

## 1. Experimental Methodology & Ground Truth Design

To objectively evaluate the rule implementations without relying on circular self-scoring, SAT-SA
pairs with a deterministic synthetic generator (`satsa generate-data`) that models 10 Critical
Sector Entities (CSE-01 through CSE-10) over a 6-month period across 5 critical infrastructure
sectors.

### 1.1 Injected Operational Defects (Positive Cases)
Ground truth injects 11 distinct operational execution gaps and negative space defects into 7 entities:
- **CSE-02 (Banking Large):** Declared MTTR gaming ($>200$ min actual vs 35 min declared) $\to$ **EG10**.
- **CSE-03 (Telecom Large):** Premature rubber-stamp closures ($<120$s) $\to$ **EG01**; Critical True Positives closed without escalation $\to$ **EG03**.
- **CSE-05 (Transport Medium):** Silent Criticality 4 monitored assets ($>3$ days zero logs) $\to$ **NS01**; Ghost inventory assets absent from telemetry $\to$ **NS06**.
- **CSE-07 (Banking Large):** Identical repetitive closure comments ($60\%$ share, vs. the rule's real 25% code threshold -- see Section 0) $\to$ **EG04**; SLA deadline hugging and month-end bulk closures $\to$ **EG06**.
- **CSE-08 (Telecom Small):** Complete absence of peer threat categories (Malware, DoS, Phishing) $\to$ **NS02**; Record ID sequence gaps $\to$ **NS04**.
- **CSE-09 (Oil & Gas Large):** High repeat alert pairs without root-cause remediation tickets $\to$ **EG05**.
- **CSE-10 (Transport Small):** Total nighttime logging collapse (zero 24x7 coverage) and mid-period volume drop $\to$ **NS03**.

### 1.2 Clean Baselines & Controlled Confounders (Negative Cases)
- **Clean Baselines (CSE-01, CSE-04, CSE-06):** Entities operating with disciplined triage, timely escalations, balanced dispositions, and consistent 24x7 logging.
- **Confounder 1 (SOAR Automation):** High-velocity closures executed by automated playbooks (`closed_by_type='soar'`). Validates that fast triage algorithms are not misflagged as human rubber-stamping.
- **Confounder 2 (Small Entity Scale):** CSE-08 has lower absolute alert volumes. Validates that robust statistics correctly group by size band rather than falsely flagging small entities as volume collapses.

> **Note on config vs. code:** `config/rules.yaml` documents an EG04 `max_comment_hash_share` of
> 0.45, but the current `EG04TemplateDrivenInvestigations.evaluate()` implementation does not read
> `self.params` at all and hardcodes a 25% repeat-share threshold with a >=10-alert hash-group
> floor directly in its SQL. The primary dataset's CSE-07 defect (60% share) clears either number;
> the stress scenario in Section 2A is calibrated against the actual code threshold (25%), which is
> the one that matters for detection. This drift between the documented config and the executed
> code is a known gap, not a claim we are making about a real capability.

---

## 2. Detector-Implementation Correctness Results (Primary Dataset)

The validation harness (`satsa validate`) was executed against the ground-truth dataset described
in Section 1. All figures below are actual measured outputs, evaluated against defects
constructed to be unambiguous (see Section 0 for what that does and does not prove):

| Evaluation Metric | Measured Result | Benchmark Target | Verdict |
|---|---|---|---|
| **Entity Rank Precision@7** | **100.0%** (7/7) | $\ge 90.0\%$ | **PASS** |
| **Entity Rank Recall@7** | **100.0%** (7/7) | $\ge 90.0\%$ | **PASS** |
| **Injected Defect Recall** | **100.0%** (13/13) | $\ge 90.0\%$ | **PASS** |
| **Overall Defect Precision** | **100.0%** (13/13) | $\ge 85.0\%$ | **PASS** |
| **Overall Defect F1 Score** | **1.0000** | $\ge 0.8500$ | **PASS** |
| **Ranking Stability (+20% Weights)** | **Spearman $\rho = 1.0000$** | $\ge 0.8500$ | **PASS** |
| **Ranking Stability (-20% Weights)** | **Spearman $\rho = 1.0000$** | $\ge 0.8500$ | **PASS** |
| **Cryptographic Audit Chain** | **100% Intact** | Zero Tampering | **PASS** |

These are correctness-check results, not a real-world accuracy benchmark; see Section 0 and
Section 2A.

### 2.1 Entity Ranking Confirmation
- **Top 7 Ranked Entities (All Injected):** CSE-07, CSE-08, CSE-10, CSE-03, CSE-02, CSE-05, CSE-09
- **Bottom 3 Entities (All Clean Baselines):** CSE-01, CSE-06, CSE-04

*(Exact risk indices vary slightly between regenerations of the synthetic dataset; run `satsa validate` for the current run's numbers.)*

---

## 2A. Stress Scenario (Harder, Realistic-Imperfection Results)

Run via `satsa validate-stress`. This uses a second, independent dataset (`satsa/synth/stress.py`)
with three entities, evaluated in a fully isolated store so it never perturbs the numbers in
Section 2:

- **STRESS-01:** EG04 defect injected at 27.5% comment-hash repeat share -- only ~2.5 points over
  the rule's real 25% code threshold, versus CSE-07's deliberately blown-out 60% in the primary
  dataset.
- **STRESS-02:** the SAME 12/40 closures simultaneously satisfy EG02 (ack without investigation)
  and EG04 (template closures) -- genuinely ambiguous which rule should be credited.
- **STRESS-03:** a "clean" entity with realistic jitter (variable closure durations, unique
  comments, mixed day/night hours, rotating rule IDs across 120 alerts) rather than a hand-picked,
  noise-free baseline.

Representative results from one run (regenerate with `satsa validate-stress`; exact numbers vary
by seed and are not curated):

| Metric | Result |
|---|---|
| Entity Rank Precision@k | 100.0% |
| Injected Defect Recall | 100.0% (3/3) |
| Overall Defect Precision | **60.0%** |
| False Positives | **2** (on the noisy "clean" STRESS-03 entity: EG05 and NS08 both fired) |

Both injected defects were correctly detected (the borderline EG04 case and the ambiguous
EG02/EG04 case both crossed their thresholds as designed), but the noisy clean entity produced two
genuine false positives that the primary, noise-free dataset in Section 2 would never surface.
**This is the more honest signal of how the rule thresholds behave away from hand-tuned,
unambiguous inputs**, and it is a large part of why Section 5's Shadow-Pilot mode against real
historical examiner findings exists: neither synthetic scenario is a substitute for it.

---

## 3. Operational Review-Effort Lift

Review-effort lift quantifies how many more operational defects supervisory examiners discover
when reviewing SAT-SA's prioritized review queue versus standard unassisted random sampling of the
same size at fixed audit budgets (1%, 2%, and 5% of total alerts), measured on the **primary**
(unambiguous) dataset from Section 1:

| Audit Budget (% of Alerts) | Records Examined | Defects Found (SAT-SA) | Queue Hit Rate | Random Sampling Rate | Empirical Lift Factor |
|---|---|---|---|---|---|
| **1% Review Budget** | 162 records | 13 defects | **8.0%** | 1.34% | **5.97x Lift** |
| **2% Review Budget** | 324 records | 18 defects | **5.6%** | 1.34% | **4.13x Lift** |
| **5% Review Budget** | 810 records | 18 defects | **2.2%** | 1.34% | **1.65x Lift** |

*Takeaway: on this synthetic, unambiguous dataset (default generator, seed 42, ~16,200 alerts), an
examiner auditing 1% of alerts using SAT-SA's prioritized queue finds 5.97 times as many of the
injected defects as unassisted random sampling of the same size. The lift falls as the budget grows
because the 30-item-per-entity queue is exhausted early. As with Section 2, treat this as a
correctness/design check of the prioritisation logic, not a real-world lift guarantee.*

*Correction (hardening pass): this table previously reported 16.60x / 12.66x / 5.07x. Those figures
came from an older, smaller synthetic dataset (~5,600 alerts, so a 1% budget was 56 records) and
were not updated when the default generator grew to ~16,200 alerts. The numbers above were
recomputed from scratch with `satsa validate` on a clean checkout and match
`docs/validation_report.md`.*

---

## 4. Sensitivity & Ranking Stability

To verify that entity rankings are not hyper-sensitive to threshold choices, the harness perturbed
all 8 capability domain weights by **$\pm 20\%$** on the primary dataset:
- **+20% Perturbation:** Spearman rank correlation $\rho = \mathbf{1.0000}$.
- **-20% Perturbation:** Spearman rank correlation $\rho = \mathbf{1.0000}$.
- **Conclusion:** on this dataset, ranking order is invariant to minor supervisory parameter
  tuning. This is a useful robustness property of the scoring formula itself, independent of the
  detector-correctness caveat above.

---

## 5. Shadow-Pilot Validation Mode

The integrated `ShadowPilotAdapter` allows supervisory teams to validate SAT-SA against historical
manual examination workpapers -- **real evidence**, unlike Sections 2 and 2A which are both
synthetic. This is the recommended way to obtain an actual real-world accuracy estimate before
relying on SAT-SA operationally.

### Usage:
1. Prepare past audit CSV with columns: `entity_id,record_id,rule_id,label`.
2. Run validation:
   ```bash
   satsa validate --shadow-csv path/to/historical_reviews.csv
   ```
3. The harness computes historical finding recall and queue discovery efficiency against those
   real prior findings.

No shadow-pilot run has been executed against real NCIIPC/CSE data as of this writing; Sections 2
and 2A remain synthetic-only until one is.
