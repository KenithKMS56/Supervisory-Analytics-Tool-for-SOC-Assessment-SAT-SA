# SAT-SA Analytics Methodology & Mathematical Specifications

> **Supervisory Notice:** *Indicators requiring supervisory review; not a compliance determination.*

This document provides the exhaustive mathematical, statistical, and algorithmic specifications for all detection rules, scoring engines, and benchmarking models implemented in **SAT-SA**.

---

## 1. Robust Statistics & Peer Benchmarking

> **Implementation status.** Peer cohorts (Section 1.4) are used by EG01, EG11, NS02 and NS03. The
> robust z-score (Section 1.2) decides **NS03** (night share far below peers) and **EG11** (FP rate
> far above peers), via `BaseRule.robust_z`: $z = (x - \tilde{x}) / \max(1.4826\,\text{MAD}, s_{\min})$
> against the cohort, where the spread floor $s_{\min}$ stops near-identical peers from making a
> trivial difference look extreme; with fewer than 3 comparable peers these rules fall back to a
> fixed threshold. The other rules use the fixed thresholds stated in Section 3. IQR/percentile rank
> (Section 1.3) and the SPC charts (Section 2) are implemented and unit-tested but not used by any
> rule or score.

Traditional mean and standard deviation metrics are highly sensitive to extreme outliers and asymmetric distributions common in SOC incident response data. SAT-SA's statistics library therefore implements **classical robust statistics**.

### 1.1 Median & Median Absolute Deviation (MAD)
For an entity observation set $X = \{x_1, x_2, \dots, x_n\}$ across a peer group:
$$\tilde{x} = \text{median}(X)$$
$$\text{MAD}(X) = \text{median}(|x_i - \tilde{x}|)$$

### 1.2 Robust Z-Score ($z_{\text{rob}}$)
To benchmark an entity's metric $x$ against its sector/size peer group:
$$z_{\text{rob}} = \frac{x - \tilde{x}}{1.4826 \times \text{MAD}(X)}$$
*Where 1.4826 is the asymptotic consistency factor for normally distributed data.*

### 1.3 Interquartile Range (IQR) & Percentile Rank
$$\text{IQR} = Q_3 - Q_1 = P_{75} - P_{25}$$
$$\text{Percentile}(x) = \frac{\sum_{i=1}^n \mathbb{I}(x_i \le x)}{n} \times 100$$

### 1.4 Peer Grouping Hierarchy
`PeerResolver` (`config/peers.yaml`, `min_peers: 3`) picks the first level with at least 3 other entities:
1. Primary: `(sector, size_band)` (e.g., Banking Large, Power Medium).
2. Fallback 1: same `sector`, any size band.
3. Fallback 2: same `size_band`, any sector.
4. Fallback 3: every other entity in the portfolio.

The entity itself is never in its own cohort. In the 10-entity synthetic portfolio no
`(sector, size_band)` or sector cohort reaches 3 peers, so large entities fall back to "all large"
and the rest to "all other entities"; genuine sector cohorts need a larger portfolio.

---

## 2. Statistical Process Control (SPC): CUSUM & EWMA

To detect abrupt operational regime shifts, weekend/holiday volume collapses, or sudden drop-offs in logging velocity, SAT-SA uses deterministic SPC formulations.

### 2.1 Tabular Cumulative Sum (CUSUM)
Given daily metric sequence $y_t$ with baseline mean $\mu_0$ and standard deviation $\sigma$:
$$C_t^+ = \max(0, C_{t-1}^+ + (y_t - \mu_0 - k\sigma))$$
$$C_t^- = \max(0, C_{t-1}^- - (y_t - \mu_0 + k\sigma))$$
- Default allowance $k = 0.5$, decision boundary $h = 4.0\sigma$. A shift is flagged when $C_t^+ > h$ or $C_t^- > h$.

### 2.2 Exponentially Weighted Moving Average (EWMA)
$$Z_t = \lambda y_t + (1 - \lambda) Z_{t-1}$$
- Smoothing parameter $\lambda = 0.20$, baseline $Z_0 = \mu_0$.
- Dynamic control limits:
  $$\text{UCL/LCL} = \mu_0 \pm L \sigma \sqrt{\frac{\lambda}{2 - \lambda} \left[1 - (1 - \lambda)^{2t}\right]}$$
  *(with standard supervisory control width $L = 3.0$).*

---

## 3. Comprehensive Rule Specifications

### 3.1 Execution Gaps (EG01–EG12)

#### EG01: Fast Closures Without Investigation
- **Purpose:** Detect rubber-stamping and premature dismissals of high-priority alerts.
- **Logic:** Among the entity's human-closed High/Critical alerts, the share closed faster than its peer cohort's 5th-percentile close time (human High/Critical closures of the peers resolved from `config/peers.yaml`, never including the entity itself) with at most one workflow event exceeds `fast_share_threshold` (0.15), with at least `min_fast_count` (5) such closures. SOAR/automation closures are excluded.
- **Benign Explanations:** Automated playbook executions mislabeled as human; duplicate suppression rules in external SIEM.
- **Examiner Checks:** Inspect closure logs for script execution IDs; verify if analyst could have reviewed payload in the time recorded.

#### EG02: Acknowledged Without Investigation
- **Purpose:** Surface alerts closed with no recorded investigative work.
- **Logic:** Among human-closed alerts, the share with no `investigate` workflow event and a closure comment under 25 characters exceeds `max_uninvestigated_share` (0.15), with at least `min_uninvestigated_count` (5) such alerts.
- **Benign Explanations:** Shift handover reassignments; consolidated investigation inside an external parent ticket.
- **Examiner Checks:** Request ticket cross-reference in secondary ticketing tools.

#### EG03: Missing Escalations
- **Purpose:** Identify critical incidents closed at Tier-1 without Tier-2/Tier-3 SME or management review.
- **Logic:** Any alert with `severity_final = 'critical'` and `disposition = 'true_positive'` that has no record in `escalation`. Zero tolerance: one such alert is a finding; there is no tunable threshold.
- **Benign Explanations:** Tier-1 analyst possesses senior clearance/role; incident was handled in direct war-room chat.
- **Examiner Checks:** Verify seniority of the closing analyst; inspect meeting minutes or external war-room logs.

#### EG04: Template / Low-Effort Closure Comments
- **Purpose:** Detect superficial closure documentation lacking technical justification.
- **Logic:** Human closures whose normalized comment hash repeats at least `min_hash_group_size` (10) times are summed; flagged when they exceed `max_comment_hash_share` (0.25) of all human closures. Comment shingles and comment length are not used.
- **Benign Explanations:** Mandatory standardized dropdown resolution codes enforced by SOC management.
- **Examiner Checks:** Check if detailed technical evidence is attached as external files or tickets.

#### EG05: Repeat Alerts Without Root Cause Remediation
- **Purpose:** Detect chronic alert fatigue and lack of permanent tuning.
- **Logic:** `(asset_id, rule_id)` pairs that fired at least $k$ times over the whole period, were always closed benign/FP, and have no matching `remediation` record; flagged when at least `min_unaddressed_pairs` (2) such pairs exist. There is no 30-day window.
- **Repeat threshold $k$:** $k = \max(\texttt{min\_repeat\_count}, k_{\text{chance}})$, with `min_repeat_count` 8. $k_{\text{chance}}$ is the smallest count for which $M \cdot P(X \ge k) <$ `max_chance_pairs` (0.5), where $M$ is the entity's distinct assets × distinct rules and $X \sim \text{Poisson}(N / M)$ for its $N$ alerts: the count that coincidence alone would rarely reach at that volume. $k_{\text{chance}}$ is capped at $2 \times$ `min_repeat_count`, so a pair repeating 16+ times, always benign and never tuned, always counts however busy the entity. The Poisson model assumes alerts spread evenly over pairs; it removes only small-count repeats that volume explains (see `docs/validation.md` Section 4A).
- **Benign Explanations:** Legacy system awaiting decommissioning; scheduled quarterly tuning backlog.
- **Examiner Checks:** Review change request logs for scheduled tuning on the affected asset.

#### EG06: Metric Gaming & SLA Distortions
- **Purpose:** Detect artificial manipulation of SOC operational performance metrics.
- **Logic:** Flags either of two indicators:
  1. **Bulk Closures:** one analyst closing at least `min_bulk_closures_per_minute` (8) human alerts within the same clock minute.
  2. **Deadline Hugging:** more than `max_deadline_hugging_share` (0.25) of human closures landing between 90% and 100% of the severity's SLA resolve time.
- **Not implemented:** shift/month-end spikes, severity downgrades and MTTA/MTTR divergence are not checked.

#### EG07: Analyst Implausibility
- **Purpose:** Detect superhuman analyst workloads indicating script abuse or shared credentials.
- **Logic:** One analyst closing at least `min_closures_per_analyst_hour` (30) human alerts within a single clock hour. Activity outside declared shift hours is not checked.
- **Benign Explanations:** Batched shift catch-up entry; shared service account used by junior rotation.
- **Examiner Checks:** Inspect VPN and badge swipe logs for the named analyst during the event timestamps.

#### EG08: Escalation Without Follow-Through
- **Purpose:** Detect stalled escalations abandoned by senior tiers.
- **Logic:** At least `min_unacknowledged_escalations` (3) records in `escalation` with no acknowledgement timestamp. Acknowledgement delay against SLA is not checked.
- **Benign Explanations:** Escalated to external third-party vendor (MSSP) without API sync.
- **Examiner Checks:** Review MSSP portal tickets and emails for vendor acknowledgment.

#### EG09: Backlog & Aging Accumulation
- **Purpose:** Identify systemic queue stagnation.
- **Logic:** At least `min_stale_cases` (3) cases with status `open` that were opened more than `stale_case_days` (14) days before the assessment runs. Workflow inactivity and SLA multiples are not checked.
- **Benign Explanations:** Long-term forensic investigation awaiting legal or law-enforcement subpoena.
- **Examiner Checks:** Confirm active case status in legal or incident management logs.

#### EG10: KPI Reconciliation Gap
- **Purpose:** Detect discrepancies between declared regulatory KPIs and KPIs recomputed from submitted records.
- **Logic:** Recomputes MTTR (created → closed) from canonical alert timestamps for each of High and Critical, and compares it with the declared MTTR for the same severities only, each weighted by its alert count. Flags when the empirical MTTR exceeds the declared MTTR by more than `mttr_gap_ratio_threshold` (default 0.60). MTTA and SLA achievement are not reconciled by this rule.
- **Formula:** $\text{Gap} = \frac{\text{Empirical} - \text{Declared}}{\max(\text{Declared}, 1)}$, where both sides are alert-count-weighted over the declared severities. Only under-declaration (empirical slower than declared) is flagged.
- **Benign Explanations:** Different timezone assumptions; exclusion of maintenance hours in declared SLA calculation.
- **Examiner Checks:** Verify official SLA calculation formula submitted by entity leadership.

#### EG11: Disposition Extremes
- **Purpose:** Detect abnormal classification skew indicative of alert tuning failure or detection blindspots.
- **Logic:** With at least `min_alert_volume` (200) alerts: exactly zero True Positives over the review period, or a false-positive/benign rate with a robust z-score of at least `max_robust_z` (3.5) above the peer cohort's median (peers with at least 200 alerts; spread floor `min_spread` 0.01). With fewer than 3 comparable peers, the rate is compared with the fixed `max_fp_rate` (0.98) instead.
- **Benign Explanations:** Ultra-noisy commercial rule left in staging mode.
- **Examiner Checks:** Verify if rule was active in production or marked as test/monitoring only.

#### EG12: Workflow Non-Conformance
- **Purpose:** Audit adherence to the mandated containment step for critical incidents.
- **Logic:** At least `min_skipped_cases` (2) Critical cases with no `contain` workflow event. Other stages and their order are not checked, and `config/expected.yaml` is not read by this rule.
- **Benign Explanations:** Emergency containment executed out of band before ticket creation.
- **Examiner Checks:** Examine emergency radio or messaging logs confirming containment timeline.

---

### 3.2 Negative Space Rules (NS01–NS08)

#### NS01: Silent Critical Assets
- **Purpose:** Surface critical infrastructure components that have completely stopped generating security events.
- **Logic:** Monitored assets with criticality at least `min_asset_criticality` (3) that have at least `min_silent_days` (3) days with zero events in `log_source_daily`. The days need not be consecutive; peer event rates are not compared.
- **Benign Explanations:** Planned offline maintenance; air-gapped backup server on standby.
- **Examiner Checks:** Request maintenance ticket or network ping history for the silent IP.

#### NS02: Missing Alert Categories
- **Purpose:** Detect blindspots in detection coverage where peers actively detect standard threat classes.
- **Logic:** Alert categories reported by at least `min_peer_share` (0.6) of the entity's peer cohort (resolved from `config/peers.yaml`) but absent from this entity's alerts. Uses alert categories, not MITRE tactics.
- **Benign Explanations:** Entity relies on upstream ISP-managed cloud scrubbers for DDoS/Malware.
- **Examiner Checks:** Verify third-party perimeter architecture and outsourced managed controls.

#### NS03: Unexpectedly Low or Flat Activity
- **Purpose:** Identify missing 24x7 coverage or logging collapse.
- **Logic:** With at least `min_alert_volume` (100) alerts, the share created at night (20:00–08:00) has a robust z-score of at most −`max_robust_z` (3.5) against the peer cohort's night shares (peers with at least 100 alerts; spread floor `min_spread` 0.02). With fewer than 3 comparable peers, the share is compared with the fixed `max_night_share` (0.03) instead. CUSUM and weekend activity are not used.
- **Benign Explanations:** 8x5 business application with no user activity outside business hours.
- **Examiner Checks:** Review shift rosters to verify if 24x7 SOC shift coverage was formally contracted.

#### NS04: Missing Records
- **Purpose:** Detect audit trail truncation, record deletion, or unrecorded triage.
- **Logic:** At least `min_tp_without_case` (3) High/Critical True Positive alerts with no linked case management record. Numeric sequence gaps in alert IDs (e.g., ALT-101 $\to$ ALT-105) are not part of this rule; they are reported by the ingest data-quality checks (`DQValidator.check_id_sequence_gaps`, shown on the DQ view).
- **Benign Explanations:** Deleted test alerts created during scheduled engineering validation.
- **Examiner Checks:** Review change control records for test execution IDs.

#### NS05: Rule Coverage & Inactive Signatures
- **Purpose:** Detect stale, inactive, or unmaintained SIEM detection catalogs.
- **Logic:** More than `max_dormant_share` (0.40), and at least `min_dormant_rules` (5), of the entity's enabled detection rules produced no alert over the period. MITRE baseline coverage is not checked.
- **Benign Explanations:** Narrow, high-fidelity custom detection for rare zero-day indicators.
- **Examiner Checks:** Verify if test attacks/adversary simulations have validated rule logic.

#### NS06: Inventory vs. Telemetry Reconciliation
- **Purpose:** Detect ghost assets (registered devices sending zero logs).
- **Logic:** At least `min_ghost_assets` (2) inventory assets with no alerts and no (or only zero-count) `log_source_daily` rows. Shadow assets (unregistered devices generating alerts) are not checked.
- **Benign Explanations:** DHCP hostname churn; recently decommissioned hardware not yet purged from CMDB.
- **Examiner Checks:** Reconcile active IP addresses with network core switch ARP tables.

#### NS07: Absent External Regulatory Reporting
- **Purpose:** Identify statutory reporting non-compliance for critical cybersecurity incidents.
- **Logic:** Any Critical case with no matching record in `external_report`. Zero tolerance, no tunable threshold. Presence only: whether the report was filed within a statutory window is not checked (documented follow-up).
- **Benign Explanations:** Preliminary verbal notification provided to regulator before formal portal filing.
- **Examiner Checks:** Check NCIIPC official incident hotline communications log.

#### NS08: Submission Completeness & Data Quality Deficits
- **Purpose:** Detect data withholding, incomplete log submissions, or corrupt data drops.
- **Logic:** The entity's alerts cover fewer than the 6 months of the review period. Null rates are reported by the ingest data-quality checks and volume drops by NS03; neither is part of this rule.
- **Benign Explanations:** SIEM migration occurred during the reporting period.
- **Examiner Checks:** Request migration documentation and revised ingestion extracts.

---

## 3A. Cross-Entity ("Systemic") Correlation Detection

Every rule above (EG01-EG12, NS01-NS08) evaluates a single entity in isolation against its peer
cohort. `satsa.rules.systemic.SystemicCorrelationDetector` (configured by `config/systemic.yaml`)
runs once per assessment, AFTER all per-entity rules, and looks ACROSS the whole portfolio instead:

- **Grouping key:** entities are grouped by `soc_provider` (a canonical entity field distinct from
  the coarser `soc_model` category -- two entities can both be `soc_model=mssp` but use different
  vendors; `soc_provider` names the specific shared vendor, or `internal` for an in-house SOC).
- **Trigger condition:** if `>= min_entity_count` (default 3) entities sharing the same
  `soc_provider` all produced a finding for the SAME `rule_id` in the SAME assessment run, that is
  surfaced as one systemic finding, persisted to its own `systemic_findings` SQLite table and
  rendered in its own portfolio dashboard section (`/`), never folded into any individual entity's
  finding cards.
- **Exclusions:** `soc_provider=internal` is never correlated on (shared in-house negligence isn't
  evidence of a shared-vendor problem). `config/systemic.yaml`'s `excluded_rule_ids` lets an
  operator exclude rules known to fire portfolio-wide for non-vendor reasons; it is empty by
  default, because excluding a rule also hides a genuine shared-vendor pattern in it.
- **Rationale for supervisors:** a cluster of identical findings under one shared provider points at
  that provider's own process or detection-engineering practices as the likely root cause, which
  changes the appropriate supervisory response from "counsel this one entity" to "examine this
  vendor's practice across its full client roster." This is SAT-SA's answer to the problem
  statement's invitation to surface additional supervisory signals beyond the illustrative EG/NS
  examples: a correlation across the portfolio that no single-entity rule could ever see.

---

## 4. Scoring, Aggregation & Prioritization Mathematics

### 4.1 Rule Score (0–100)
$$\text{Score}(r) = \frac{\min(2, \; \text{Distance}(r))}{2} \times \text{SeverityWeight}(r) \times \text{Confidence}(r)$$
- **Distance** is how far the measured value is past the rule's threshold (e.g. measured share ÷ threshold share), capped at 2, so a finding at twice its threshold or more scores the full severity weight.
- **SeverityWeight** is per rule (`severity_weight` in `config/rules.yaml`, 70–95), and is therefore also the maximum score a rule can produce.
- **Confidence:** $\min\left(1.0, \; n / n_{\min}\right)$, where $n_{\min}$ is the rule's `min_sample` in `config/rules.yaml`.
- **Known limitation:** for several count-based rules (EG03, EG08, EG09, EG12, NS04, NS06, NS07) $n$ is the number of offending items, not the size of the population examined, so a small number of serious cases scores low: 3 critical cases without containment (EG12, `min_sample` 15) get confidence 0.2 and a score of 12. The band floor in Section 4.3 is not affected by this for findings at confidence ≥ 0.5, but the index is.

### 4.2 Capability Domain Score (Probabilistic Noisy-OR)
For domain $d$ encompassing $m$ triggered rules with scores $s_1, s_2, \dots, s_m \in [0, 100]$:
$$S_d = 100 \times \left(1 - \prod_{i=1}^m \left(1 - \frac{s_i}{100}\right)\right)$$

### 4.3 Composite Entity Risk Index
$$\text{RiskIndex} = (1 - w_{\text{breadth}}) \left(\sum_{d=1}^8 w_d S_d\right) + w_{\text{breadth}} \times \min(100.0, \; 10 \times N_{\text{distinct\_rules}})$$
- Standard domain weights $w_d$ sum to 1.0 (configured in `config/scoring.yaml`).
- Default breadth weight $w_{\text{breadth}} = 0.10$.
- **Risk bands by index** (`risk_bands` in `config/scoring.yaml`): 0–25 Low, 25–50 Moderate, 50–75 High, 75–100 Critical Supervisory Concern.
- **Band floor** (`band_floors`): the index is a weighted average over 8 domains, so a single maximum-score finding in one domain cannot lift it above about 14. To stop an entity with, say, an unreported critical incident being labelled "Low Supervisory Concern", an entity with a **critical**-severity finding (confidence ≥ 0.5) is classified at least **High**, and one with a **high**-severity finding at least **Moderate**. The floor changes the band only: the index and the entity ranking are unchanged, and the entity profile states when the band was raised.
- The dashboard, HTML reports and PDFs all take an entity's classification, colour and "requires action" status (any band above Low) from this stored band.

### 4.4 Review Queue
Per entity, up to `queue_size_per_entity` (30) items (`review_queue` in `config/scoring.yaml`):
1. **Cited records:** records named as evidence by the entity's findings, ordered by accumulated finding score, up to `top_risk_ratio` (70%) of the size.
2. **Random controls:** the remainder of the size (9 of 30), sampled from the entity's other alerts and stratified by severity, with a fixed seed.

The 70/30 split is an upper bound on cited records, not the actual mix: rules cite only a few example records, and entity-level findings cite none, so an entity with few cited records gets a shorter, mostly random queue (a clean entity gets only the 9 controls). In the synthetic run the queue is 44 cited records and 90 random controls.
