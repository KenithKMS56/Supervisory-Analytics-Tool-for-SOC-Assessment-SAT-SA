# SAT-SA Analytics Methodology & Mathematical Specifications

> **Supervisory Notice:** *Indicators requiring supervisory review; not a compliance determination.*

This document provides the exhaustive mathematical, statistical, and algorithmic specifications for all detection rules, scoring engines, and benchmarking models implemented in **SAT-SA**.

---

## 1. Robust Statistics & Peer Benchmarking

Traditional mean and standard deviation metrics are highly sensitive to extreme outliers and asymmetric distributions common in SOC incident response telemetry. SAT-SA employs **classical robust statistics** exclusively.

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
1. Primary: `(sector, size_band)` (e.g., Banking Large, Power Medium).
2. Fallback 1: `sector` (all size bands in sector if peer group count $N < 3$).
3. Fallback 2: `portfolio` (all entities across portfolio if sector count $N < 3$).

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
- **Logic:** Identifies High/Critical severity alerts closed in $t_{\text{close}} - t_{\text{create}} \le T_{\text{threshold}}$ (default 120 seconds) where workflow shows no intermediate actions and actor is human (not SOAR).
- **Benign Explanations:** Automated playbook executions mislabeled as human; duplicate suppression rules in external SIEM.
- **Examiner Checks:** Inspect closure logs for script execution IDs; verify if analyst could have reviewed payload within 2 minutes.

#### EG02: Triage Without Action
- **Purpose:** Surface alerts acknowledged but abandoned or left untouched past SLA.
- **Logic:** Alerts where $t_{\text{touch}} - t_{\text{ack}} > T_{\text{max}}$ (default 4 hours) or where status transitioned to `in_progress` but no subsequent comments or escalations exist for >7 days.
- **Benign Explanations:** Shift handover reassignments; consolidated investigation inside an external parent ticket.
- **Examiner Checks:** Request ticket cross-reference in secondary ticketing tools.

#### EG03: Missing Escalations
- **Purpose:** Identify critical incidents closed at Tier-1 without Tier-2/Tier-3 SME or management review.
- **Logic:** Alerts with `severity_final = 'critical'` and `disposition = 'true_positive'` that have zero linked records in `escalation` or `case`.
- **Benign Explanations:** Tier-1 analyst possesses senior clearance/role; incident was handled in direct war-room chat.
- **Examiner Checks:** Verify seniority of the closing analyst; inspect meeting minutes or external war-room logs.

#### EG04: Template / Low-Effort Closure Comments
- **Purpose:** Detect superficial closure documentation lacking technical justification.
- **Logic:** Computes exact matches of normalized comment text and 4-gram shingles. Flagged if single hash accounts for $>40\%$ of closures or length $<15$ characters.
- **Benign Explanations:** Mandatory standardized dropdown resolution codes enforced by SOC management.
- **Examiner Checks:** Check if detailed technical evidence is attached as external files or tickets.

#### EG05: Repeat Alerts Without Root Cause Remediation
- **Purpose:** Detect chronic alert fatigue and lack of permanent tuning.
- **Logic:** Identifies `(asset_id, rule_id)` pairs generating $\ge 5$ alerts in 30 days, all closed as benign/FP, with zero linked records in `remediation`.
- **Benign Explanations:** Legacy system awaiting decommissioning; scheduled quarterly tuning backlog.
- **Examiner Checks:** Review change request logs for scheduled tuning on the affected asset.

#### EG06: Metric Gaming & SLA Distortions
- **Purpose:** Detect artificial manipulation of SOC operational performance metrics.
- **Sub-indicators:**
  1. **Deadline Hugging:** Disproportionate clustering of closures in the final 10% of the SLA time window ($>35\%$ vs expected $10\%$).
  2. **Bulk Closures:** Single analyst closing $\ge 20$ tickets with identical timestamps ($\pm 5$ seconds).
  3. **Shift/Month-End Spikes:** Closure volume surges $>3\times$ daily median during final 2 hours of shifts.
  4. **Severity Downgrades:** Critical/High downgraded to Low immediately prior to closure.
  5. **MTTA vs MTTR Divergence:** Near-zero MTTA ($<2$ min) coupled with high MTTR ($>24$ hrs).

#### EG07: Analyst Implausibility
- **Purpose:** Detect superhuman or unlogged analyst workloads indicating script abuse or shared credentials.
- **Logic:** Single analyst account closing $>25$ complex alerts per hour or performing actions outside declared shift hours.
- **Benign Explanations:** Batched shift catch-up entry; shared service account used by junior rotation.
- **Examiner Checks:** Inspect VPN and badge swipe logs for the named analyst during the event timestamps.

#### EG08: Escalation Without Follow-Through
- **Purpose:** Detect stalled escalations abandoned by senior tiers.
- **Logic:** Records in `escalation` where $t_{\text{ack}} - t_{\text{esc}} > \text{SLA}$ or where escalation outcome is empty after 14 days.
- **Benign Explanations:** Escalated to external third-party vendor (MSSP) without API sync.
- **Examiner Checks:** Review MSSP portal tickets and emails for vendor acknowledgment.

#### EG09: Backlog & Aging Accumulation
- **Purpose:** Identify systemic queue stagnation.
- **Logic:** Unresolved cases exceeding $3\times$ SLA or open cases with no recorded workflow activity for $\ge 14$ days.
- **Benign Explanations:** Long-term forensic investigation awaiting legal or law-enforcement subpoena.
- **Examiner Checks:** Confirm active case status in legal or incident management logs.

#### EG10: KPI Reconciliation Gap
- **Purpose:** Detect discrepancies between declared regulatory KPIs and empirical telemetric data.
- **Logic:** Recomputes MTTA, MTTR, and SLA achievement percentage directly from canonical timestamps. Flags relative discrepancy $>10\%$ against values in `declared_kpi`.
- **Formula:** $\text{Gap} = \frac{|\text{Declared} - \text{Empirical}|}{\max(\text{Declared}, \text{Empirical})}$.
- **Benign Explanations:** Different timezone assumptions; exclusion of maintenance hours in declared SLA calculation.
- **Examiner Checks:** Verify official SLA calculation formula submitted by entity leadership.

#### EG11: Disposition Extremes
- **Purpose:** Detect abnormal classification skew indicative of alert tuning failure or detection blindspots.
- **Logic:** False positive rate $>98\%$ across $\ge 200$ alerts without tuning, or exactly zero True Positives across 6-month review period.
- **Benign Explanations:** Ultra-noisy commercial rule left in staging mode.
- **Examiner Checks:** Verify if rule was active in production or marked as test/monitoring only.

#### EG12: Workflow Non-Conformance
- **Purpose:** Audit deterministic adherence to mandated step sequences.
- **Logic:** Evaluates sequential execution of required workflow states per severity specified in `config/expected.yaml` (e.g., Critical: `triage` $\to$ `investigate` $\to$ `escalate` $\to$ `contain` $\to$ `close`). Flags cases with skipped or inverted steps.
- **Benign Explanations:** Emergency containment executed out of band before ticket creation.
- **Examiner Checks:** Examine emergency radio or messaging logs confirming containment timeline.

---

### 3.2 Negative Space Rules (NS01–NS08)

#### NS01: Silent Critical Assets
- **Purpose:** Surface critical infrastructure components that have completely stopped generating security events.
- **Logic:** Monitored assets with `criticality >= 3` exhibiting zero events in `log_source_daily` for $\ge 3$ consecutive days, or daily event rate $< P_5$ of peer assets.
- **Benign Explanations:** Planned offline maintenance; air-gapped backup server on standby.
- **Examiner Checks:** Request maintenance ticket or network ping history for the silent IP.

#### NS02: Missing Alert Categories
- **Purpose:** Detect blindspots in detection coverage where peers actively detect standard threat classes.
- **Logic:** MITRE tactics/categories present in $\ge 80\%$ of peer entities but completely absent in this entity's detection catalog.
- **Benign Explanations:** Entity relies on upstream ISP-managed cloud scrubbers for DDoS/Malware.
- **Examiner Checks:** Verify third-party perimeter architecture and outsourced managed controls.

#### NS03: Unexpectedly Low or Flat Activity
- **Purpose:** Identify missing 24x7 coverage or logging collapse.
- **Logic:** Alerts per asset robust z-score $\le -2.0$, CUSUM downward collapse, or night/weekend activity share $<2\%$ of peer median.
- **Benign Explanations:** 8x5 business application with no user activity outside business hours.
- **Examiner Checks:** Review shift rosters to verify if 24x7 SOC shift coverage was formally contracted.

#### NS04: Missing Records & Sequence Gaps
- **Purpose:** Detect audit trail truncation, record deletion, or unrecorded triage.
- **Logic:** Numeric sequence gaps in auto-incrementing alert/case IDs (e.g., ALT-101 $\to$ ALT-105 missing 102, 103, 104) or True Positive alerts with no case management record.
- **Benign Explanations:** Deleted test alerts created during scheduled engineering validation.
- **Examiner Checks:** Review change control records for test execution IDs.

#### NS05: Rule Coverage & Inactive Signatures
- **Purpose:** Detect stale, inactive, or unmaintained SIEM detection catalogs.
- **Logic:** Proportion of enabled detection rules that have zero firings over 6 months; mapping coverage against mandatory MITRE baseline in `config/expected.yaml`.
- **Benign Explanations:** Narrow, high-fidelity custom detection for rare zero-day indicators.
- **Examiner Checks:** Verify if test attacks/adversary simulations have validated rule logic.

#### NS06: Inventory vs. Telemetry Reconciliation
- **Purpose:** Detect shadow assets (unregistered devices generating alerts) and ghost assets (registered devices sending zero logs).
- **Logic:** Cross-references `asset` inventory table against unique `asset_id` values appearing in `alert` and `log_source_daily`.
- **Benign Explanations:** DHCP hostname churn; recently decommissioned hardware not yet purged from CMDB.
- **Examiner Checks:** Reconcile active IP addresses with network core switch ARP tables.

#### NS07: Absent External Regulatory Reporting
- **Purpose:** Identify statutory reporting non-compliance for critical cybersecurity incidents.
- **Logic:** Identifies confirmed critical True Positive incidents lacking a linked record in `external_report` within statutory time window (default 6 hours).
- **Benign Explanations:** Preliminary verbal notification provided to regulator before formal portal filing.
- **Examiner Checks:** Check NCIIPC official incident hotline communications log.

#### NS08: Submission Completeness & Data Quality Deficits
- **Purpose:** Detect data withholding, incomplete log submissions, or corrupt data drops.
- **Logic:** Assesses missing temporal dates, high null-rates on mandatory audit fields, and sudden $>50\%$ drops in ingested volume compared to preceding quarters.
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
  evidence of a shared-vendor problem), and `config/systemic.yaml`'s `excluded_rule_ids` (NS05,
  EG12, EG10) are excluded because they are known to fire near-universally in the current synthetic
  dataset for reasons unrelated to any shared vendor (see docs/validation.md).
- **Rationale for supervisors:** a cluster of identical findings under one shared provider points at
  that provider's own process or detection-engineering practices as the likely root cause, which
  changes the appropriate supervisory response from "counsel this one entity" to "examine this
  vendor's practice across its full client roster." This is SAT-SA's answer to the problem
  statement's invitation to surface additional supervisory signals beyond the illustrative EG/NS
  examples: a correlation across the portfolio that no single-entity rule could ever see.

---

## 4. Scoring, Aggregation & Prioritization Mathematics

### 4.1 Calibrated Rule Score (0–100)
$$\text{Score}(r) = \min\left(100.0, \; \text{Strength}(r) \times \text{SeverityWeight}(r) \times \text{Confidence}(r)\right)$$
- **Severity Weights:** Critical = 1.0, High = 0.8, Medium = 0.5, Low = 0.25.
- **Confidence Damping Factor:**
  $$\text{Confidence} = \min\left(1.0, \; \frac{n}{n_{\min}}\right)$$
  *(where $n_{\min}$ is the minimum sample threshold specified in `config/scoring.yaml`).*

### 4.2 Capability Domain Score (Probabilistic Noisy-OR)
For domain $d$ encompassing $m$ triggered rules with scores $s_1, s_2, \dots, s_m \in [0, 100]$:
$$S_d = 100 \times \left(1 - \prod_{i=1}^m \left(1 - \frac{s_i}{100}\right)\right)$$

### 4.3 Composite Entity Risk Index
$$\text{RiskIndex} = (1 - w_{\text{breadth}}) \left(\sum_{d=1}^8 w_d S_d\right) + w_{\text{breadth}} \times \min(100.0, \; 10 \times N_{\text{distinct\_rules}})$$
- Standard domain weights $w_d$ sum to 1.0 (configured in `config/scoring.yaml`).
- Default breadth weight $w_{\text{breadth}} = 0.15$.
- **Categorical Risk Bands:**
  - $\ge 70.0$: High Supervisory Concern
  - $40.0 - 69.9$: Elevated Supervisory Concern
  - $20.0 - 39.9$: Moderate Supervisory Concern
  - $< 20.0$: Low Supervisory Concern
