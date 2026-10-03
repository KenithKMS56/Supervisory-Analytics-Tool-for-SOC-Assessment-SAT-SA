# SAT-SA Examiner Demonstration Script & Click-Path (about 2.5 minutes)

> **Supervisory Notice:** *Indicators requiring supervisory review; not a compliance determination.*

This script guides an examiner or regulatory presenter through a short live walkthrough of SAT-SA. All data shown is synthetic; a real-data pilot is pending.

The entity names, ranks and figures below come from the default synthetic portfolio (`satsa generate-data && satsa ingest && satsa run`, seed 42), checked against a fresh run on 2026-10-03. If you change the seed or upload other data, read the figures off the screen instead.

---

## Pre-Demo Setup (before start)
Prepare the data and start the examiner portal (port 8001; port 8000 is the NCIIPC administration portal):
```bash
satsa generate-data && satsa ingest && satsa run
satsa serve --host 127.0.0.1 --port 8001
```
Open `http://127.0.0.1:8001` and sign in with an examiner account. Seeded accounts must set a new passphrase on first login, so do this before the audience arrives.

---

## Click-Path & Talking Points

### [0:00 - 0:25] Step 1: Portfolio Heatmap & Risk Rankings
1. **Action:** Navigate to `http://127.0.0.1:8001/portfolio`.
2. **Presenter Script:**
   > *"This is SAT-SA, an offline supervisory analytics tool for NCIIPC's oversight of SOCs.
   > The Portfolio screen ranks 10 synthetic Critical Sector Entities across 8 capability domains, using deterministic rules and Noisy-OR aggregation, with no AI or machine-learning models.
   > Entities with injected operational breakdowns, led by CSE-02, CSE-08 and CSE-03, rank at the top of the risk index, while CSE-01, CSE-04 and CSE-06 score zero and sit in the low-concern tier."*

---

### [0:25 - 0:50] Step 2: Entity Profile & Reported vs Recomputed KPIs
1. **Action:** Click on **CSE-02** (Apex Central Bank) to open `/entity/CSE-02`.
2. **Presenter Script:**
   > *"Let's drill into CSE-02. Here we see the entity's 8-domain radar chart against the median of its peer cohort (the cohort is named above the chart; in this demo portfolio it is all large entities, since there are too few banks for a sector cohort).
   > Down in the Reported vs Recomputed KPI panel, the entity declared an MTTR of 35 minutes, but recomputing it from the alert timestamps in its own submission gives 80.8 minutes, a 131% gap, flagged under rule EG10. The panel breaks this down by severity."*

---

### [0:50 - 1:15] Step 3: Execution Gap Finding Card (Evidence & Examiner Check)
1. **Action:** Click on finding **EG01 (Fast High-Severity Closure)** under **CSE-03** (`/finding/...`).
2. **Presenter Script:**
   > *"Each finding explains itself. Here is the finding card for EG01 on CSE-03.
   > It shows the plain-language rationale, why the control matters, the parameters and peer comparison used, the confidence and limitations, and a suggested examiner check.
   > CSE-03 closed 195 of 488 human-handled High and Critical alerts (40%) faster than the peer 5th-percentile close time of about 30 minutes, with at most one workflow event. The evidence table lists those alert IDs, so the examiner knows exactly which records to request."*

---

### [1:15 - 1:35] Step 4: Negative Space Finding (Silent Assets)
1. **Action:** Click on finding **NS01 (Silent Critical Assets)** under **CSE-05** (National Rail Freight Logistics).
2. **Presenter Script:**
   > *"SAT-SA does not just evaluate alerts that occurred; it also looks for Negative Space: what should have happened but didn't.
   > Here NS01 shows a criticality-4 SCADA controller that is marked as monitored yet recorded zero log events on 16 days, a logging blind spot that alert-only metrics would not show."*

---

### [1:35 - 1:55] Step 5: Exploratory Leads & Controls to Prioritise
1. **Action:** Back on `/portfolio`, scroll to **Controls & Processes to Prioritise**, then click the **Leads** count for **CSE-09**.
2. **Presenter Script:**
   > *"Beyond the 20 rules, the portfolio ranks which controls failed at the most entities and which capability domains are weakest across the sector.
   > SAT-SA also runs an exploratory scan of about 40 metrics for peer outliers and month-on-month shifts. These are leads, not findings: they are kept out of the risk index and have not been validated. For example, CSE-09 maps only 54.5% of its enabled detection rules to a MITRE technique, against 100% for its peers, which no rule tests for. This run raised 9 such leads."*

---

### [1:55 - 2:10] Step 6: Prioritized Review Queue & Lift
1. **Action:** Click **Review Queue** in top navbar (`/queue`).
2. **Presenter Script:**
   > *"Rather than reviewing millions of logs, the examiner uses the Review Queue: the records our findings cite, highest risk first, plus a random control sample from each entity.
   > On our synthetic validation dataset, the top 25 alerts in this queue are about nineteen times as likely to be defect-affected as alerts picked at random, and the whole 130-alert queue about five times (19.47x and 5.19x, `satsa validate`, re-run 2026-10-03). That is a design check on synthetic data, not a real-world guarantee. Examiners can mark audit dispositions directly with one click."*

### [2:10 - 2:25] Step 7: Blinded Supervisory Review (Cognitive Bias Mitigation)
1. **Action:** Click **Blind Review** in top navbar (`/blind-review`).
2. **Presenter Script:**
   > *"To reduce anchoring on the tool's scores, SAT-SA offers a blinded review.
   > The examiner inspects the underlying metrics, such as MTTA, MTTR, SOAR automation share and sample closure comments, with SAT-SA's scores withheld.
   > After the examiner submits an independent verdict, SAT-SA reveals its own assessment and a concordance score, and records the review in the hash-chained audit log."*

---

### [2:25 - 2:35] Step 8: Rule Calibration & Audit Verification
1. **Action:** Navigate to `/tuning` or run in terminal:
   ```bash
   satsa audit verify
   ```
2. **Presenter Script:**
   > *"Finally, supervisory rules are calibratable and signed. In the Rule Studio, supervisors can adjust thresholds and export versioned rule packs signed with HMAC-SHA256.
   > Running 'satsa audit verify' confirms the audit hash chain verifies: an edited, inserted, deleted or reordered entry would break it, and checking against an off-box checkpoint also catches removal of the newest entries. It is tamper-evident, not tamper-proof. Fully offline, zero AI/ML, and every output is an indicator for a human examiner, not a compliance determination."*
