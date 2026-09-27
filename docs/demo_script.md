# SAT-SA 2-Minute Examiner Demonstration Script & Click-Path

> **Supervisory Notice:** *Indicators requiring supervisory review; not a compliance determination.*

This script guides an examiner or regulatory presenter through a crisp, high-impact **2-minute live walkthrough** of SAT-SA.

---

## Pre-Demo Setup (10 seconds before start)
Ensure the local server is running:
```bash
satsa serve --host 127.0.0.1 --port 8000
```
Open your browser to `http://127.0.0.1:8000`.

---

## 2-Minute Click-Path & Talking Points

### [0:00 - 0:25] Step 1: Portfolio Heatmap & Risk Rankings
1. **Action:** Navigate to `http://127.0.0.1:8000/portfolio`.
2. **Presenter Script:**
   > *"Welcome to SAT-SA, NCIIPC's air-gapped supervisory analytics platform for SOC oversight.
   > Here on the Portfolio screen, we see 10 Critical Sector Entities ranked across 8 supervisory domains using deterministic robust statistics and Noisy-OR probability—strictly without AI or black-box models.
   > Notice how entities with operational breakdowns like CSE-07 and CSE-08 immediately surface at the top of the risk index, while disciplined entities like CSE-04 remain safely in the low-concern tier."*

---

### [0:25 - 0:50] Step 2: Entity Profile & Reported vs Recomputed KPIs
1. **Action:** Click on **CSE-02** (Apex Central Bank) to open `/entity/CSE-02`.
2. **Presenter Script:**
   > *"Let's drill into CSE-02. Here we see the entity's 8-domain radar chart benchmarked against banking sector peers.
   > Down in the Reported vs Recomputed KPI panel, SAT-SA exposes an immediate execution gap: the entity self-declared an MTTR of 35 minutes, but recomputing directly from raw SIEM timestamps reveals their actual empirical MTTR exceeds 200 minutes—a major KPI reconciliation gap flagged under rule EG10."*

---

### [0:50 - 1:15] Step 3: Execution Gap Finding Card (Evidence & Examiner Check)
1. **Action:** Click on finding **EG01 (Fast Closures Without Investigation)** under **CSE-03** (`/finding/...`).
2. **Presenter Script:**
   > *"Every finding is completely explainable. Here is the finding card for EG01 on CSE-03.
   > SAT-SA provides a plain-language rationale, dynamic peer thresholds, concrete engineering explanations, and suggested examiner checks.
   > Below, the evidence table lists the exact alert IDs where High and Critical alerts were dismissed in under 120 seconds by human analysts, giving the examiner exact targets for evidentiary subpoena."*

---

### [1:15 - 1:35] Step 4: Negative Space Finding (Silent Assets)
1. **Action:** Click on finding **NS01 (Silent Critical Assets)** under **CSE-05**.
2. **Presenter Script:**
   > *"SAT-SA does not just evaluate alerts that occurred—it detects Negative Space: what should have happened but didn't.
   > Here in rule NS01, SAT-SA identifies two Criticality-4 monitored servers in transport logistics that exhibited complete telemetric silence for consecutive days, uncovering severe logging pipeline failures that traditional SIEM dashboards missed."*

---

### [1:35 - 1:50] Step 5: Prioritized Review Queue & 16.6x Lift
1. **Action:** Click **Review Queue** in top navbar (`/queue`).
2. **Presenter Script:**
   > *"Rather than reviewing millions of logs, the examiner uses our mathematically stratified Review Queue: 70% top-risk alerts combined with 30% stratified random controls.
   > In empirical validation, auditing just 1% of alerts through this queue yields a 16.60x discovery lift over standard random sampling. Examiners can mark audit dispositions directly with one click."*

### [1:50 - 2:10] Step 6: Blinded Supervisory Review (Cognitive Bias Mitigation)
1. **Action:** Click **Blind Review** in top navbar (`/blind-review`).
2. **Presenter Script:**
   > *"To eliminate confirmation bias in regulatory inquests, SAT-SA introduces a Blinded Review Studio.
   > The examiner inspects raw objective telemetry—such as MTTA, MTTR, SOAR automation rates, and comment hashes—with pre-computed algorithmic scores withheld.
   > After the examiner submits an independent verdict, SAT-SA reveals the Inter-Rater Concordance Matrix, comparing human judgment against the mathematical engine and logging the concordance score to our cryptographic audit trail."*

---

### [2:10 - 2:20] Step 7: Cryptographic Rule Calibration & Audit Verification
1. **Action:** Navigate to `/tuning` or run in terminal:
   ```bash
   satsa audit verify
   ```
2. **Presenter Script:**
   > *"Finally, supervisory rules are fully calibratable and signed. In the Rule Studio, supervisors can adjust thresholds and export signed, versioned rule packs with HMAC-SHA256 integrity.
   > Running 'satsa audit verify' confirms the entire supervisory audit chain is intact and untampered. Fully offline, zero AI/ML, and strictly grounded under Section 70A of the IT Act, 2000."*
