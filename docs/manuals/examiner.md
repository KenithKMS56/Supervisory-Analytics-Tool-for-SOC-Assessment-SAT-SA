# Examiner manual

For examiners and analysts who use SAT-SA to decide which CSEs need supervisory attention and
to work those concerns. The full rules of the case workflow are in `docs/examiner_workflow.md`;
the meaning of each analytic is in `docs/analytics_methodology.md` and `docs/analytics_context.md`.

**Findings are indicators for review, not compliance determinations.** A finding says that a
CSE's submitted data shows a pattern worth checking. SAT-SA does not draft, issue or send any
notice. A confirmed concern is the examiner's own conclusion.

## Who does what

| | Analyst | Examiner |
|---|---|---|
| Upload and publish submissions, run assessments, tune rules | yes | no |
| Read the portfolio, entities, findings, evidence, cases and reports | yes | yes |
| Triage review-queue records, open and decide cases, review and adjudicate | no | yes |
| Draw blind-review samples / work blind-review tasks | draws | works |

Whoever runs and tunes the engine does not decide its findings. Closing a case and passing a
verification need a second examiner: someone who neither owns the case nor made the decision.

## 1. Start at the portfolio

The portfolio answers four questions for each CSE: **who needs attention, why, how sufficient
the evidence is, and what to do next**.

- **Risk band.** Low, Moderate, High, Critical, or **Insufficient Evidence** when the submission
  did not let enough rules run. An insufficient entity is never shown as low concern; ask for
  the missing data (the "next action" column names it).
- **Coverage.** How many of the applicable rules could be assessed.
- **Why.** The rules behind the band.
- **Evidence support.** How much evidence a rule's result rests on. It is not a probability that
  the concern is real.
- **Filters and saved views.** Filter, search and sort the table, and save a view you use often.

Every figure is from one assessment **run**, named with its period at the top of the page. A
report or export taken from a page is pinned to that same run.

## 2. An entity's page

- The domain scores and the per-rule results: finding, assessed and clear, insufficient
  evidence, degraded, not applicable (only by a recorded applicability decision).
- The entity's **context**: time zone, operating schedule, approved maintenance windows and
  rule exceptions. These change what the rules count, and each one is shown with who approved
  it and until when.
- The **peer cohort** the run compared the entity with: its members, exclusions, the fallback
  level, and whether the comparison is *established* or only *exploratory* (too few peers).
- **Export Report** → CSE Report PDF, or View Standalone HTML.

## 3. A finding and its evidence

The finding page shows the rule (and its version), what was measured against what threshold,
the records cited as evidence, the peer comparison where one was used, and the run's
configuration. Rejected or held rows never appear as evidence.

From here an examiner can **Open supervisory case**.

## 4. Review queue (record-level triage)

The queue lists records the run selected: those cited by findings, plus random controls that
no finding cites, to keep triage honest. For each record an examiner records **Confirmed
concern**, **Marked as justified** or **More data needed**, with notes. Deciding again adds to
the history and never overwrites it; the counts at the top cover the whole queue.

## 5. Working a case

```
new → assigned → explanation requested → response received → confirmed / dismissed / inconclusive
confirmed → corrective action → verification → closed          dismissed / inconclusive → closed
```

1. **Assign** the case to its owner.
2. **Request explanation**: what the entity must explain, and by when. Then use **Export request
   package**. It downloads a signed package to send to the CSE by your usual channel; SAT-SA
   sends nothing itself.
3. **Record the response**: import the CSE's response package (it is checked, size-limited, and
   importing it twice changes nothing), or record a response that came another way.
4. **Decide**: confirmed concern, dismissed, or inconclusive, with reasons. A wrong decision is
   corrected by a new one that *supersedes* it; the first stays in the history.
5. **Second review**: another examiner records agreement or disagreement. A disagreement blocks
   closure until a third examiner adjudicates.
6. For a confirmed concern, **require corrective action**: what, by whom, by when, and how it
   will be verified.
7. **Verify** against the next comparable period's run. Verification cannot pass when that run
   lacks sufficient evidence for the rule.

If two examiners edit the same case at once, the second save is refused ("stale version").
Reload the page and decide again.

## 6. Blind review

To check the tool against independent judgement, an analyst draws a **blind sample** from a run
(Blind review page): the tool's highest-ranked entities, random entities and low-band controls,
shuffled so the examiner cannot tell which is which. The examiner judges each entity from raw
signals only, then submits, and only then can reveal the system's band.

For a formal pilot, an analyst assigns the same sample to a **second examiner** ("Independent
second review"; it is shown to them in a different order). The evaluation is frozen and
computed with `satsa pilot` (`docs/shadow_pilot_runbook.md`, Part B). Disagreements are
adjudicated by a third examiner.

## 7. Approving rule changes

Thresholds change only through a reviewed version (`docs/rule_governance.md`). Review Tools →
**Rule Changes** lists proposed drafts with what each changes. Approve a change you did not
propose (with a note), or reject it with a reason. An analyst then puts approved changes in
force, which re-assesses the latest period. You cannot approve your own proposal.

## 8. Reports and exports

- CSE report: HTML or PDF, from the entity page. Portfolio report: PDF.
- CSV exports of findings and of the review queue (analysts). A cell that starts like a
  spreadsheet formula is exported as text.

Each report states its run, period and configuration, and says that its findings are
indicators for review.

## 9. Words used on the screens

| Term | Meaning |
|---|---|
| Run | One assessment of one period's published data with one frozen configuration |
| Insufficient evidence | The submission did not allow enough rules to run to classify the entity |
| Degraded | A rule ran on partial inputs; its result is shown with that warning |
| Evidence support | How much evidence a result rests on (not a probability) |
| Exploratory comparison | Too few peers for an established comparison; read it with care |
| Held submission | An upload with rejected rows, waiting for an analyst to publish or discard it |
