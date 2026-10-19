# Shadow-Pilot Runbook

How to measure SAT-SA's real-world accuracy against historical examiner workpapers. Everything in
`docs/validation.md` Sections 2–4 is synthetic; this procedure is the only thing that produces real
evidence. Follow the steps in order: the order is what makes the result credible.

## What you need

- **Submissions** from real CSEs for a past review period (the same data an examiner had).
- **Workpapers** from the manual examination of those same entities and period: what examiners
  found, and what they checked and cleared.
- Entities that were **not** used to choose any threshold. If thresholds were tuned on an entity,
  leave it out.
- An examiner (ideally not the person who ran the tool) for the blind adjudication in step 5.

More entities give tighter results. With fewer than about 10 entities per rule, expect confidence
intervals too wide to conclude much; report them anyway.

## Step 1 — Freeze the rules before looking at any workpaper

1. Make sure `config/rules.yaml` holds the thresholds you intend to test. Do not open the workpapers
   first.
2. Record the file's hash and commit:
   ```bash
   git rev-parse HEAD
   sha256sum config/rules.yaml
   ```
   Every assessment run stores the first 16 characters of this hash as its `config_hash`, and every
   shadow-pilot result repeats it, so a later reader can check the thresholds were not changed.
3. From here until step 6, do not edit `config/rules.yaml` or use the Tuning page. If you must, the
   pilot restarts from this step with entities not yet seen.

## Step 2 — Ingest the submissions and run the assessment

```bash
satsa ingest --data-dir path/to/submissions
satsa run --period 2026-H1
```

Note the run ID. Check the DQ view (`/dq`) first: a submission with broken timestamps or missing
tables will produce findings that reflect the data, not the SOC. In particular:

- `rule_not_assessed` — the entity's submission did not include a table the rule needs, so the rule
  was not run for it. This is neither a finding nor a clean result: ask for the table (a
  header-only file if it is genuinely empty) and re-run, or exclude that rule for that entity from
  the pilot's recall and precision.
- `rule_dependency_empty` — the table was submitted but has no rows for the entity, so the rules ran
  and treat the absence as real. Confirm with the entity that the empty table is complete. (If the
  text says there is "no record of what it submitted", the data predates the manifest: re-ingest
  it.)
- `orphan_foreign_keys` — closures, workflow events, escalations or case links whose alert is not in
  the submission. They distort EG02/EG03/NS04 and can indicate withheld alerts.
- `table_write_failed` / `file_unreadable` — a table could not be stored or a file could not be
  read; fix and re-ingest before assessing.

## Step 3 — Turn the workpapers into a CSV

Columns: `entity_id,record_id,rule_id,label`.

| What the examiner recorded | Row to write |
|---|---|
| An issue that corresponds to a SAT-SA rule | `entity, record (if any), rule_id, confirmed` |
| A rule's subject was checked and found fine | `entity, (blank), rule_id, not_an_issue` |
| A specific record was checked and found fine | `entity, record_id, (blank), not_an_issue` |

- Map each workpaper item to a rule using `docs/analytics_methodology.md` Section 3. Do this
  mapping **without** looking at SAT-SA's findings for the entity, and have a second person check it.
- Record what was *cleared*, not only what was found. Precision can only be computed from
  `not_an_issue` rows that name a `rule_id`.
- An issue that matches no rule is a genuine gap in the tool: keep a separate list of these.

## Step 4 — Evaluate, and export what the workpapers don't cover

```bash
satsa validate --shadow-csv workpapers.csv --adjudication-csv to_adjudicate.csv
```

This prints and stores overall and per-rule recall and precision with 95% confidence intervals,
each rule's firing rate, and the run's rule-config hash. It also writes `to_adjudicate.csv`: every
SAT-SA finding the workpapers neither confirmed nor cleared.

Those findings are **not** false positives and **not** true positives yet. A workpaper is never a
complete audit, so silence says nothing either way.

## Step 5 — Blind adjudication

1. Give `to_adjudicate.csv` to the examiner. It deliberately has no score, confidence, severity or
   risk rank, and is in entity/rule order, so nothing hints at how strongly the tool believes each
   finding. Do not show them the SAT-SA UI for these entities.
2. For each row the examiner uses `what_to_check` and the original submission to decide, and fills
   `label` with `confirmed` or `not_an_issue`. Rows they cannot decide stay blank (and stay
   unadjudicated).
3. Append the filled rows to `workpapers.csv` (the extra columns are ignored) and re-run step 4.
   Repeat until the unadjudicated count is 0 or only undecidable rows remain.

## Step 6 — Read the results

Report, per rule and overall:

- **Recall** — of the issues examiners confirmed, how many SAT-SA raised. Low recall on a rule means
  it misses real problems.
- **Precision** — of the adjudicated findings, how many examiners confirmed. Low precision means
  examiner time wasted.
- **Confidence intervals** — quote them with every figure. "3 of 3" is 100% with an interval of
  roughly 44–100%: not evidence of a reliable rule.
- **Firing rate** — a rule that fires on most entities carries little information even if each
  finding is technically correct. Watch **EG05** (repeat alerts): its repeat threshold now rises to
  each entity's chance level, but real alert streams are far more repetitive than the synthetic
  data, so untuned noisy pairs may still be common (`docs/validation.md` Section 4A). If it fires
  on most entities, raise `min_repeat_count` or `min_unaddressed_pairs` and re-measure (step 7).
- **Peer cohorts** — with a real portfolio, check which cohort each entity got (shown on the entity
  profile). NS03 and EG11 compare against the cohort by robust z-score and fall back to fixed
  thresholds when fewer than 3 peers are comparable; EG01 and NS02 also depend on the cohort.
- **Issues matching no rule** (from step 3) — coverage gaps to consider as new rules.

## Step 7 — If you change a threshold

Any threshold chosen after seeing these results is tuned on this data. Its accuracy must be
re-measured on **different** entities (or a later period): repeat from step 1 with the new config
hash. Reporting the tuned threshold's accuracy on the data it was tuned on would repeat the mistake
described in `docs/validation.md` Section 0.1.

## What the numbers will and won't mean

- They describe these entities, this period, and these examiners' judgement; workpapers contain
  errors and omissions too.
- Entity-level rules (one finding per entity and rule) give at most one data point per entity per
  rule, which is why entity count matters more than alert count.
- A stand-in rehearsal of this pipeline on synthetic labels is in `docs/validation.md` Section 5A.
  Its perfect scores are circular and are not evidence.

---

# Part B: a prospective pilot with blinded reviewers

Part A measures the rules against workpapers that already exist. Part B measures what the brief
asks of a pilot (docs/product_brief.md section 14): whether examiners who follow the tool's
ranking find more important concerns per fixed review effort than a random baseline, judged by
reviewers who cannot see what the tool thinks. It uses blind review (Review Tools → Blind
Review) and `satsa pilot` (`satsa.validate.pilot`, migration v9).

**What it needs, and what cannot be simulated:** at least two qualified examiners who have not
tuned the rules, a third for disagreements, authorised submissions from several distinct SOC
environments, and enough entities: around 100 to 200 entity reviews is a starting point, to be
agreed with the domain reviewers. On a demonstration deployment every figure is labelled a
*synthetic implementation check*.

## B1. Freeze the protocol before anyone judges anything

```
satsa pilot freeze --name pilot-2026-h1 --run <completed run> --actor <analyst> \
    --seed <a number you write down> --calibration 0.3 --budget 10 --notes "..."
```

This records the run's configuration hash (thresholds frozen), a seeded split of the entities
into **calibration** (may be looked at while setting up) and **held-out** (the headline
figures), and the review budget: how many entities an examiner can review per arm. Protocols are
never edited. Only runs with the frozen configuration hash are evaluated; a run under other
thresholds is listed and left out.

## B2. Draw blinded samples

On the Blind Review page an analyst draws a sample from the run and assigns it to examiner A:
the tool's highest-ranked entities (*flagged*, the tool arm), uniform random entities (*random*,
the baseline) and low-band entities (*control*), shuffled with a recorded seed. The examiner
judges each entity from raw signals; the system's view is hidden until they have submitted.

Assign the same sample to examiner B with **Independent second review** (or
`satsa pilot replicate --sample <id> --assignee B --actor <analyst>`). B gets the same entities
in a different seeded order, so neither the order nor A's judgement leaks. The time from first
opening a task to submitting it is recorded as the review time.

## B3. Adjudicate disagreements

`satsa pilot evaluate` lists entities where A and B disagree on whether there is an important
concern (Elevated or Critical). A third examiner, who reviewed neither side, settles each:

```
satsa pilot adjudicate --protocol <id> --run <run> --entity <id> --label Elevated --rationale "..." --actor C
```

## B4. Evaluate

```
satsa pilot evaluate --protocol <id> --out pilot.md --json pilot.json
```

Per arm, for held-out and calibration entities separately:

- important concerns found, overall and **within the fixed budget**: does the tool's ranking
  beat the random baseline for the same review effort?
- rates with **Wilson** intervals and an **entity-cluster bootstrap** interval (several periods
  of one entity are correlated, so the entity is the unit that is resampled);
- **false positives**: tool-arm entities both reviewers judged not an important concern;
- **missed concerns**: random or control entities judged important that the system rated low;
- **agreement**: observed agreement and Cohen's kappa (binary, and linearly weighted on the
  four levels);
- **reviewer time**: median and 90th percentile, overall and per reviewer.

Unanswered tasks and unresolved disagreements are left out of every rate and counted on their
own. They are never treated as negatives.

## B5. What the figures will and will not mean

The same cautions as Part A apply. Also: an examiner's concern level is a judgement, not ground
truth; with tens of entities per arm the intervals are wide; and a difference between arms on
one portfolio and period is not proof for other sectors. Usability errors are measured
separately (`docs/usability_protocol.md`).
