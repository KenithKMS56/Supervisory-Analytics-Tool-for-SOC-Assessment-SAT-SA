# Examiner workflow

How a supervisory concern goes from a finding to an evidence-based closure, and how blind review
works. It covers docs/product_brief.md §8. The code is in `src/satsa/cases/`; the routes are in
`src/satsa/api/case_routes.py`; the tables are migration v7 (docs/migrations.md).

## What is and is not a decision

- **Review-queue dispositions** ("Confirmed concern", "Marked as justified", "More data needed")
  are an examiner's triage of one record. They were called "Escalated to Statutory Notice" and
  "CSE Explanation Requested" before Phase 3. Neither label was true, because a click issued and
  sent nothing.
- **A supervisory case** is how a concern is worked: the request for an explanation, the
  decision, the corrective action and its verification.
- **A confirmed concern is the examiner's finding, not a notice.** SAT-SA drafts, approves,
  issues and sends nothing: no email, no legal notice, no claim of external issuance. Notice
  drafting is not part of v1.

## Cases

A case follows one concern: an **entity and a rule**.

- An examiner opens it from a finding's evidence card ("Open supervisory case").
- While it is open, later findings of the same entity and rule are linked to it, not given new
  cases. The case page shows the lineage across periods.
- If a closed concern recurs, the new case links back to the old one ("Recurs after ...").
- At most one case per entity and rule is open; a unique index enforces this.

### States and transitions

```
new -> assigned -> explanation_requested -> response_received
    -> confirmed | dismissed | inconclusive
confirmed -> corrective_action -> verification -> closed
dismissed | inconclusive -> closed
closed -> reopened -> assigned ...
```

Every transition is decided on the server (`satsa.cases.workflow.ACTIONS`). Pages and API
callers can only ask for one.

| Action | From | To | Who | Must carry |
|---|---|---|---|---|
| assign | new, reopened | assigned | any examiner | owner (an active examiner), optional due date |
| reassign | any open state after assignment | (same) | any examiner | new owner, reason |
| request_explanation | assigned, response_received, inconclusive, reopened | explanation_requested | owner | request text, respond-by date |
| record_response | explanation_requested | response_received | owner | explanation (or a response package) |
| decide | assigned, explanation_requested, response_received | confirmed, dismissed or inconclusive | owner | outcome, reasons |
| supersede_decision | confirmed, dismissed, inconclusive | the new outcome | owner | a different outcome, reason |
| record_review | confirmed, dismissed, inconclusive | (same) | an examiner other than the decision maker | agree or disagree, reasons |
| adjudicate | a decision state with an unresolved disagreement | the outcome | an examiner who neither decided nor disagreed | outcome, reasons |
| require_corrective_action | confirmed | corrective_action | owner | action, entity-side owner, due date, verification criteria, reasons |
| submit_for_verification | corrective_action | verification | owner | what the entity reports |
| verify | verification | closed (passed) or corrective_action (failed) | an examiner other than the owner and the decision maker | result, the next-period run, notes |
| close | dismissed, inconclusive | closed | an examiner other than the owner and the decision maker | reasons |
| reopen | closed | reopened | any examiner | reasons |
| add_note | any open state | (same) | any examiner | text or a file |

Who may act:

- **Only examiners act on cases. Analysts can read them.** This keeps the Phase 2 separation of
  duties: whoever runs and tunes the engine does not decide its findings.
- **Sign-off is by a second examiner.** This replaces a separate reviewer role in v1. Closing a
  dismissed or inconclusive case, and passing a verification, need an examiner who is neither
  the owner nor the decision maker.
- **An unresolved disagreement blocks closure and corrective action.** It ends when a third
  examiner adjudicates, or when the owner makes a new decision.

Refusals are reported with the HTTP status of the reason:

| Status | Reason |
|---|---|
| 403 | not allowed for this person |
| 409 | not allowed from this state, or a stale version |
| 422 | missing or invalid input |

### History and corrections

- `case_events` is append-only. Database triggers refuse `UPDATE` and `DELETE` on it and on
  `case_attachments`. Every event is also in the hash-chained audit log, as `case_<action>`.
- A decision is never edited. A correction is a superseding decision that names the event it
  supersedes and says why. The page marks the earlier one "superseded" and keeps it.
- Reviews and adjudications are separate events, so disagreement stays on record.
- `cases` and `corrective_actions` are the current state derived from the events.

### Concurrent edits

- Every form and API call carries the case version it was based on (`expected_version`).
- If the case has changed since, the request is refused with 409 and nothing is recorded. The
  page says to reload and read the latest history first.
- The check and the write happen in one `BEGIN IMMEDIATE` transaction. A test races two
  connections and checks that exactly one wins.

### Evidence files

- Files attached to a note, a response or a verification are stored once, by SHA-256, under
  `data/case_files/<sha[:2]>/<sha>`. They are never rewritten.
- They are served only as downloads (`application/octet-stream`, `nosniff`), to analysts and
  examiners. The hash is checked on every download, and a mismatch is refused.
- Backups include `case_files/`. A restore checks that every referenced file is present and
  intact.
- Limits: 20 MiB per file.

## Response packages (offline explanations)

v1 has no portal for regulated entities. The exchange is by file.

1. The owner records an explanation request (what to explain, respond-by date), then exports the
   **request package**, a zip containing:
   - `request.json`: case reference, entity id, the concern's rule and title, the request, the
     dates, a token;
   - `response_template.json`;
   - `README.txt`.

   It contains **no score, severity, peer comparison, risk index, evidence record or other
   entity**.
2. The regulator sends it to the entity by its usual channel. SAT-SA sends nothing.
3. The entity returns a zip with `response.json` (the template filled in) and an `attachments/`
   folder.
4. The owner imports it. It is accepted only if all of these hold:
   - It is a well-formed zip: at most 51 files, 50 MiB, 20 MiB per attachment and 100 MiB
     expanded, no compression ratio above 100 for large members, no `..` or absolute paths, and
     only `response.json` and `attachments/<name>`.
   - Its token matches this deployment's HMAC-SHA256 of the request. The key is
     `data/secrets/case_package_key`, created on first use and included in backups.
   - It answers the case's current request, and the case is still awaiting it.
   - It lists exactly the attachments it carries.
5. Importing the same zip again changes nothing. A different response to an already answered
   request is refused (409); request a new explanation instead.

## Next-period reassessment

Remediation is verified, never assumed. Each run after the case's run is evaluated for the
case's entity and rule. A run counts as **sufficient comparable evidence** only if all of these
hold:

- it completed and is later than the case's run;
- it is a period-limited run (`mode: window`) whose period starts at or after the end of the
  original finding's period;
- the rule has the same version as when the case was opened;
- the rule assessed the entity and found it clear (`assessed_clear`), with no finding.

Anything else is listed as a reason it is not sufficient:

- the rule was not evaluated;
- the data was insufficient or degraded. Missing data is not improvement;
- the rule was not applicable;
- the finding recurs;
- the rule version changed;
- the run covers the original period.

Some differences are warnings rather than refusals: rule parameters, the peer-group definition
or the peer-group size changed. The case page also shows how the evidence changed: the score
before and after, and the evidence records added or no longer cited.

**Nothing closes a case automatically.**
- "Verify: passed" is refused unless the selected run is sufficient.
- "Verify: failed" is always allowed. It sends the case back to corrective action, and the
  corrective action is marked failed.

### Trends

The portfolio trend chart lists comparability warnings between consecutive runs:

- rule parameters changed;
- a rule's version changed;
- the peer-group definition changed;
- a run predates configuration snapshots.

It also warns when an entity's risk index fell while less of its evidence could be assessed
(lower coverage, or not fully classified). A lower score from missing data is not improvement.

## Blind review

Blind review is done through assigned tasks, never on an entity the examiner picks.

1. **An analyst draws a sample** from a completed run and assigns it to an examiner. The analyst
   cannot assign it to themselves. The sample mixes three kinds of entity:
   - **flagged**: the highest risk index among entities the run classified;
   - **control**: random draws from entities in the lowest band;
   - **random**: uniform draws from the rest.

   The draw uses a seed, recorded with the sample. Each task stores its kind, the method, its
   rank or pool size, the seed and the run. Tasks are shuffled with the same seed, so the same
   seed reproduces the same draw and order.
2. **The examiner** sees only their own tasks: position, entity and progress, without the kind.
   A task page serves raw operational signals and a judgement form. The server leaves the band,
   risk index, findings, rule ids, sample kind and provenance out of the page, so they cannot
   leak into hidden fields. Another examiner, or an analyst, gets 403.
3. **Submitting** records the judgement once; a second submission gets 409. At that moment the
   system's index, band and classification for the task's run are fixed, along with the
   agreement score. An entity the run did not classify has no agreement score ("not
   comparable"), never a guessed one.
4. **Revealing** is a separate, recorded step (`revealed_at`), allowed only after submission.
   Only then does the page show the system's assessment, the findings and why the entity was in
   the sample.

The analyst's page lists their samples with progress and the mean agreement of revealed tasks.
Blind reviews from before Phase 3 (`blind_reviews`) are kept as recorded and listed for analysts,
labelled as not blinded to the selection.

## Limits of this version

- **Separation of duties is between examiner accounts.** There is no distinct reviewer or
  approver role. A deployment with fewer than three examiners cannot adjudicate a disagreement,
  and one with a single examiner cannot close or verify anything.
- **Examiners are not scoped to entities.** Any examiner may be assigned any case.
- **No notice drafting,** no portal for regulated entities, and no automatic email or reminders.
  Due dates are shown but not enforced.
- **Blind-task signals use all of an entity's submitted data,** not just the run's review period.
- **Next-period sufficiency** needs period-limited runs (`satsa run --period ...`). A deployment
  that only runs over all submitted data cannot verify remediation.
