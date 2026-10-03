# Examiner Usability Protocol

> **Supervisory Notice:** *Indicators requiring supervisory review; not a compliance determination.*

**Status: protocol only. No session has been run, and no usability result exists.** The results
file `docs/usability/usability_results_template.csv` holds only its header. Nothing in this
repository may be described as measured examiner usability until sessions under this protocol
have been run and summarised with `scripts/usability_summary.py`.

## 1. Question

Can a supervisory examiner who has not used SAT-SA before work out, from the web app alone,
which entity needs attention, why a finding was raised, what evidence it rests on, how far to
trust it, and what to check next? The finding page is built for this in five parts: what was
found, why it matters, evidence, confidence and limitations, next step
(`src/satsa/ui/templates/finding_detail.html`).

## 2. Participants

- 5 to 8 participants who do supervisory or audit work on SOCs, signed in with the
  **NCIIPC Examiner** role. People who built or tested SAT-SA do not take part.
- Record each participant only as `P01`, `P02` and so on. No name, employer or contact detail
  goes into the results file.
- Ask before the session: years in SOC supervision or audit (0-2, 3-5, 6+), and whether the
  participant has seen SAT-SA before (expected: no). Keep these answers outside the results
  file.

## 3. Setup

- One laptop, offline, running `satsa serve` on the synthetic demo data:
  `satsa generate-data && satsa ingest && satsa run`. The same data and the same run for every
  participant.
- A facilitator reads each task aloud, starts and stops a stopwatch, and records the outcome.
  The facilitator does not help. If the participant asks for help, the facilitator answers
  "what would you try?" once; a second request is recorded as an error and the facilitator
  then helps, so that the next task can start.
- Participants think aloud. No screen or audio recording is needed; the facilitator's notes
  are enough.

## 4. Tasks

Read each task exactly as written. Start timing when the task has been read; stop when the
participant gives the answer or says they cannot.

| ID | Task as read to the participant | Correct when the participant |
|---|---|---|
| T1 | "Which entity would you look at first, and why?" | names the entity at the top of the portfolio ranking and gives its band or score as the reason |
| T2 | "Open that entity's highest-scoring finding. In your own words, what did SAT-SA find?" | restates the finding's rule and its main figure (for example the share or count it reports) |
| T3 | "Why would that matter to a supervisor?" | gives the point of the "Why it matters" section in their own words |
| T4 | "Show me one record this finding rests on." | points to a row of the evidence table and reads its record ID |
| T5 | "How far would you trust this finding, and what could explain it innocently?" | mentions the confidence figure or a stated limitation, and one listed legitimate explanation |
| T6 | "What would you check next, outside SAT-SA?" | describes the step in the "Next step" section |
| T7 | "Find this entity's review queue items and say why one of them is there." | opens the queue and reads an item's selection reason (cited by a finding, or random control) |
| T8 | "Produce something you could attach to a file note about this finding." | downloads the finding or entity PDF report |

## 5. What is recorded

One row per participant and task in a copy of
`docs/usability/usability_results_template.csv`:

| Column | Meaning |
|---|---|
| `participant_id` | `P01`, `P02`, ... |
| `task_id` | `T1` to `T8` |
| `seconds` | time from the end of the task's reading to the answer, whole seconds |
| `completed` | `yes` if correct as defined in Section 4, `no` otherwise (including "I can't") |
| `errors` | number of wrong turns: a wrong page opened and left, a wrong answer later corrected, or a second request for help |
| `notes` | anything said or done that explains the result; no personal details |

## 6. Summary

```
python scripts/usability_summary.py <results.csv>
```

prints, per task: participants, completion rate, median time over completed attempts, and the
total and median number of errors. The script uses the standard library only and works on a
results file with no rows (it says so). Report those figures with the number of participants,
and do not pool tasks: they differ in length.

## 7. What the results can and cannot show

- They can show whether examiners new to the tool find and understand a finding, its evidence
  and its limits, and which tasks take long or go wrong.
- They cannot show that findings are correct; that is the subject of the validation reports.
  With 5 to 8 participants, a median time is a rough figure and a completion rate has a wide
  margin; state the count with every figure.
- All data shown to participants is synthetic. Participants' judgement of a synthetic entity
  says nothing about real CSE data; a real-data pilot is pending.
