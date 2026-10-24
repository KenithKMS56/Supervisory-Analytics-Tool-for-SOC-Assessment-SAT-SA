# Context-aware analytics and defensible comparisons

This page covers what the assessment takes into account about each entity, who it is compared
with, and how strongly each comparison can be relied on. It covers brief §7 and the Phase 4
part of §9. The code is in `src/satsa/context.py`, `src/satsa/peers/grouping.py`,
`src/satsa/rules/systemic.py` and the rules NS01, NS03 and NS06.

## Entity context

| Context | Where it comes from | What it changes | What it never does |
|---|---|---|---|
| Time zone | `entity.timezone` in the submission (IANA name, e.g. `Asia/Kolkata`) | NS03 and the anomaly scan's night and weekend shares read hours in the entity's own zone | It never guesses. An unknown or missing zone is read as UTC, and the finding and entity page say so |
| Operating schedule | `entity.declared_shift_hours` (`09:00-18:00`, `24x7`) | Classified as `24x7`, `business_hours` or `unknown`. It is a peer-cohort attribute and is stated in NS03's rationale | It never suppresses a finding |
| SOC model | `entity.soc_model` | Peer-cohort attribute | |
| Effective-dated inventory | optional asset columns `in_service_from`, `in_service_to` (aliases: `commissioned_on`, `decommissioned_on`, `retired_on`, ...) | NS01 does not count a day outside the asset's in-service dates as silence. NS06 does not count an asset whose in-service dates miss the submitted telemetry period as a ghost | Files without the columns mean "in service throughout" |
| Maintenance windows | recorded on the entity page (below) | NS01 does not count a zero-event day as silence when an approved window covers it, for its asset (or all assets) and dates only | It changes nothing outside its own scope and dates. A day with no telemetry row at all is a missing submission, never silence |
| Rule exceptions | recorded on the entity page | The finding is still recorded and shown, marked with the exception; it is left out of the entity's score and the review queue while the exception is in force | It never covers a critical finding. It lapses at its expiry (at most 366 days) |
| Applicability decisions | recorded on the entity page | The rule's result is `not_applicable` and it is left out of the entity's coverage | |

Time handling: timestamps are stored in UTC. Each one is converted with the entity's zone by
DuckDB's bundled ICU time-zone data, which works offline. Daylight saving and fractional offsets
(+05:30, +05:45) are therefore exact per timestamp. The tests in
`tests/test_context_analytics.py` cover Kathmandu (+05:45) and New York in winter and summer.

### Who records what

| Record | Requested by | Approved by | Rules |
|---|---|---|---|
| Maintenance window | an analyst or examiner | an examiner other than the requester | reason and evidence reference required; at most 92 days; revocable with a reason |
| Rule exception | an examiner | an examiner other than the requester | scope, reason, evidence reference and an expiry within 366 days required; revocable |
| Applicability decision | an examiner | (single decision) | reason required; optional expiry; revocable |

Every step is written to the hash-chained audit log. The database refuses an approval by the
requester even if the API is bypassed (a `CHECK` constraint).

Context applies from the **next** assessment run. A recorded run never changes. The run stores
which decisions, windows and exceptions were in force (its selection, part of the analytical
fingerprint), and a replay resolves them as of the run's start time. Revoking an exception later
does not change what a replay of an older run sees.

## Peer cohorts

The cohort is the first level of `peer_groups.hierarchy` in `config/peers.yaml` that has enough
members:

1. sector, size band, SOC model and operating schedule. Used only with at least 5 members, so a
   small portfolio is not split into cohorts of one or two;
2. sector and size band (at least `min_peers`, 3);
3. sector;
4. size band;
5. every other entity.

Every run records each entity's cohort in `peer_comparisons`: the members, every excluded
entity with the reason ("different sector", "retired"), the fallback level, the denominator and
the minimum support. A comparison is:

- **established** when it has at least `min_support` (5) members and is not the all-entities
  fallback;
- **exploratory** otherwise. It is shown, but marked, and never presented as an authoritative
  peer judgement;
- **none** when there is nobody to compare with.

The entity page, finding page and reports show the cohort the run recorded, not one re-derived
from today's data. Runs recorded before Phase 4 say "not recorded for this run". Their radar
peer median is labelled as re-derived from current data.

Within a rule, only peers with enough data enter a comparison: NS03, for example, needs 100
alerts per peer. The finding records that denominator and the peer ids it actually used
(`peer_count`, `peer_ids`), so each displayed comparison can be reproduced.

## Evidence support, not confidence

The figure stored as `confidence` is `min(1, n / min_sample)`: how much data the rule examined
against its minimum sample. It is shown as **evidence support** and is not a probability that
the finding is correct. Domain scores combine rule scores with a noisy-OR formula so that
several moderate failures add up. Rules that test related behaviour fire together, so the result
is a ranking aid, not a calibrated probability (docs/analytics_methodology.md §4.2). Missing
evidence does not dilute a supported critical finding: a critical finding still sets the band
floor, and an exception never covers it.

## Provider-level leads

A provider-level lead is listed when at least `min_entity_count` (3) clients of the same
third-party SOC provider trigger the same rule in a run. Each lead shows:

- **affected / assessable / group size**: clients that triggered the rule, clients whose data
  could support the rule (a client with insufficient evidence is neither affected nor clear),
  and all of the provider's clients in the run;
- **comparison rate**: the same rate among assessable entities with other providers;
- **p and q**: a one-sided hypergeometric (Fisher exact) test of the provider's count against
  the portfolio rate, and the Benjamini-Hochberg q-value across every provider-and-rule pair
  tested. Leads are ranked by it. A lead with q above `max_q` (0.2) is marked weak.

Co-occurrence is a hypothesis to examine with the provider, not proof that the provider caused
the gaps. Leads never enter a score or the review queue. Their false-discovery rate can only be
measured on held-out, independently labelled data. That is part of the field-validation gate,
which is **blocked** until real reviewers and data are available (docs/release_readiness.md).

## Anomaly baselines

The anomaly scan's time-shift test sets each entity's baseline from its first
`reference_months` months and tests only later months against it. The CUSUM and EWMA charts
(`satsa.peers.spc`), when not given a reference, take their baseline from the first five values
only. A later value never moves an earlier baseline: `tests/test_context_analytics.py` changes
the last month and checks that the baseline and its reference months stay the same.

## Portfolio and reports

The portfolio answers who needs attention, why, how sufficient the evidence is and what to do
next:

- **Why it needs attention**: the highest-scoring finding not under an exception, or "too
  little evidence to classify" with the missing tables.
- **Evidence**: classification status, the rules assessed out of those applicable, and what is
  missing.
- **Next action**: continue the open case, review the evidence and open a case, request the
  missing data, or no action.

The portfolio can be searched, filtered by band and by evidence, sorted, and pinned to any
recorded run. A filter set can be saved as a named view, private to its user.

Reports and exports (HTML, PDF, findings CSV, queue CSV) are built from one run (`run_id`, or
by default the latest), from the same stored results the pages show, including each entity's
evidence coverage, recorded cohort and exceptions. Each file is built in a private temporary
directory, so concurrent downloads cannot overwrite each other. Every value in the HTML reports
is escaped.

## Known limitations

- Night is fixed at 20:00-08:00 local. The declared schedule is stated and used for cohorts,
  but it does not move the night window.
- Maintenance windows are whole days. An outage of a few hours inside a day is not modelled.
- Monthly series in the anomaly scan are bucketed by UTC month. Hours and weekdays use local
  time.
- Exceptions cover an entity and rule as a whole. The scope is free text recorded for the
  examiner, not a filter on records.
- Rule correlation and noisy-OR sensitivity have not been measured on reviewed outcomes. The
  scores are presented as ranking aids for that reason.
- Peer cohort strength thresholds (3 and 5) are configured defaults, not calibrated values.
