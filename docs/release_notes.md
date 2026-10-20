# Release notes: product-brief release (Phases 1–5)

Changes since `47f10c9`, the commit reviewed in `docs/product_brief.md`. **This release is not
declared production-ready**: see "Gates still open" below and `docs/release_readiness.md`.

## Upgrading

1. Stop the web app, the Administration Portal and any worker or CLI job.
2. Copy the whole data directory.
3. Run `satsa migrate --data-dir data`. It backs up `satsa.db` before the first pending
   migration and applies operational migrations v1–v10 and catalog migrations v1–v2.
4. Run `satsa verify-data --data-dir data`.
5. Start the three processes (`python entrypoint.py`, or the container).

Every migration adds tables and columns and rewrites no existing row. Recovery per version is
in `docs/migrations.md`. Existing Parquet files are adopted into the publication catalog as
legacy batches; none is rewritten.

**Behaviour you will notice**

- A production deployment starts empty and is set up with a one-time token. Default accounts
  exist only in demo mode.
- The product no longer names an organisation by default. Set yours with
  `satsa deployment brand --organisation "<name>" --actor <you>` (or at first-run setup); until
  then the portals use neutral wording.
- Imports and assessments run as jobs in a worker. The upload page sends you to the job's page.
- An entity whose submission lets too few rules run is *Insufficient Evidence*, never *Low*.
- In production, saving on Rule Tuning proposes a draft: another analyst or an examiner approves it
  (Review Tools → Rule Changes), then an analyst puts it in force.
- Review-queue labels are "Confirmed concern", "Marked as justified" and "More data needed";
  nothing is presented as a statutory notice.
- A web upload with a format error (an alert missing `alert_id`, `created_at` or
  `severity_final`, a repeated `alert_id`, or a severity, status or disposition
  `config/taxonomy.yaml` does not list) is held for review, and the same API submission is
  rejected with 422. Problems that are also supervisory signals (closed before created,
  references to records not submitted, numbering gaps, empty fields) are reported and published
  as before. Set in the new `config/data_quality.yaml`; without it the same defaults apply.

## What is new

**Correctness (Phase 1).** Per-rule results and evidence coverage, with an unknown domain score
instead of zero (B01). One ingestion service for files, the JSON API, the CLI and connectors,
with the same privacy processing and validation (B02). Header and row entity binding, and
period labels normalised to UTC ranges so overlapping labels cannot evade the duplicate check
(B03). The assessment period selects data (B04). Immutable, versioned batches with atomic
publication, so a revision supersedes and is never double-counted (B05). A full analytical
fingerprint and configuration snapshot per run, and `satsa replay` (B06).

**Operations and security (Phase 2).** Durable jobs with leases, heartbeats and safe retries.
First-run setup and an isolated, labelled demo mode. Offline API docs (B07). Keys and
configuration persisted in `data/`. Consistent backups with verified restore and replay. Health
and readiness endpoints. Retention, and a redacted diagnostics package. CSRF and WebSocket
origin checks. Scoped, expiring, revocable service credentials. Idle session timeout. Offline
TOTP MFA for administrators. A signed offline release bundle with SBOM and licence notices.

**Examiner workflow (Phase 3).** Supervisory cases with a server-side state machine, immutable
history, superseding decisions, second-examiner sign-off, reviews and adjudication. Corrective
actions verified against the next comparable period. Offline request and response packages.
Blind review through seeded, assigned tasks.

**Analytics and screens (Phase 4).** Entity context: time zone (exact DST and fractional
offsets), schedule, effective-dated inventory, maintenance windows and rule exceptions with a
second approver and an expiry. Peer cohorts recorded per run with members, exclusions, fallback
level and strength. Provider-level leads with assessable denominators and multiple-testing
control. "Evidence support" instead of "confidence". A portfolio that says who needs attention,
why, how sufficient the evidence is, and the next action. Reports pinned to one run. Responsive
layout (B08).

**Verification and handoff (Phase 5).**

- *Security verification suite* (`tests/test_security_suite.py`): stored, reflected and DOM XSS,
  SQL injection through every list filter, path traversal through file routes, archive bombs
  (ratio, member count, expanded size, a forged size header), request bodies with and without a
  declared length, open redirects, and response headers. Fixed on the way:
  - no security headers were sent: now a CSP, `nosniff`, `DENY` framing and a referrer policy
    on both portals;
  - a chunked request body bypassed the size cap: it is now counted as it arrives;
  - `next=/\host` on sign-in redirected off the portal: closed;
  - the Administration Portal's live activity feed inserted event values into the page
    unescaped, so an analyst-controlled value could run script in an administrator's browser:
    every value is now escaped;
  - values were interpolated into inline JavaScript: they are now carried in escaped data
    attributes or `tojson`;
  - an upload file name with characters Windows refuses failed the upload and leaked a server
    path: stored names keep only portable characters.
- *End-to-end browser workflow* (`tests/browser/test_end_to_end_workflow.py`): register a CSE,
  upload, see why the batch was held, publish, assess, read the evidence, open a case, request
  an explanation (download the package), decide, export the report. A real worker, offline
  Chromium, no browser error.
- *Independent pilot tooling* (`satsa pilot`, migration v9): frozen protocols, independent
  second reviewers, review times, adjudication, and evaluation with Wilson and entity-cluster
  intervals. Unanswered or unresolved labels are never counted as negatives.
- *Benchmarks* extended to skewed, free-text and uneven data, ten concurrent readers during
  ingestion, and repeated submissions (`docs/benchmarks.md`).
- *Performance*:
  - schema checks are skipped on reopening a database already at the current version, so
    readers no longer take SQLite's write lock several times per request;
  - the Parquet scan behind the analytics cache runs at most every 2 s, with publications still
    seen at once;
  - configuration YAML is parsed once per change;
  - free-text redaction hashes only the shingles it keeps and joins its results instead of
    copying every comment.
  - assessment no longer quadratic in portfolio size: NS03 converts time zones once per run,
    NS06 no longer multiplies alerts by log days, NS08 reads the portfolio's months once.
- *Configurable branding*: `satsa deployment brand`, and an optional organisation at setup.
- *Check only*: an upload (or `satsa ingest --check-only`) is validated and its full report shown,
  including which rules the entity could be assessed on, with nothing published.
- *Rule governance* (migration v10): a threshold change is a draft until someone other than its
  author approves it; an analyst then puts it in force (`docs/rule_governance.md`). In production
  *Save* on Rule Tuning no longer changes `config/rules.yaml` directly.
- *Memory preflight* for imports and assessments; *connector conformance suite*; table
  alternatives for every portfolio chart.
- *Drills* executed and recorded: offline install into a clean environment, backup and restore
  with replay, a worker killed mid-assessment (`docs/drills.md`).
- *Manuals*: `docs/manuals/administrator.md`, `examiner.md`, `integration.md`. Also
  `docs/connector_compatibility.md`.

**After Phase 5.**

- *Blocking data-quality checks* (owner decision, 2026-10-20): format errors stop publication,
  supervisory signals stay evidence (`docs/data_contract.md`, "Blocking checks"). New check
  `unrecognised_value`: a value the taxonomy does not list used to be stored as `unmapped` with
  no report. API change log 1.3.
- *Dependency audit*: `pip-audit` on every pinned package found no known vulnerabilities
  (`docs/dependency_audit.md`).
- *Performance*: 5,000,000 alerts across 50 entities ingested and assessed in 162.6-164.2 s,
  against 450.5 s at the end of Phase 5, with identical results on the same data
  (`docs/benchmarks.md`). Tables are held in entity order; the peer rules and the local-time
  figures read portfolio-wide figures once per run; an ingest no longer reloads every table
  after publishing. The memory preflight now assumes 240 bytes per published row.

## Known limitations

- **Field validation has not been done.** No real reviewers or authorised SOC data have been
  used; every accuracy figure in the repository is a synthetic implementation check
  (`docs/validation.md`).
- **No connector is production-verified**; each is verified against fixtures only
  (`docs/connector_compatibility.md`).
- **Benchmarks are from one development laptop**, not the declared 4-vCPU / 8-GiB reference
  machine (`docs/benchmarks.md`). There, 100,000 alerts assess in 4.6–6.3 s and ten concurrent
  readers see a p95 of 0.5–0.9 s (up to 1.5 s while another process ingests); single requests
  reached 3.1 s at 100,000 and 4.5 s at 500,000 alerts during the reload after a publication.
- **The first page after a run is slow on large portfolios**: 55 s at 5,000,000 alerts (17 s on
  2026-10-02), while the web app reloads every table; later pages load in under a second.
  Ingest and assessment of 5,000,000 alerts take under 3 minutes (162.6-164.2 s). Nothing above
  100,000 alerts is a supported tier until the reference machine is measured.
- **One worker per deployment.** Several workers are safe by lease, but are not load-tested.
- **Content-Security-Policy keeps `'unsafe-inline'`** for scripts and styles, because the
  templates still use inline scripts and handlers. The other directives confine every page to
  the portal itself.
- **Windows path length**: install under a short path or enable long paths.
- Analysts and examiners are portfolio-wide (no entity-scoped operator accounts). There is no
  separate reviewer or read-only auditor role; second-examiner rules provide the separation of
  duties.
- No independent penetration test, and no installation on an independent target machine.

## Gates still open

See `docs/release_readiness.md`. Blocked on external resources: field validation (reviewers and
data), production-verified connectors (authentic exports), reference-hardware benchmarks, an
independent penetration test, and installation on an independent machine.
