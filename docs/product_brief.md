# SAT-SA product implementation brief for Antigravity

Copy this entire document into the coding agent, or attach it with the current repository. This is an implementation specification, not a claim that the requested features already exist or that completing code alone guarantees a 10/10 product.

## 1. Your assignment

Act as the senior engineer responsible for turning the existing SAT-SA application into a dependable offline supervisory analytics product. Implement, migrate, test and document the work below in the existing repository. Begin with confirmed correctness defects, then product operations, then examiner workflow improvements. Deliver working vertical slices rather than disconnected screens.

The product analyzes periodic SOC submissions across multiple Critical Sector Entities. It helps human examiners prioritize, investigate and document concerns. Preserve the eight supervisory capability domains and existing useful analytics. Findings are indicators for review, not automatic compliance determinations or legal notices.

The reference review concerned archive commit `47f10c99113349c9c3910e301cdcca1e3a18eb7e`. If this checkout differs, reproduce each issue before changing it and mark already-fixed items with evidence. Read repository instructions, `pyproject.toml`, `uv.lock`, the problem statement, methodology, traceability matrix and existing tests first.

Retain FastAPI/Jinja, SQLite, DuckDB and Parquet unless a demonstrated limitation warrants a narrowly scoped change. Prefer a modular monolith and a local durable worker. Do not introduce cloud services, hosted AI, mandatory telemetry, real-time CSE monitoring, a SIEM, Kubernetes or a replacement frontend solely for novelty. No unrequested deployment or outbound communication.

Default product model: one customer-controlled on-premises deployment containing multiple organizations/CSEs. This is not a shared public SaaS tenancy design. Support offline installation, runtime, administration and recovery. Product branding must be configurable and must not imply government endorsement.

## 2. Evidence baseline and defect register

The previous review ran both portals, browser and HTTP workflows, isolated counterexamples, the bundled suite and a scale benchmark. Results: 1,221 tests passed, 33 skipped, one proxy-dependent test failed and passed on targeted retest without inherited proxy settings; combined statement/branch coverage 89.48%; lint and type checking passed. These are baseline observations, not guarantees for a different checkout.

Confirmed defects to reproduce and fix:

| ID | Observed failure | Required result |
|---|---|---|
| B01 | One asset, no supporting SOC tables: all 20 rules skipped, yet entity scored 0 / Low Supervisory Concern | Insufficient evidence, explicit rule coverage, no reassuring classification |
| B02 | JSON submissions stored clear-text analyst/contact information and accepted malformed timestamps; equivalent file uploads used privacy processing | One validated ingestion path for all transports |
| B03 | Batch header entity differed from row entity; alternate headers bypassed the actual entity/period duplicate restriction | Validated entity binding and semantic idempotency |
| B04 | Ordinary Q1 and Q2 assessment calls used the same full data and identical results, including dates outside Q1 | Explicit period/as-of data selection |
| B05 | Updated alert with the same business ID persisted alongside its old version in current analytical facts | Version-aware selection without duplicate counting |
| B06 | Changing scoring breadth weight changed CSE-03 from 27.7 to 29.7 but left the reported config hash unchanged | Complete configuration/input identity and reproducible snapshots |
| B07 | `/docs` failed offline because Swagger JS/CSS came from a CDN | Local documentation assets and browser offline checks |
| B08 | Desktop upload and 390-pixel portfolio layouts overflowed the document | Responsive, usable layouts and contained table scrolling |

Source-review concerns to verify, not falsely describe as previously runtime-proven: pseudonym salt and edited config are outside the default Compose persistent mounts; automatic demo seeding is unsuitable for production; writes span SQLite/Parquet without a unified publication protocol; NS03 does not use entity timezone/shift context; peer confidence is not calibrated reliability; old finding pages consult current rule parameters; a confirmation is labelled as statutory-notice escalation without a complete notice workflow.

Relevant implementation entry points: `src/satsa/api/routes.py`, `src/satsa/ingest/{pipeline,columnar,manifest,pseudonymise,adapters}.py`, `src/satsa/scoring/{runner,scorer,history}.py`, `src/satsa/store/{sqlite,duckdb}.py`, `src/satsa/rules/`, `src/satsa/peers/`, `src/satsa/auth/`, `src/satsa/admin/`, `src/satsa/report/`, UI templates, `entrypoint.py`, Docker/Compose files and configuration YAMLs. Verify current names before editing.

## 3. Evidence eligibility and risk classification — release blocker

Create persisted results for every applicable rule/entity/run, including rules that produce no finding. Each result needs a state: `finding`, `assessed_clear`, `insufficient_evidence`, `degraded`, or `not_applicable`, with reason, required/missing inputs, evaluated population and relevant evidence references.

Treat `not_applicable` as a documented applicability decision with actor/version; it must not be a shortcut for missing data. Derive required tables/fields and minimum support from one rule-contract registry used by ingestion previews, the runner, APIs, UI and reports.

Distinguish an omitted table, declared complete-but-empty table, rejected/unparseable table and stale table. A missing input is not evidence of a missing SOC control. Empty data may support a negative-space signal only when completeness and an operational expectation justify it.

Compute domain/entity evidence coverage independently of risk. The denominator is applicable rules with justified exclusions. Degraded or missing critical dependencies cannot quietly count as fully assessed. An unassessable domain is unknown, not zero. Do not renormalize a tiny observable subset into apparent full assurance.

Introduce an explicit classification status such as `assessable`, `partially_assessable`, `insufficient_evidence`. A supported critical finding remains visible even if overall assurance is incomplete. Keep data-request priority and observed-risk priority visible separately. Show limitations consistently on portfolio, entity, queue, APIs and exports.

Acceptance: asset-only input yields 0/20 assessed and insufficient evidence; missing escalation data cannot be labelled successful escalation control; complete-empty escalation evidence can support a finding when the rule conditions are met; missing one input does not erase independently supported findings; approved non-applicability is auditable.

## 4. Shared ingestion and connector framework — release blocker

Build a single ingestion service used by upload, CLI, database exports and JSON/API submissions. Use typed canonical schemas, versioned mappings and taxonomy validation; adapters translate formats and never bypass the common service to write Parquet directly.

Validate identifiers, required fields, types, enumerations, timestamps/timezones, chronology, duplicate keys and cross-table relationships. Normalize equivalent supported values. Reject impossible values with file/table/row/field/reason details. Missing optional values remain explicit unknowns, not invented defaults. Preserve useful partial data only in staging until the submission is approved for publication.

The JSON contract must support the canonical tables needed by the rules, including alert/case links, workflow events, escalations and reporting records. Represent missing versus declared-empty tables explicitly. Bind single-entity batches to that entity; reject mixed row entities. If multi-entity batch support is retained, make it a separate explicit contract with authorization and identity checks for every entity.

Apply pseudonymisation, redaction and canonical-column filtering to every transport before analytical persistence. Preserve the stable keyed identity needed for authorized longitudinal linkage. Do not log source payloads, secrets or unredacted free text. If original source evidence must be retained, use a separately permissioned, encrypted evidence store with retention policy; analytical storage must not become an accidental raw-data archive. Record transform/key versions, without including secret keys in replay exports.

Use idempotency keys scoped to deployment, submitter/entity and submission meaning. Repeating the same key/payload returns the existing result; the same key with different content returns a conflict. Define overlaps among monthly, quarterly and half-year batches; alternate labels must not evade duplicate/overlap policy. Corrections create revisions referencing prior batches.

Add bounded upload size, archive entry count, decompressed size, compression-ratio limits, parsing time and staging disk limits. Retain traversal protection. Quarantined data must remain access-controlled and have bounded retention. Add mapping preview: recognized fields, missing requirements, likely rule eligibility and accepted/rejected counts before publication.

Provide a connector contract and fixture-based conformance tests. Implement an honest compatibility matrix for existing vendor mappings. Validate at least one authentic authorized export before calling a connector production-verified. Keep remote/internal API retrieval disabled unless explicitly configured for bounded periodic imports on an approved internal allowlist; never add continuous collection.

Acceptance: equivalent API/CSV/JSON/SQLite data produces equivalent canonical records and analytical outcomes; malformed inputs do not silently succeed; fake header entities cannot evade rules; sensitive test strings never enter analytical files/logs; an invalid final table does not leave a partially published batch; retries do not duplicate evidence.

## 5. Versioned data, time semantics and atomic publication — release blocker

Create immutable batch revisions and per-table manifests. Each records entity, source, schema/mapping versions, declared completeness, start/end dates, source hashes, received time, revision parent and publication state. Namespace business keys by entity and source system as needed so unrelated vendors' IDs cannot collide.

Retain record revisions with operational/event time and time received/known to the system. Do not deduplicate updates using full-row equality. Build analytical views that select the appropriate record version for the requested snapshot. Preserve old evidence and findings when corrections arrive.

Make assessment input explicit: period start, exclusive end, as-of cutoff, source snapshot and policy for late-arriving records. Use consistent UTC storage plus entity timezone for operational interpretation. Define per-table rules: alerts created within the window, cases carried into the window/backlog, inventory effective at cutoff, workflow/escalation events and unresolved obligations. A blanket date filter on every table is insufficient.

Distinguish historical-as-known-at-the-time from retrospectively corrected assessments. Mark unavailable historical state rather than fabricating it from a final export. Never let a later closure, disposition, escalation or revised record silently alter an earlier as-of result. UI, CLI, API, preview and scheduled jobs must use the same selection service. Keep cumulative-history mode explicit.

SQLite and filesystem writes are not one native transaction. Implement staged immutable files, integrity checks, same-filesystem atomic publication where applicable, and a short SQLite metadata transaction that marks a complete manifest published. Readers consume only committed manifests. Recover/quarantine orphan staging files after a crash. Serialize conflicting publications and make recovery idempotent. Publish run results together only after all required result components succeed; failed runs are not latest successful runs.

Use versioned database migrations. Back up before migrations; validate counts, identities, foreign keys and historical findings; do not destroy legacy data to make tests pass. Legacy missing provenance is labelled unknown. Provide a tested upgrade and documented restore-based recovery path for migrations that cannot safely be reversed.

Acceptance: Q1/Q2 fixtures intentionally contain different evidence and produce correctly bounded results; boundary/timezone/late-arrival tests pass; duplicate revisions are not double-counted; readers never see half a batch/run; interrupted imports, full disks and worker termination recover without hidden data loss; old published runs remain unchanged.

## 6. Reproducible assessments and rule governance

Snapshot and hash all analytical inputs: batches/record versions, rule definitions, scoring, peers, systemic/anomaly settings, expected-pattern policy, mappings/taxonomy, applicability/exception policies, time selection, code revision, dependency lock, deterministic seeds and relevant runtime versions. Store full configuration snapshots as well as hashes.

Keep a unique execution/run ID distinct from the deterministic analytical fingerprint. Audit timestamps and generated run IDs may differ on replay; normalized analytical content must be deterministic within the supported, pinned environment. Document any measured numerical tolerances instead of claiming bitwise equality across arbitrary hardware.

Old finding pages and reports read the old run's parameters, baseline membership and evidence, never current YAML. Add an offline replay command and comparison report. Replay bundles include integrity manifests and necessary minimized data, with explicit access controls and optional encrypted originals. Verify hashes/signatures before import; audit-log integrity alone does not prove the source data was truthful.

Add draft → preview → approval → active → retired rule-pack versions. Preview changes against a frozen snapshot and show affected findings, coverage, ranks and sampling. Preserve analyst/examiner separation; support approval by a separate authorized reviewer. Rollback selects a prior signed/configured version without rewriting old runs. Bootstrap signing trust locally; do not trust a package merely because it contains its own public key.

Acceptance: changing any result-affecting configuration changes the analytical fingerprint; the existing scoring-weight counterexample is caught; an old finding retains original parameters; replay matches normalized results; tampered input/config/rule packs are rejected; changing a threshold does not modify an approved historical assessment.

## 7. Context-aware analytics and defensible comparisons

Extend entity context with timezone, operational schedule, SOC model, monitoring expectations, effective-dated inventory, approved maintenance and documented exceptions. Reuse existing fields where possible. Apply context to NS03 and other time/coverage rules. Exceptions require reason, scope, evidence, approver and expiry; they must not permanently hide future concerns.

Use appropriate peer cohorts: sector, size/exposure, SOC model and operating schedule where there is sufficient data. Record membership, excluded entities, fallback level, denominator and minimum support for every comparison. Avoid over-partitioning tiny datasets. Where evidence is weak, show an exploratory comparison or use a documented fallback rather than an authoritative peer judgment.

For negative space, establish why activity should exist and whether the submission covers that expectation. Differentiate inactive assets, legitimate maintenance, missing submission and actual monitoring silence. Do not infer reporting-law breaches from severity alone; reporting applicability/windows must be explicitly versioned, authorized organizational policy.

For provider-level signals, show affected/assessable clients, provider-group size and comparison rate. Co-occurrence is a hypothesis, not proven shared-vendor causation. Keep exploratory leads separate from confirmed findings. Rank/bound exploratory results and measure false discoveries on held-out data.

The current sample-size-based confidence is not a calibrated probability of correctness. Label it as evidence support or replace it with a justified, documented measure. Evaluate correlated rules and sensitivity before presenting noisy-OR scores as probabilistic. Missing evidence must not dilute supported critical concerns.

Acceptance: fractional-offset and daylight-saving fixtures behave correctly; maintenance changes only approved scope/time; missing-input scenarios do not become confirmed monitoring failures; sparse peer cohorts are clearly flagged; anomaly baselines never include future information; rationale and evidence reproduce each displayed comparison.

## 8. Complete examiner workflow

Implement a persistent supervisory case linked to findings, run and evidence versions. Support: new concern → assigned review → explanation requested → response received → confirmed/dismissed/inconclusive → corrective action → verification → closed or reopened. Define permitted transitions and roles on the server.

Store owner, due date, rationale, evidence attachments, request/response history, reviewer sign-off and verification criteria. Reviewers can record disagreement and adjudication without overwriting earlier judgments. Preserve immutable decision history; allow correction through a superseding decision with reason.

A finding confirmed is not a statutory notice issued. Rename the existing misleading label. If notice drafting is included, keep draft, approved, exported and externally issued distinct. Do not automatically send email, create legal notices or claim external issuance from a local feedback click.

Use an offline response-package import/export flow for CSE explanations in v1. Do not expose a half-implemented CSE portal or grant new CSE roles access to supervisor-only evidence. Add a scoped portal only as a complete separately tested workflow if genuinely needed.

Add next-period reassessment: link recurring concern lineage, show what evidence changed, and require sufficient comparable evidence before concluding remediation worked. A score decrease caused by missing data is not improvement. Add rule-version/cohort-change warnings to trend comparisons.

Keep blinded review genuinely blinded: separate task assignment and server-side access paths from scored views for the blind task; record reveal time; do not serve scores in hidden HTML/API fields. Use random/control samples as well as flagged records and preserve sample provenance.

Acceptance: a concern can proceed end to end through an authorized human decision and evidence-based closure; unauthorized transitions fail; conflicting concurrent edits are detected; history remains intact; insufficient next-period evidence cannot auto-close remediation; blind-task responses contain no leaked scores.

## 9. Durable jobs and product usability

Run imports, assessments and large exports as durable local jobs rather than long synchronous web requests. Persist queued/running/succeeded/failed/cancelled states, progress stages, heartbeats, attempts, input fingerprints, safe retry policy and structured errors. Use a local worker with leases and bounded concurrency; avoid an in-memory background-task queue for work that must survive restart.

Concurrent users can read stable completed assessments while one worker publishes new data. Avoid uncontrolled parallel SQLite/Parquet writers. Retry/cancellation must not duplicate findings or leave a partial published run. Provide disk/memory preflight checks and visible job status without invented progress percentages.

Build a first-run setup flow: create admin, set deployment identity/timezone, choose storage/retention, configure TLS if network-exposed, then import a sample explicitly. Production starts empty. Demo mode is opt-in, isolated and persistently labelled.

The portfolio should answer: who needs attention, why, evidence sufficiency and next action. Add filter/search/sort, saved assessment views, contextual help, concise evidence cards and a side-by-side review panel. Use consistent terminology, units, timestamps and source period labels. Provide usable loading, empty, error and permission states.

Fix B08. Test desktop/laptop/tablet/narrow widths; tables may scroll inside containers but must not break the page. Support keyboard navigation, visible focus, labelled fields, non-color status cues and readable chart/table alternatives. Keep all fonts/icons/scripts local.

Acceptance: a user can upload, inspect validation, publish, run, review evidence, request a response, record a decision and export a report through the UI; refreshing/restarting does not lose job state; representative screens have no unintended page-level overflow or browser errors.

## 10. Access control, privacy and secure defaults

Define a documented permission matrix for deployment administrator, analyst, examiner, reviewer/approver, read-only auditor and service account, implementing only roles with complete workflows. Separate organization/entity scope from role. If a role is intentionally portfolio-wide, say so explicitly. Apply the same checks to lists, counts, search, downloads, jobs, attachments and WebSockets, not only entity detail routes.

Remove known production default passwords. Use a local one-time administrator bootstrap, secure password storage, login throttling, revocation and session expiry. Add offline-capable privileged-user MFA/recovery without cloud dependencies. Protect cookie-based mutations with CSRF defenses and origin checks. Use TLS and secure cookies for network-exposed deployments; keep loopback development mode explicit. Validate WebSocket origins and permissions.

If programmatic ingestion is exposed, provide scoped, expiring, revocable service credentials; store verifiers rather than recoverable tokens, display secrets once, audit use and cap request sizes. Do not make browser-session cookies the long-term machine integration contract. Version the API and preserve documented migration/deprecation behavior.

Address SQL/path traversal, XSS, unsafe upload handling, CSV formula injection, authorization bypass and resource exhaustion. Use an explicit threat model and a versioned security verification checklist based on appropriate OWASP ASVS requirements. Verify controls rather than claiming certification.

Persist pseudonym keys, approved config and signing state in protected storage; do not mount them into user-facing static paths. Design key rotation with versioning and longitudinal linkage consequences, not silent regeneration. Use vetted encryption for sensitive evidence/backups; document deployment volume encryption and separate recovery-key custody. An application cannot claim protection from a fully privileged host administrator merely because files are encrypted locally.

Make retention configurable by data class, with documented hold/archive/delete decisions and audited permissions. Do not promise forensic secure erasure on arbitrary hardware. Ordinary UI deletion must not silently erase historical assessment evidence. Export support diagnostics only through a reviewed, redacted package with no automatic external upload.

Acceptance: deny-path tests cover every resource type; blocked users/service keys lose access promptly; leaked IDs do not cross unauthorized scopes; CSRF/XSS/injection fixtures are handled safely; logs/exports contain no secrets; key changes and retention actions are auditable and recoverable where promised.

## 11. Offline distribution, upgrades and recovery

Fix B07 by serving local Swagger assets or shipping a clearly documented local alternative. Exercise all application/browser paths with external DNS/HTTP unavailable, not just mocked Python sockets. Keep the runtime egress guard as defense in depth, not a replacement for host/network controls.

Ship a versioned offline release bundle with matching dependency wheels, application artifacts, checksum/signature manifest, migration scripts, local documentation, license notices and software bill of materials. Online build preparation may download pinned inputs; installing/running on the target must not. List exact supported OS/architecture/Python combinations and test each advertised configuration.

Provide verified container and native-install paths only to the extent they are tested. Persist data, published manifests, configuration, pseudonym keys and required signing state. Run services with least necessary privileges. Both portals and the worker must use the same intended deployment state.

Implement consistent backup/restore across SQLite, immutable Parquet snapshots, attachments, manifests and secret/config state. Use a safe database backup method and a coordinated snapshot/quiescence protocol; do not rely on copying a live database file while ignoring its write-ahead log. Restore to a clean location and validate integrity and fingerprints. Document backup encryption/key recovery separately from ordinary report export.

Add local health/readiness checks, disk thresholds, job heartbeat checks, redacted structured logs, retention cleanup, offline diagnostic export and dependency update instructions. Product telemetry stays local. Define measured recovery objectives after drills rather than inventing achieved RPO/RTO values.

Acceptance: clean offline installation works; both portals and the worker start; container recreation preserves pseudonyms/tuning; a signed update is verified; failed migration recovery restores a consistent state; an independently restored instance reproduces a selected assessment.

## 12. Data model and refactoring guidance

Adapt existing tables instead of creating duplicate sources of truth. Conceptually support: deployment settings and migration history; entity/source profiles; submission/revision and table manifests; record revisions; immutable assessment snapshots; rule results and coverage; findings and evidence; review cases and decision events; corrective actions/verifications; rule-pack versions/approvals; jobs/leases; service credentials/scopes; retention/backup metadata.

Use foreign keys, appropriate uniqueness constraints and indexes, optimistic concurrency for editable workflows, and explicit state transitions. Keep immutable historical content separate from current projections. Store large evidence outside SQLite with integrity-tracked immutable references where justified. Published Parquet files should not be rewritten in place by correction flows.

Split the large API/store/admin modules incrementally into routers and tested application services. Keep authentication, authorization, auditing and validation centralized. Preserve external contracts or provide an explicit version/migration plan. Avoid a wholesale rewrite that discards working tests and analytics.

## 13. Verification and release gates

Add regression tests that fail on B01–B08 before fixing them. Do not weaken assertions, remove inconvenient tests, hard-code fixture outcomes or disable auth to obtain green results. Production startup/rotation tests must exercise real enforcement rather than inherit broad test-suite bypass fixtures.

Test unit logic, API/file parity, period boundaries, late corrections, replay, RBAC/CSRF, batch idempotency, failure recovery, migration, backup/restore and browser workflows. Include malformed/unfamiliar inputs and independent expected outcomes. Diagnose proxy-related tests using a controlled environment; never silently disable the product guard.

Benchmark uniform and skewed entities, large free-text fields, uneven periods, multiple readers during ingestion and repeated submissions. Report hardware, versions, counts, peak memory, disk and latency percentiles. Separate ingestion, assessment and first/cached page latency. Report anomalies and failures honestly.

Proposed v1 service targets, not achieved promises or SIH requirements: on a declared 4-vCPU/8-GiB entry configuration, 100k representative alerts should assess within 60 seconds, normal warmed dashboard/API reads should have p95 under 2 seconds with ten read sessions, and one worker should stay within a documented memory budget while readers remain responsive. Establish the baseline first; explain and record justified budget changes rather than editing tests to conceal regressions. Test larger datasets on a separately declared supported tier before advertising scale.

Release blockers: unresolved B01–B07; unauthorized data access; silent data loss/partial publication; failed replay or restore; runtime external dependencies in advertised offline paths; fabricated validation claims. Browser usability defects must be triaged and fixed before their affected screen is considered complete.

Each completed phase needs code, migration/backward-compatibility evidence, acceptance tests, documentation and a short demonstration. Track every requirement with status `not_started`, `in_progress`, `verified`, or `blocked`, plus implementation/test evidence. A screen or written plan alone is not completion.

## 14. Independent validation — owner-assisted release gate

Extend the existing shadow-pilot tooling; do not invent a second fake evaluation system. Support blinded independent labels, adjudication, reviewer timing, reproducible sampling, baseline comparison and confidence intervals. Split calibration from held-out evaluation by entity/time where appropriate; freeze thresholds before testing. Account for correlated records within entities and small sample sizes.

Measure findings confirmed per fixed review budget, missed important concerns, false positives, reviewer time, disagreement and usability errors. Compare with an explicit manual/stratified baseline under matched conditions; prevent order/memory bias. Inconclusive/missing labels are not automatic negatives. Preserve evaluation settings and reviewer evidence.

Suggested starting study: two independent qualified reviewers, multiple distinct SOC environments, around 100–200 authorized de-identified cases; determine adequacy with the domain reviewers. This small study is an initial pilot, not blanket proof across sectors. Real experts/data cannot be manufactured by the coding agent.

If actual records, reviewers or deployment access are unavailable, deliver the tooling and protocol and mark the field-evidence gate BLOCKED. Report synthetic scores only as synthetic implementation checks. Do not claim 100% real-world accuracy, official regulatory approval, external penetration-test completion or “10/10 production readiness” without evidence.

## 15. Delivery sequence and handoff

Execute in this order, keeping a working application after each phase:

1. Reproduce defects; establish current baseline; write migration and data-contract decisions.
2. Implement shared ingestion, immutable publication, version/time semantics, evidence eligibility and complete run snapshots. Complete B01–B06 acceptance tests.
3. Implement durable jobs, production bootstrap/access/privacy controls, offline docs/distribution, persistent keys/config, upgrades and recovery. Complete offline and restore gates.
4. Implement examiner case/remediation workflow, contextual analytics, transparent peers, usable responsive screens and honest reports. Complete B08 and end-to-end workflow tests.
5. Deliver benchmark/security-verification evidence, operator/integration documentation, pilot tooling and a transparent release-readiness matrix. Conduct real pilot/deployment checks when the required humans/resources are available.

Required handoff: runnable repository; updated lockfile; migrations and recovery instructions; offline install/update artifacts for tested targets; administrator/examiner/integration manuals; API/schema/connector contracts; threat model; test and benchmark reports; source-to-requirement matrix; completed/blocked backlog; release notes and known limitations. Provide the actual commands executed and distinguish measured results from proposed targets.

Operate on the supplied code and implement the work; do not respond with only a plan. Make routine engineering choices, document assumptions and continue with unblocked work. Stop only for genuinely missing inputs, unsafe/destructive decisions or unavailable external resources, stating exactly what is needed. Never fabricate a test, deployment, reviewer decision or audit result. Do not declare the product finished while a mandatory gate is unresolved.

## Implementation references

These are reference documents for the coding agent, not runtime dependencies:

- FastAPI self-hosted documentation assets: https://fastapi.tiangolo.com/how-to/custom-docs-ui-assets/
- SQLite write-ahead logging and its operational constraints: https://sqlite.org/wal.html
- OWASP Application Security Verification Standard: https://owasp.org/projects/asvs

Product completeness means reliable behavior, an operable release, useful examiner workflows and independent evidence of benefit. A numeric score must follow a new review of the implementation and field results; it is not produced by completing a feature checklist.
