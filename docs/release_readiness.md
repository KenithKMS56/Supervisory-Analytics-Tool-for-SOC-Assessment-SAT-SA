# Release-readiness matrix (docs/product_brief.md)

**SAT-SA is not production-ready.** Mandatory gates below remain unresolved, and two gates
(§14 field validation and §13 independent security testing) cannot be met without
external resources.

The matrix is updated at the end of every phase. Each row is one requirement or acceptance
criterion of the brief and uses one of four statuses:

| Status | Meaning |
|---|---|
| **verified** | Implemented and verified by the tests or commands named in the row. These are automated or local checks, not independent validation. |
| **implemented, not independently validated** | Implemented and covered by our own tests, but the brief asks for validation we cannot do ourselves (real data, real reviewers, an external party). |
| **blocked** | Blocked by a missing external resource, named in the row. |
| **not implemented** | Not done. The row says why, and what deciding or doing it would take. |

Last updated: end of Phase 5 (branch `feat/product-brief-phase5`). Phase 5 is the last phase of the brief's delivery sequence; rows still open say what they need.

## §2 Defect register

| ID | Requirement | Status | Evidence |
|---|---|---|---|
| B01 | Asset-only entity is insufficient evidence (0/20), not Low | verified | `tests/test_brief_defects.py::test_b01_*`, failing at `47f10c9` (docs/baseline_product_brief.md) |
| B02 | JSON submissions get the same privacy processing and validation as files | verified | `test_b02_*`: e-mail, name and phone absent from Parquet; malformed timestamp returns 422 with table, field and row |
| B03 | Header and row entity bound; alternate period labels cannot evade the duplicate rule | verified | `test_b03_*`: mismatched row returns 422 and nothing stored; `2026-02` after `2026-Q1` returns 409; identical retry is an idempotent replay |
| B04 | The assessment period selects data | verified | `test_b04_*`: Q1 and Q2 scores differ; Q1 evidence lies inside Q1; window recorded in the run |
| B05 | Revisions are not double-counted | verified | `test_b05_*`, `tests/test_selection.py::test_a_correction_in_a_later_batch_*` |
| B06 | Config identity covers every result-affecting file | verified | `test_b06_*`: a breadth-weight change alters `config_hash` and `fingerprint` |
| B07 | `/docs` works offline | verified | Swagger UI 5.17.14 vendored under `ui/static/vendor/swagger-ui`; `tests/test_offline_docs.py` (only local assets, validator badge off, needs a session); `tests/browser/test_offline_browser.py::test_docs_renders_offline` renders it in Chromium with every non-local request blocked |
| B08 | No overflow at 390 px or on desktop upload | verified | `tests/browser/test_responsive_layout.py` failed first (upload scrolled sideways by 178 px at 1440 px; 8 pages overflowed at 390-1024 px). Fixed in `style.css` and the templates: contained table scrolling, collapsing grids, a narrower navigation bar, tooltips that take no room. Every analyst and examiner page, the sign-in and splash pages, at 1440/1024/768/390 px: no page-level overflow, no browser error |
| extra | Overwrite-on-error data loss in the Parquet writer | verified | Writer removed. Published files are immutable (`tests/test_migrations.py::test_a_published_file_is_never_overwritten`, `test_a_batch_is_published_whole_or_not_at_all`) |
| extra | KPI case mismatch (`mttr` vs `MTTR`) | verified | `test_declared_kpis_are_compared_whatever_their_case`, failing with `47f10c9`'s EG10 |
| extra | `seed_default_admin` re-promotes admin on every start | verified | Seeding is demo-only and never re-promotes (`tests/test_deployment_setup.py::test_a_demoted_admin_account_stays_demoted_after_a_restart`) |
| extra | Findings CSV covers all runs; HTML report always uses the latest run | verified | Reports and exports take `run_id` (default latest), are built per request in a private temporary directory and escape every value (`tests/test_context_http.py::test_reports_follow_the_selected_run_*`, `test_report_html_escapes_stored_text`) |
| extra | `/api/v1/entities` returned every run's scores (one row per entity per run) | verified | one run (default latest), with coverage (`test_the_entities_api_returns_one_run_*`) |
| extra | Excluded maintenance days were counted only for assets that stayed flagged | verified | found by `test_maintenance_excludes_only_its_own_asset_and_days` while writing it; counted over every asset considered |

## §3 Evidence eligibility and risk classification (release blocker)

| Requirement | Status | Evidence / remaining work |
|---|---|---|
| Persisted per-rule result states with reason, missing inputs and population | verified | `rule_results` table (migration v1); B01 tests |
| One rule-contract registry | verified | `satsa.rules.contracts`, read by the runner; the UI and reports read the per-rule results and coverage it produces; the ingestion report and the *Check only* preview say which rules a submission lets the entity be assessed on (`tests/test_ingest_preview.py`, `tests/test_connector_conformance.py::test_6_*`) |
| `not_applicable` only through audited applicability decisions | verified | recorded and revoked by examiners on the entity page (`/entity/{id}/applicability`), audited, resolved as of the run's time so replays see what the run saw (`tests/test_context_http.py::test_an_exception_needs_a_second_examiner_*`) |
| Table states: omitted, declared empty, rejected, stale | verified | runner `_table_status`; `tests/test_ingest.py` (submitted-empty, not submitted, unreadable), `test_rule_is_not_assessed_when_there_is_no_manifest` |
| Complete-but-empty escalation evidence can support EG03 | verified | `tests/test_ingest.py::test_rule_runs_when_its_table_was_submitted_empty` |
| Missing one input does not erase independently supported findings | verified | `test_b01_missing_escalation_table_*` |
| Unassessable domain is unknown, not 0 | verified | nullable `domain_scores.score`; B01 test |
| Classification status and coverage | verified | `entity_scores.classification_status` and `coverage`; thresholds in `config/scoring.yaml` `evidence_coverage` |
| No renormalising a tiny subset into apparent assurance | implemented, not independently validated | Below 25 % coverage an entity gets no index band, only "Insufficient Evidence" or a finding floor. **Partially assessable entities still show an index band** computed over their known domains. The 25 % and 90 % thresholds are proposed, not validated |
| Limitations shown on portfolio, entity, queue, APIs and exports | verified | portfolio Evidence column, entity page evidence line, queue badge for entities not fully assessable, `/api/v1/entities` coverage fields, coverage in the HTML/PDF reports and the findings CSV (`tests/test_context_http.py`) |
| Separate data-request priority and observed-risk priority | implemented, not independently validated | the portfolio's Next action asks for the missing data separately from the observed-risk review, and lists what is missing. The stored `data_request_priority` ranking itself is not displayed |

## §4 Shared ingestion and connector framework (release blocker)

| Requirement | Status | Evidence / remaining work |
|---|---|---|
| Single ingestion service for upload, CLI, DB exports and JSON API | verified | API now writes JSON sections to a temporary directory and calls `IngestionPipeline.ingest_directory`. No other write path remains (direct `write_partitioned_parquet` calls remain only in the "register entity" form, for its profile and declared KPIs, which hold no personal data, and in tests) |
| JSON contract covers every rule table, with explicit declared-empty | verified | `SUBMISSION_SECTIONS`, `declared_empty`; B02 and B03 tests, `tests/test_batch_submission.py` |
| Entity binding; mixed rows rejected | verified | `bound_entity`; B03 test |
| Privacy processing on every transport | verified | B02 test |
| Timestamp validation with row details | verified | `invalid_timestamps`; B02 test |
| Full typed validation of enums, chronology and cross-table references before publication | not implemented | Timestamps are validated before publication (rejected or held). Enum, chronology and cross-table problems are found by the DQ checks at ingest and shown in the job report and in *Check only* before anything is published, but they do not block publication: some (an alert closed before it was created, a closure with no alert) are both data errors and the supervisory signals rules look for. Making them blocking needs a decision, per check, on which is which (an owner decision, not taken here) |
| Idempotency keys; replay; conflict on different content | verified | B03 test, `test_first_submission_accepted_repeat_rejected` (updated per brief) |
| Overlap policy across month, quarter and half labels; corrections as revisions | verified | `reject_overlap`, `revision_of`, `parent_batch_id`; B03 test |
| Upload and archive limits (size, entries, expanded size, ratio), staging disk | verified | `check_zip_limits`, `_copy_limited`; every request body capped as it arrives (`satsa.web_security.SecurityMiddleware`); disk and memory preflight before an import starts (`tests/test_preflight.py`); bombs by ratio, member count, expanded size and a forged size header, and a chunked body over the cap (`tests/test_security_suite.py`). **No parse-time limit** |
| Held submissions need an explicit publish or discard decision | verified | `tests/test_migrations.py::test_a_held_batch_*`; `/batches/{id}/publish|discard` (RBAC matrix updated) |
| Mapping preview before publication | verified | *Check only* on the upload page and `satsa ingest --check-only` (ingestion policy `preview`): per file, rows that would be stored, filtered or rejected; DQ issues; rule coverage; nothing published, recorded or saved (`tests/test_ingest_preview.py`) |
| Connector contract, conformance tests, compatibility matrix | verified (fixture level) | docs/connector_compatibility.md; `tests/test_connector_conformance.py` runs every shipped file-export mapping through one contract (loads; one published batch for the named entity only; UTC timestamps; no personal identifier; every source row accounted for per file and table; every rule in one coverage state). Every connector is "fixture-verified" only |
| Production-verified connector | blocked | needs an authentic, authorised vendor export |

## §5 Versioned data, time semantics and atomic publication (release blocker)

| Requirement | Status | Evidence / remaining work |
|---|---|---|
| Immutable batches with per-table manifests | verified | `satsa.store.catalog`; `tests/test_migrations.py` |
| Record revisions by business key, never full-row dedup | verified | `VERSION_KEYS`; B05 and selection tests |
| Explicit window, source snapshot, per-table selection rules, masking of later state | verified | `satsa.scoring.selection`; `tests/test_selection.py`; snapshot reads `test_a_reader_can_load_an_earlier_source_snapshot` |
| Entity timezone in operational interpretation | verified | NS03 v1.1.0 and the anomaly scan read hours in the entity's IANA zone (DuckDB ICU, offline); unknown zones read as UTC and said so (`tests/test_context_analytics.py::test_fractional_offset_*`, `test_daylight_saving_*`, `test_unknown_time_zone_*`) |
| Effective-dated inventory | verified | optional asset `in_service_from` / `in_service_to`; NS01 and NS06 v1.1.0 respect them (`test_days_outside_an_assets_in_service_dates_are_not_silence`). Older files load as "in service throughout" |
| Atomic publication; readers see whole batches only | verified | `test_a_batch_is_published_whole_or_not_at_all` |
| Orphan and crash recovery, idempotent | verified | `test_files_left_by_an_interrupted_writer_*`; `satsa recover` |
| Run results published in one transaction; failed runs never latest | verified | `AssessmentRunner` uses `audited_transaction`. A failed run leaves no row and writes a `run_failed` audit entry |
| Full-disk and worker-termination drills | verified (worker); simulated (disk) | Worker killed 20 s into a 2,000,000-alert assessment: no run written, the next worker finished it once (docs/drills.md section 3, `scripts/drill_worker_kill.py`). A full volume was **not** produced; the disk and memory preflights are tested by simulating free space and memory (`tests/test_preflight.py`) |
| Versioned migrations with backup and post-checks | verified | `tests/test_migrations.py`; docs/migrations.md |
| Migration of the deployment's real `data/` | blocked | Never run by us, by design. The owner runs `satsa migrate` on a copy first (docs/migrations.md) |

## §6 Reproducible assessments and rule governance

| Requirement | Status | Evidence / remaining work |
|---|---|---|
| Full config snapshots and hashes; analytical fingerprint distinct from run id | verified | `run_config_snapshots`, `runs.fingerprint`; B06 test |
| Old finding pages read the run's parameters | verified | finding page uses the run's snapshot (`tests/test_finding_page.py`) |
| Reports read the run's parameters | verified | HTML, PDF and CSV reports are built from one run's stored results, coverage, recorded cohort and exceptions (`tests/test_context_http.py`) |
| Offline replay and comparison | verified | `satsa replay`, `tests/test_replay.py` (reproduces after a correction and a configuration change) |
| Replay bundles with integrity manifest | verified (as a backup) | A backup carries `manifest.json` with every file's hash; restore checks it before writing, then replays a selected run in the restored instance and compares fingerprints (`tests/test_backup_restore.py::test_a_restored_instance_reproduces_an_assessment`, `test_a_damaged_backup_is_refused_*`). There is no separate, smaller replay-only bundle |
| Rule-pack draft → approve → active → retired lifecycle | verified | `satsa.rules.lifecycle`, migration v10, docs/rule_governance.md: a change is a draft until someone other than its author approves it (also a database `CHECK`); an analyst puts it in force atomically and the previous version is retired; a draft based on an older version cannot overwrite a newer one; edits outside the lifecycle are recorded and flagged; signed packs are recorded as approved by their signature; demo deployments apply at once and record it (`tests/test_rule_lifecycle.py`, on a production-mode copy) |
| Numerical tolerance across hardware | not implemented | Determinism is pinned (single-threaded DuckDB, `uv.lock`); cross-hardware tolerance is unmeasured |

## §9 Durable jobs and operations

| Requirement | Status | Evidence / remaining work |
|---|---|---|
| Imports, assessments and demo seeding run in a durable worker, not in the request | verified | `satsa.jobs`; `satsa worker` (started by `entrypoint.py`); `tests/test_jobs.py::test_an_upload_becomes_an_import_job_*`, `test_tuning_and_entity_changes_queue_assessments_*` |
| Jobs survive a restart; an expired lease is recovered | verified | `test_a_queued_job_survives_a_restart_*`, `test_an_expired_lease_is_requeued_*` |
| A killed worker loses no job and duplicates nothing | verified | `test_a_killed_worker_process_loses_no_job_and_duplicates_nothing` (kills a real worker process while the job is running) |
| Retries never duplicate runs or batches; unsafe jobs are not retried | verified | deterministic `RUN-<job>` / `BATCH-<job>-a<n>` ids; `test_an_import_retry_continues_*`, `test_a_job_that_is_unsafe_to_retry_*` |
| Duplicate pending work is not queued twice | verified | unique fingerprint index; `test_the_same_pending_work_is_not_queued_twice` |
| Cancellation, structured errors, stage, worker liveness on a job page and API | verified | `/jobs`, `/jobs/{id}`, `/api/v1/jobs/{id}`; `test_cancelling_*`, `test_a_failure_records_*`, `test_the_jobs_page_says_when_a_worker_is_alive` |
| Report and export generation as jobs | not implemented | Reports read one run's snapshot and are built in a private temporary directory, inside the request; moving them to the worker is open |
| Bounded concurrency beyond one worker | not implemented | One worker per deployment (single writer, documented). Several workers are safe by lease and catalog lock; they are not load-tested, so more than one is not supported |
| First-run setup with a one-time token; production starts empty | verified | `satsa.deployment`; `tests/test_deployment_setup.py` (no accounts, no published passphrase, token works once, guessing throttled, CLI path) |
| Demo mode opt-in, isolated, labelled | verified | `SATSA_DEMO`; banner on both portals; a demo process refuses production data (`test_a_demo_process_refuses_production_data`); docs/first_run_setup.md |
| Legacy databases keep working | verified | recorded as production, already set up (`test_a_database_from_before_modes_*`); migrations v3–v6 in docs/migrations.md |
| Health and readiness endpoints | verified | `/healthz`, `/readyz` (database, worker heartbeat, free disk); `tests/test_backup_restore.py::test_health_and_readiness` |
| Retention cleanup; redacted diagnostics package | verified | `satsa ops retention` (old job inputs only, audited), `satsa ops diagnostics`; `test_retention_*`, `test_the_diagnostics_package_*` |
| Memory preflight before large assessments | verified | imports and assessments refused before they start when free memory is below the measured estimate (256 MiB + 200 B per published row; 4x an import's input), figures in the job's error; `SATSA_MEMORY_PREFLIGHT=off` for misleading hosts (`tests/test_preflight.py`) |
| Usability: portfolio (who, why, evidence sufficiency, next action), filter/search/sort, saved views, run selection, B08, labelled fields, keyboard-reachable help, chart table alternative, wide tables scrollable from one sticky bar above them and from the keyboard | verified | `tests/test_context_http.py::test_the_portfolio_says_why_*`, `tests/browser/test_responsive_layout.py` (overflow, browser errors, unlabelled fields, unreachable tooltips at four widths; a wide table has exactly one bar, above it, which moves it and follows it; the arrow keys scroll it; the bar stays pinned under the demonstration banner, uncovered, at 1440 and 390 px) |
| Usability: every chart with a table alternative | verified | the entity radar, the portfolio heatmap and the trend chart each have a table with the same figures, and the charts are labelled images pointing to it (`tests/test_chart_tables.py` checks every cell against the stored scores) |
| Usability: side-by-side review panel, contextual help throughout | not implemented | The finding page holds the evidence card, peer comparison and case form in one place; there is no split-screen panel. Help is per field and per page (tooltips, page notes), not a help system |

## §10 Access control, privacy and secure defaults

| Requirement | Status | Evidence / remaining work |
|---|---|---|
| Permission matrix, enforced and tested per route and role | verified | docs/security/permission_matrix.md; `tests/test_rbac_matrix.py` fails when a route is added without being classified |
| CSRF protection on every cookie-authenticated mutation; WebSocket origin check | verified | `satsa.web_security` (Sec-Fetch-Site, Origin, Referer); `tests/test_csrf.py` on both portals |
| Scoped, expiring, revocable service credentials for the submission API | verified | `satsa service-credential`; hashed verifier, shown once, at most 365 days; `tests/test_access_controls.py::test_a_service_credential_*`, `test_revoked_expired_and_forged_*` |
| Request-size limit on every request | verified | counted on the bytes received, with or without `Content-Length` (`tests/test_security_suite.py::test_a_chunked_body_without_a_length_is_cut_off_at_the_cap`, `test_a_declared_length_over_the_cap_*`, `test_an_upload_streamed_past_the_upload_limit_*`). **No parse-time limit** |
| Idle session timeout on both portals | verified | `SATSA_SESSION_IDLE_MINUTES` (default 30); `test_an_idle_session_ends`, `test_an_idle_admin_session_ends_too` |
| MFA for privileged users | implemented, not independently validated | Admin Portal: offline TOTP (RFC 6238 vector), replay protection, hashed recovery codes, audited reset, required in production (`tests/test_admin_mfa.py`; docs/security/mfa.md). **SAT-SA analyst and examiner accounts have no MFA** |
| CSV formula-injection escaping | verified | `satsa.csv_safe`; `test_formula_like_text_is_exported_as_text`, `test_the_queue_export_neutralises_*` |
| Deleting an entity never erases evidence | verified | retirement instead of deletion, recorded in the run selection; replay still reproduces (`test_retiring_an_entity_keeps_its_evidence_and_replays`). `tests/test_injection.py::test_delete_entity` now checks retirement, as the brief requires |
| Keys and secrets persist outside the image; no silent regeneration | verified | `data/secrets/` (0600 on POSIX), legacy salt imported byte for byte, versioned pseudonym key per batch, rotation refused without confirmation and audited (`tests/test_keys.py`; docs/key_management.md) |
| Secrets directory never served | verified | `test_the_secrets_directory_is_not_served` |
| Threat model and ASVS checklist | implemented, not independently validated | docs/security/threat_model.md (v4), docs/security/asvs_checklist.md (v2; self-assessed; rows marked partial or not implemented are listed there) |
| XSS (stored, reflected, DOM), SQL injection, path traversal, open redirect, security headers | verified | `tests/test_security_suite.py`. Found and fixed: no security headers were sent; a chunked body bypassed the size cap; `next=/\host` redirected off the portal; the Admin Portal live feed put event values into the page unescaped; values were interpolated into inline scripts; an upload name Windows refuses failed the upload. CSP keeps `'unsafe-inline'` for scripts and styles (ASVS V14.4.3 partial) |
| Reviewer / approver and read-only auditor roles | not implemented (as roles) | Separation of duties is enforced between *different accounts* instead: case sign-off, verification and adjudication between examiners (`tests/test_cases.py`), rule changes approved by someone other than their author (`tests/test_rule_lifecycle.py`). No distinct reviewer or read-only auditor role (the brief: implement only roles with complete workflows) |
| Entity-scoped operator accounts | not implemented | Analysts and examiners are portfolio-wide by design (permission matrix) |
| Configurable branding (no hard-coded regulator wording in product chrome) | verified | optional organisation name at setup or `satsa deployment brand` (audited); neutral wording otherwise in both portals, role labels, report headers and file names; a static check fails on any hard-coded name in a template (`tests/test_branding.py`). Stored role values and the NS07 reporting rule's subject keep their wording |

## §11 Offline distribution, upgrades and recovery

| Requirement | Status | Evidence / remaining work |
|---|---|---|
| Versioned migrations, `satsa migrate`, `verify-data`, `recover` | verified | Phase 1; operational migrations v1–v10, catalog v1–v2 (docs/migrations.md) |
| Local API docs (B07) and no external requests from the UI | verified | see B07; `tests/browser/test_offline_browser.py::test_main_pages_make_no_external_requests` |
| Backup: consistent snapshot of SQLite, published Parquet, held batches, job inputs, secrets, case evidence files | verified | `satsa backup` under the catalog writer lock with the SQLite backup API; `tests/test_backup_restore.py` (incl. `test_case_evidence_files_are_backed_up_and_checked_on_restore`) |
| Optional backup encryption | verified | AES-256-GCM in chunks, scrypt key derivation; tampering detected (`test_an_encrypted_backup_round_trips_and_detects_tampering`) |
| Verified restore into a clean directory, never over a deployment | verified | `satsa restore` checks every hash first and replays a run (`test_a_restored_instance_reproduces_*`, `test_restore_never_overwrites_*`, `test_a_held_batch_can_still_be_decided_*`) |
| Backup retention | verified | `satsa backup --keep`; `test_prune_keeps_the_newest_backups_only` |
| Offline bundle with SBOM, licence notices, signed checksum manifest | verified | `satsa offline-bundle --signing-key`, `satsa release keygen / verify`; `tests/test_release_bundle.py` (SBOM matches `uv.lock` and excludes dev tools; tampering, extra and missing files and a wrong key are rejected) |
| Vulnerability scan of dependencies (pip-audit or similar) | not implemented (not run) | `SATSA_AUDIT=1` makes the wheelhouse build run `pip-audit` on the pinned requirements. It was **not run**: it sends the dependency list to an online advisory service, which needs the owner's go-ahead |
| Compose mounts for data, config and secrets | implemented, not independently validated | `docker-compose.yml` mounts `${SATSA_DATA_DIR:-./data}` and `./config`. **No container was built or run in this phase** |
| Backup and restore drill on the deployment's real data | blocked | Never run by us, by design (the owner runs it; docs/backup_restore.md SOP) |
| Offline install into a clean environment | verified (same machine) | wheelhouse built online (37 wheels), installed with `--no-index --require-hashes` into a new venv in 64 s, `pip check` clean, then generate/ingest/assess and the portals' health, readiness and sign-in pages (docs/drills.md section 1) |
| Backup and restore drill | verified (synthetic data) | backup 2.9 s; restore into a clean directory with every hash checked and a replay reproduced in 5.8 s; encrypted backup round-trip; a tampered or wrongly keyed backup refused, nothing written (docs/drills.md section 2) |
| Offline install on an independent target machine | blocked | needs a separate machine |

## §8 Examiner workflow

| Requirement | Status | Evidence / remaining work |
|---|---|---|
| Persistent case linked to finding, run and evidence; lineage across periods | verified | `cases` (migration v7) links finding and run; later findings of the same entity and rule are linked to the open case, a recurrence after closure links back (`tests/test_cases.py::test_lineage_links_recurrences_and_reopening`) |
| Full lifecycle new → assigned → explanation requested → response → confirmed/dismissed/inconclusive → corrective action → verification → closed/reopened, transitions and roles on the server | verified | `satsa.cases.workflow.ACTIONS`; `test_a_concern_goes_end_to_end_to_an_evidence_based_closure`; through the web app `tests/test_case_http.py::test_a_case_is_worked_end_to_end_in_the_browser` (TestClient) and in Chromium offline `tests/browser/test_case_workflow_browser.py` |
| Unauthorised transitions fail | verified | analysts read only; owner-only actions; second-examiner sign-off; wrong state 409 (`test_unauthorised_transitions_fail`, `test_the_json_api_enforces_the_same_rules`, RBAC matrix) |
| Owner, due date, rationale, attachments, request/response history, sign-off, verification criteria | verified | case and corrective-action fields; content-addressed evidence files with hash check on download (`test_case_http.py`) |
| Disagreement and adjudication without overwriting judgements | verified | reviews and adjudications are events; an unresolved disagreement blocks closure (`test_a_disagreement_must_be_adjudicated_by_a_third_examiner`) |
| Immutable decision history; correction by superseding decision with reason | verified | triggers refuse UPDATE/DELETE on `case_events`; `test_history_is_immutable_and_corrections_supersede`; every action in the audit chain |
| Conflicting concurrent edits detected | verified | `expected_version` in one IMMEDIATE transaction; two racing connections, exactly one wins (`test_conflicting_concurrent_edits_are_detected`); stale form gets 409 |
| "Confirmed" is not a statutory notice; misleading labels renamed; no automatic issuance | verified | queue labels "Confirmed concern" / "More data needed"; case page and docs state SAT-SA issues and sends nothing (`tests/test_auth.py`, `tests/test_review_queue_filter.py`). Notice drafting: not implemented (out of v1 scope) |
| Offline response-package export/import for entity explanations; no supervisor-only evidence to entities | verified | HMAC-authenticated request token, idempotent import, refusal of altered, foreign, superseded, malformed, oversized and bomb packages (`tests/test_case_packages.py`). No CSE portal (none exposed) |
| Next-period reassessment: lineage, evidence change, sufficient comparable evidence before remediation is accepted; missing data is not improvement | verified | `workflow.evaluate_run`; verify-pass refused for insufficient, degraded, not-applicable, recurring, rule-version-changed, overlapping and unbounded runs (`test_insufficient_next_period_evidence_cannot_close_remediation`, `test_a_run_that_is_not_a_later_period_is_not_next_period_evidence`); nothing auto-closes |
| Rule-version / cohort-change warnings on trend comparisons | verified | portfolio trend lists rule-parameter, rule-version, peer-definition changes and score falls with lower coverage (`tests/test_trends.py::test_trend_comparisons_warn_*`) |
| Blind review genuinely blinded: assigned tasks, separate server path, no scores served before reveal, reveal time recorded | verified | `satsa.cases.blind`; `tests/test_blind_tasks.py::test_a_task_serves_nothing_scored_until_its_examiner_reveals_it`, `test_only_the_assigned_examiner_works_a_task` |
| Random/control samples alongside flagged ones, sample provenance preserved | verified | seeded, reproducible draw with stored kind, method, rank/pool and seed (`test_a_sample_mixes_flagged_control_and_random_entities_reproducibly`) |
| Field use by real examiners | blocked | needs real examiners and entities; nothing here is a field result |

## §7, §12

| Requirement | Status | Evidence / remaining work |
|---|---|---|
| §7 Entity context: timezone, schedule, SOC model, effective-dated inventory, approved maintenance, documented exceptions | verified | `satsa.context`, migration v8; docs/analytics_context.md; `tests/test_context_analytics.py`, `tests/test_context_http.py` |
| §7 Exceptions: reason, scope, evidence, approver, expiry; never a permanent hiding place | verified | second-examiner approval (also a database `CHECK`), expiry within 366 days, critical findings never covered, excepted findings kept and shown, next run after expiry or revocation counts them again (`test_a_run_records_each_cohort_and_applies_exceptions_*`) |
| §7 Maintenance changes only approved scope and time | verified | `test_maintenance_excludes_only_its_own_asset_and_days`, `test_maintenance_needs_a_different_examiners_approval_*` |
| §7 Missing input is not monitoring silence | verified | a day with no telemetry row is not counted as silent (`test_maintenance_excludes_only_*`); missing tables make a rule `insufficient_evidence`, never a finding (Phase 1, B01) |
| §7 Fractional-offset and daylight-saving fixtures | verified | Kathmandu +05:45; New York EST/EDT (`tests/test_context_analytics.py`) |
| §7 Peer cohorts by sector, size, SOC model and schedule, without over-partitioning; membership, exclusions, fallback, denominator, minimum support recorded | verified | `satsa.peers.grouping.PeerResolver.resolve`, `peer_comparisons` table; `test_sparse_cohorts_are_exploratory_*`, `test_a_small_portfolio_is_not_split_by_soc_model` |
| §7 Sparse cohorts flagged exploratory; pages show the recorded cohort | verified | `_peer_cohort.html` on entity and finding pages; reports state it |
| §7 Each displayed comparison reproducible from what the run recorded | verified | NS03 records the peer ids and denominator it used; the cohort is stored per run; replay resolves context as of the run (`test_a_run_records_*`) |
| §7 Provider-level signals with affected / assessable / group size and comparison rate; a hypothesis, not causation; ranked and bounded | verified | `satsa.rules.systemic` (Fisher exact p, Benjamini-Hochberg q), portfolio columns; `test_provider_leads_report_*` |
| §7 False-discovery rate of exploratory leads on held-out data | blocked | needs held-out, independently labelled data (§14) |
| §7 Confidence relabelled as evidence support; noisy-OR not presented as a probability | verified | finding page, reports, methodology §4.2; `tests/test_finding_page.py` (section "4. Evidence support and limitations") |
| §7 Correlated-rule and sensitivity evaluation on reviewed outcomes | blocked | needs reviewed outcomes (§14); the pilot tooling computes the arm-level figures once labels exist. Scores are presented as ranking aids meanwhile |
| §7 Anomaly baselines never include later information | verified | time-shift baseline from the reference months only; CUSUM/EWMA default to a leading phase-I baseline (`test_time_shift_baseline_is_fixed_*`; `tests/test_anomaly_scan.py::test_cusum_spread_floor_*` updated: a later shift is now detected instead of absorbed) |
| §7 Reporting-law applicability as versioned, authorised policy | not implemented | NS07 still applies its configured rule; per-entity applicability decisions are available (above) |
| §12 Data-model guidance | followed for Phase 1–5 changes (additive migrations, immutable evidence and decision history, projections separate from events, optimistic concurrency, retirement instead of deletion, context resolved as of a time). Examiner routes in `satsa.api.case_routes`, context routes in `satsa.api.context_routes` | |

## §13 – §14 Gates

| Gate | Status |
|---|---|
| Full automated suite, lint, types | verified (end of Phase 1, local Windows 11 / Python 3.13): `coverage run -m pytest tests` 1271 passed, 33 skipped, 0 failed; branch+statement coverage 88 %; `ruff check` clean; `mypy src` clean |
| Full automated suite, lint, types (end of Phase 2) | verified (local Windows 11 / Python 3.13, 2026-10-17): `coverage run -m pytest tests` 1379 passed, 54 skipped, 0 failed. All 54 skips are the RBAC matrix's "public route: exercised once anonymously" entries; no browser test was skipped. Statement coverage of `src/` 89 % (`coverage report --include="src/*"`; branch coverage not measured in this run, so not comparable with Phase 1's figure). `ruff check src tests` clean; `mypy src` clean |
| Full automated suite, lint, types (end of Phase 3) | verified (local Windows 11 / Python 3.13, 2026-10-17): `coverage run -m pytest tests` 1479 passed, 54 skipped, 0 failed. All 54 skips are again the RBAC matrix's "public route: exercised once anonymously" entries; every browser test ran. Statement coverage of `src/` 90 % (`coverage report --include="src/*"`). `ruff check src tests` clean; `mypy src` clean. The first full run found 2 failures, both fixed without weakening a test: the v7 migration's name contained the word "examiner" and so tripped the diagnostics package's no-usernames check (the migration was renamed before release), and the offline page sweep had no ids for the new case, attachment and task routes (it now creates a real case with an evidence file and a real blind task, and requests the task page as its assigned examiner) |
| Full automated suite, lint, types (end of Phase 4) | verified (local Windows 11 / Python 3.13, 2026-10-18): `coverage run -m pytest tests` 1560 passed, 54 skipped, 0 failed. All 54 skips are again the RBAC matrix's "public route: exercised once anonymously" entries (rechecked with `-rs`); every browser test ran, and `tests/browser` was re-run after the last stylesheet change (16 passed). Statement coverage of `src/` 90 % (`coverage report --include="src/*"`). `ruff check src tests` clean; `mypy src` clean. Intended test changes, none weakening an assertion: the golden snapshot was regenerated, and only the NS01/NS03 rationale text, the systemic rationale text and the asset table's new null columns changed (scores and severities identical); the anomaly test now expects the step shift to be detected, because the baseline no longer includes the shifted months; the migration test expects versions 1-8 |
| Browser tests (Playwright) | verified for Phase 2 scope: `tests/browser/test_offline_browser.py` runs a real server process and Chromium 1248 with every non-local request blocked (`/docs` renders; main pages make no external request and raise no browser error; the block itself is proven). Phase 3 adds `tests/browser/test_case_workflow_browser.py`: two examiners in two browser sessions open, assign and decide a case, record a disagreement, and see closure blocked; the case page does not scroll sideways at 390 px. Phase 4 adds `tests/browser/test_responsive_layout.py`: every analyst and examiner page plus sign-in and splash at 1440/1024/768/390 px, with no page-level overflow, no browser error, no unlabelled field and no keyboard-unreachable tooltip (B08). Phase 5 adds `tests/browser/test_end_to_end_workflow.py`: with a real worker process, an analyst registers a CSE, uploads its submission, sees why the batch was held, publishes it and gets a run; the evidence is on the finding page; an examiner opens a case, requests an explanation (downloads the package) and records a decision; the CSE PDF and HTML reports are exported; no external request, no browser error |
| Security tests and threat model | implemented, not independently validated: threat model v4, ASVS self-assessment v2, CSRF, credential, session, MFA, CSV-injection and RBAC tests (Phase 2), and the Phase 5 suite for XSS, SQL injection, path traversal, archive bombs, request bodies, open redirects and response headers (`tests/test_security_suite.py`). Self-tested only |
| Independent penetration test | blocked: needs an external tester |
| Benchmarks: uniform and skewed entities, free text, uneven periods, readers during ingestion, repeated submissions, hardware, versions, counts, memory, disk, latency percentiles | verified on one laptop (docs/benchmarks.md, product-brief Phase 5 section): every requested case measured; 100k alerts assess in 4.6–6.3 s, ten readers p95 0.5–1.5 s. Regressions reported: at 5M alerts assessment 354 s against 124 s on 2026-10-02, first page after a run 46 s |
| Benchmarks on the declared reference hardware | blocked: needs the declared 4-vCPU / 8-GiB machine; local results only |
| Offline install on an independent target machine | blocked: needs a separate machine |
| Pilot tooling (§14): blinded independent labels, adjudication, reviewer timing, reproducible sampling, baseline comparison, confidence intervals, calibration / held-out split, frozen thresholds | implemented, not independently validated: `satsa.validate.pilot`, `satsa pilot freeze / replicate / adjudicate / evaluate`, migration v9, docs/shadow_pilot_runbook.md Part B; `tests/test_pilot.py` checks every figure against arithmetic on recorded judgements. Unanswered and unresolved labels are never negatives; a demo deployment's report is labelled a synthetic implementation check |
| Field validation with expert reviewers and authorised SOC data (§14) | blocked: needs real reviewers and data; must not be simulated |
