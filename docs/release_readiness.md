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
| **not implemented** | Not done yet. The phase that will do it is named. |

Last updated: end of Phase 3 (branch `feat/product-brief-phase3`).

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
| B08 | No overflow at 390 px or on desktop upload | not implemented | Phase 4 (Playwright layout assertions) |
| extra | Overwrite-on-error data loss in the Parquet writer | verified | Writer removed. Published files are immutable (`tests/test_migrations.py::test_a_published_file_is_never_overwritten`, `test_a_batch_is_published_whole_or_not_at_all`) |
| extra | KPI case mismatch (`mttr` vs `MTTR`) | verified | `test_declared_kpis_are_compared_whatever_their_case`, failing with `47f10c9`'s EG10 |
| extra | `seed_default_admin` re-promotes admin on every start | verified | Seeding is demo-only and never re-promotes (`tests/test_deployment_setup.py::test_a_demoted_admin_account_stays_demoted_after_a_restart`) |
| extra | Findings CSV covers all runs; HTML report always uses the latest run | not implemented | Phase 4 |

## §3 Evidence eligibility and risk classification (release blocker)

| Requirement | Status | Evidence / remaining work |
|---|---|---|
| Persisted per-rule result states with reason, missing inputs and population | verified | `rule_results` table (migration v1); B01 tests |
| One rule-contract registry | verified | `satsa.rules.contracts`, read by the runner. **Not yet read by** the ingestion preview, UI or reports (Phase 4) |
| `not_applicable` only through audited applicability decisions | implemented, not independently validated | `applicability_decisions` table with audit entries; the runner honours them. **No UI or API to record them yet** (moved to Phase 4, with entity context) |
| Table states: omitted, declared empty, rejected, stale | verified | runner `_table_status`; `tests/test_ingest.py` (submitted-empty, not submitted, unreadable), `test_rule_is_not_assessed_when_there_is_no_manifest` |
| Complete-but-empty escalation evidence can support EG03 | verified | `tests/test_ingest.py::test_rule_runs_when_its_table_was_submitted_empty` |
| Missing one input does not erase independently supported findings | verified | `test_b01_missing_escalation_table_*` |
| Unassessable domain is unknown, not 0 | verified | nullable `domain_scores.score`; B01 test |
| Classification status and coverage | verified | `entity_scores.classification_status` and `coverage`; thresholds in `config/scoring.yaml` `evidence_coverage` |
| No renormalising a tiny subset into apparent assurance | implemented, not independently validated | Below 25 % coverage an entity gets no index band, only "Insufficient Evidence" or a finding floor. **Partially assessable entities still show an index band** computed over their known domains. The 25 % and 90 % thresholds are proposed, not validated |
| Limitations shown on portfolio, entity, queue, APIs and exports | not implemented | Stored and returned by the run and API and printed by the CLI; portfolio shows "n/a" and an insufficient-evidence badge. Entity, queue and export display is Phase 4 |
| Separate data-request priority and observed-risk priority | not implemented | `data_request_priority` stored per entity; display is Phase 4 |

## §4 Shared ingestion and connector framework (release blocker)

| Requirement | Status | Evidence / remaining work |
|---|---|---|
| Single ingestion service for upload, CLI, DB exports and JSON API | verified | API now writes JSON sections to a temporary directory and calls `IngestionPipeline.ingest_directory`. No other write path remains (direct `write_partitioned_parquet` calls remain only in the "register entity" form, for its profile and declared KPIs, which hold no personal data, and in tests) |
| JSON contract covers every rule table, with explicit declared-empty | verified | `SUBMISSION_SECTIONS`, `declared_empty`; B02 and B03 tests, `tests/test_batch_submission.py` |
| Entity binding; mixed rows rejected | verified | `bound_entity`; B03 test |
| Privacy processing on every transport | verified | B02 test |
| Timestamp validation with row details | verified | `invalid_timestamps`; B02 test |
| Full typed validation of enums, chronology and cross-table references before publication | not implemented | DQ checks report these after the fact, as before; strict pre-publication typing is pending |
| Idempotency keys; replay; conflict on different content | verified | B03 test, `test_first_submission_accepted_repeat_rejected` (updated per brief) |
| Overlap policy across month, quarter and half labels; corrections as revisions | verified | `reject_overlap`, `revision_of`, `parent_batch_id`; B03 test |
| Upload and archive limits (size, entries, expanded size, ratio) | implemented, not independently validated | `check_zip_limits`, `_copy_limited`. **No parse-time or staging-disk limit yet**; zip-bomb tests are Phase 5 |
| Held submissions need an explicit publish or discard decision | verified | `tests/test_migrations.py::test_a_held_batch_*`; `/batches/{id}/publish|discard` (RBAC matrix updated) |
| Mapping preview before publication | not implemented | Phase 4 |
| Connector contract, conformance tests, compatibility matrix | not implemented | Fixture tests exist (`tests/test_connectors.py`). Matrix in Phase 4. Every connector is at most "fixture-verified" |
| Production-verified connector | blocked | needs an authentic, authorised vendor export |

## §5 Versioned data, time semantics and atomic publication (release blocker)

| Requirement | Status | Evidence / remaining work |
|---|---|---|
| Immutable batches with per-table manifests | verified | `satsa.store.catalog`; `tests/test_migrations.py` |
| Record revisions by business key, never full-row dedup | verified | `VERSION_KEYS`; B05 and selection tests |
| Explicit window, source snapshot, per-table selection rules, masking of later state | verified | `satsa.scoring.selection`; `tests/test_selection.py`; snapshot reads `test_a_reader_can_load_an_earlier_source_snapshot` |
| Entity timezone in operational interpretation | not implemented | Phase 4 (NS03 and context) |
| Effective-dated inventory | not implemented | Phase 4. Inventory is the latest version in the snapshot |
| Atomic publication; readers see whole batches only | verified | `test_a_batch_is_published_whole_or_not_at_all` |
| Orphan and crash recovery, idempotent | verified | `test_files_left_by_an_interrupted_writer_*`; `satsa recover` |
| Run results published in one transaction; failed runs never latest | verified | `AssessmentRunner` uses `audited_transaction`. A failed run leaves no row and writes a `run_failed` audit entry |
| Full-disk and worker-termination drills | not implemented | Phase 5 |
| Versioned migrations with backup and post-checks | verified | `tests/test_migrations.py`; docs/migrations.md |
| Migration of the deployment's real `data/` | blocked | Never run by us, by design. The owner runs `satsa migrate` on a copy first (docs/migrations.md) |

## §6 Reproducible assessments and rule governance

| Requirement | Status | Evidence / remaining work |
|---|---|---|
| Full config snapshots and hashes; analytical fingerprint distinct from run id | verified | `run_config_snapshots`, `runs.fingerprint`; B06 test |
| Old finding pages read the run's parameters | verified | finding page uses the run's snapshot (`tests/test_finding_page.py`) |
| Reports read the run's parameters | not implemented | Phase 4 |
| Offline replay and comparison | verified | `satsa replay`, `tests/test_replay.py` (reproduces after a correction and a configuration change) |
| Replay bundles with integrity manifest | verified (as a backup) | A backup carries `manifest.json` with every file's hash; restore checks it before writing, then replays a selected run in the restored instance and compares fingerprints (`tests/test_backup_restore.py::test_a_restored_instance_reproduces_an_assessment`, `test_a_damaged_backup_is_refused_*`). There is no separate, smaller replay-only bundle |
| Rule-pack draft → approve → active → retired lifecycle | not implemented | Signed import and export exist; the lifecycle is pending |
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
| Report and export generation as jobs | not implemented | PDF and CSV exports still run in the request (Phase 4, with reports reading the run snapshot) |
| Bounded concurrency beyond one worker | not implemented | One worker per deployment (single writer). Several workers are safe by lease, but untested under load (Phase 5) |
| First-run setup with a one-time token; production starts empty | verified | `satsa.deployment`; `tests/test_deployment_setup.py` (no accounts, no published passphrase, token works once, guessing throttled, CLI path) |
| Demo mode opt-in, isolated, labelled | verified | `SATSA_DEMO`; banner on both portals; a demo process refuses production data (`test_a_demo_process_refuses_production_data`); docs/first_run_setup.md |
| Legacy databases keep working | verified | recorded as production, already set up (`test_a_database_from_before_modes_*`); migrations v3–v6 in docs/migrations.md |
| Health and readiness endpoints | verified | `/healthz`, `/readyz` (database, worker heartbeat, free disk); `tests/test_backup_restore.py::test_health_and_readiness` |
| Retention cleanup; redacted diagnostics package | verified | `satsa ops retention` (old job inputs only, audited), `satsa ops diagnostics`; `test_retention_*`, `test_the_diagnostics_package_*` |
| Memory preflight before large assessments | not implemented | Phase 5 (with benchmarks) |
| Usability: portfolio, filters, saved views, B08 | not implemented | Phase 4 |

## §10 Access control, privacy and secure defaults

| Requirement | Status | Evidence / remaining work |
|---|---|---|
| Permission matrix, enforced and tested per route and role | verified | docs/security/permission_matrix.md; `tests/test_rbac_matrix.py` fails when a route is added without being classified |
| CSRF protection on every cookie-authenticated mutation; WebSocket origin check | verified | `satsa.web_security` (Sec-Fetch-Site, Origin, Referer); `tests/test_csrf.py` on both portals |
| Scoped, expiring, revocable service credentials for the submission API | verified | `satsa service-credential`; hashed verifier, shown once, at most 365 days; `tests/test_access_controls.py::test_a_service_credential_*`, `test_revoked_expired_and_forged_*` |
| Request-size limit on the API | verified | `test_an_oversized_submission_is_refused_before_it_is_read` (declared length). **Chunked bodies without a length and parse-time limits are not bounded yet** (Phase 5) |
| Idle session timeout on both portals | verified | `SATSA_SESSION_IDLE_MINUTES` (default 30); `test_an_idle_session_ends`, `test_an_idle_admin_session_ends_too` |
| MFA for privileged users | implemented, not independently validated | Admin Portal: offline TOTP (RFC 6238 vector), replay protection, hashed recovery codes, audited reset, required in production (`tests/test_admin_mfa.py`; docs/security/mfa.md). **SAT-SA analyst and examiner accounts have no MFA** |
| CSV formula-injection escaping | verified | `satsa.csv_safe`; `test_formula_like_text_is_exported_as_text`, `test_the_queue_export_neutralises_*` |
| Deleting an entity never erases evidence | verified | retirement instead of deletion, recorded in the run selection; replay still reproduces (`test_retiring_an_entity_keeps_its_evidence_and_replays`). `tests/test_injection.py::test_delete_entity` now checks retirement, as the brief requires |
| Keys and secrets persist outside the image; no silent regeneration | verified | `data/secrets/` (0600 on POSIX), legacy salt imported byte for byte, versioned pseudonym key per batch, rotation refused without confirmation and audited (`tests/test_keys.py`; docs/key_management.md) |
| Secrets directory never served | verified | `test_the_secrets_directory_is_not_served` |
| Threat model and ASVS checklist | implemented, not independently validated | docs/security/threat_model.md, docs/security/asvs_checklist.md (self-assessed; rows marked partial or not implemented are listed there) |
| Reviewer / approver and read-only auditor roles | not implemented (as roles) | Case sign-off, verification and adjudication are enforced between *different examiner accounts* (Phase 3, `tests/test_cases.py`); no distinct reviewer or auditor role. Rule-pack approval: Phase 4 |
| Entity-scoped operator accounts | not implemented | Analysts and examiners are portfolio-wide by design (permission matrix) |
| Configurable branding (no hard-coded regulator wording in product chrome) | not implemented | Phase 4 |

## §11 Offline distribution, upgrades and recovery

| Requirement | Status | Evidence / remaining work |
|---|---|---|
| Versioned migrations, `satsa migrate`, `verify-data`, `recover` | verified | Phase 1; operational migrations v1–v7, catalog v1–v2 (docs/migrations.md) |
| Local API docs (B07) and no external requests from the UI | verified | see B07; `tests/browser/test_offline_browser.py::test_main_pages_make_no_external_requests` |
| Backup: consistent snapshot of SQLite, published Parquet, held batches, job inputs, secrets, case evidence files | verified | `satsa backup` under the catalog writer lock with the SQLite backup API; `tests/test_backup_restore.py` (incl. `test_case_evidence_files_are_backed_up_and_checked_on_restore`) |
| Optional backup encryption | verified | AES-256-GCM in chunks, scrypt key derivation; tampering detected (`test_an_encrypted_backup_round_trips_and_detects_tampering`) |
| Verified restore into a clean directory, never over a deployment | verified | `satsa restore` checks every hash first and replays a run (`test_a_restored_instance_reproduces_*`, `test_restore_never_overwrites_*`, `test_a_held_batch_can_still_be_decided_*`) |
| Backup retention | verified | `satsa backup --keep`; `test_prune_keeps_the_newest_backups_only` |
| Offline bundle with SBOM, licence notices, signed checksum manifest | verified | `satsa offline-bundle --signing-key`, `satsa release keygen / verify`; `tests/test_release_bundle.py` (SBOM matches `uv.lock` and excludes dev tools; tampering, extra and missing files and a wrong key are rejected) |
| Vulnerability scan of dependencies (pip-audit or similar) | not implemented | Needs an offline advisory database; Phase 5 |
| Compose mounts for data, config and secrets | implemented, not independently validated | `docker-compose.yml` mounts `${SATSA_DATA_DIR:-./data}` and `./config`. **No container was built or run in this phase** |
| Backup and restore drill on the deployment's real data | blocked | Never run by us, by design (the owner runs it; docs/backup_restore.md SOP) |
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

| Section | Status |
|---|---|
| §7 Context-aware analytics and peers | not implemented (Phase 4) |
| §12 Data-model guidance | followed for Phase 1–3 changes (additive migrations, immutable evidence and decision history, projections separate from events, optimistic concurrency, retirement instead of deletion). Examiner routes split into `satsa.api.case_routes` |

## §13 – §14 Gates

| Gate | Status |
|---|---|
| Full automated suite, lint, types | verified (end of Phase 1, local Windows 11 / Python 3.13): `coverage run -m pytest tests` 1271 passed, 33 skipped, 0 failed; branch+statement coverage 88 %; `ruff check` clean; `mypy src` clean |
| Full automated suite, lint, types (end of Phase 2) | verified (local Windows 11 / Python 3.13, 2026-10-17): `coverage run -m pytest tests` 1379 passed, 54 skipped, 0 failed. All 54 skips are the RBAC matrix's "public route: exercised once anonymously" entries; no browser test was skipped. Statement coverage of `src/` 89 % (`coverage report --include="src/*"`; branch coverage not measured in this run, so not comparable with Phase 1's figure). `ruff check src tests` clean; `mypy src` clean |
| Full automated suite, lint, types (end of Phase 3) | verified (local Windows 11 / Python 3.13, 2026-10-17): `coverage run -m pytest tests` 1479 passed, 54 skipped, 0 failed. All 54 skips are again the RBAC matrix's "public route: exercised once anonymously" entries; every browser test ran. Statement coverage of `src/` 90 % (`coverage report --include="src/*"`). `ruff check src tests` clean; `mypy src` clean. The first full run found 2 failures, both fixed without weakening a test: the v7 migration's name contained the word "examiner" and so tripped the diagnostics package's no-usernames check (the migration was renamed before release), and the offline page sweep had no ids for the new case, attachment and task routes (it now creates a real case with an evidence file and a real blind task, and requests the task page as its assigned examiner) |
| Browser tests (Playwright) | verified for Phase 2 scope: `tests/browser/test_offline_browser.py` runs a real server process and Chromium 1248 with every non-local request blocked (`/docs` renders; main pages make no external request and raise no browser error; the block itself is proven). Phase 3 adds `tests/browser/test_case_workflow_browser.py`: two examiners in two browser sessions open, assign and decide a case, record a disagreement, and see closure blocked; the case page does not scroll sideways at 390 px. Layout assertions on every page at 1440/1024/768/390 px (B08) and the full upload-to-report workflow are Phases 4 and 5 |
| Security tests and threat model | implemented, not independently validated: threat model, ASVS self-assessment, CSRF, credential, session, MFA, CSV-injection and RBAC tests (Phase 2). XSS, SQLi, path-traversal and zip-bomb suites are Phase 5 |
| Independent penetration test | blocked: needs an external tester |
| Benchmarks on the declared reference hardware | blocked: needs the declared 4-vCPU / 8-GiB machine; local results only |
| Offline install on an independent target machine | blocked: needs a separate machine |
| Field validation with expert reviewers and authorised SOC data (§14) | blocked: needs real reviewers and data; must not be simulated |
