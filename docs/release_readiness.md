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

Last updated: end of Phase 1 (branch `feat/product-brief-phase1`).

## §2 Defect register

| ID | Requirement | Status | Evidence |
|---|---|---|---|
| B01 | Asset-only entity is insufficient evidence (0/20), not Low | verified | `tests/test_brief_defects.py::test_b01_*`, failing at `47f10c9` (docs/baseline_product_brief.md) |
| B02 | JSON submissions get the same privacy processing and validation as files | verified | `test_b02_*`: e-mail, name and phone absent from Parquet; malformed timestamp returns 422 with table, field and row |
| B03 | Header and row entity bound; alternate period labels cannot evade the duplicate rule | verified | `test_b03_*`: mismatched row returns 422 and nothing stored; `2026-02` after `2026-Q1` returns 409; identical retry is an idempotent replay |
| B04 | The assessment period selects data | verified | `test_b04_*`: Q1 and Q2 scores differ; Q1 evidence lies inside Q1; window recorded in the run |
| B05 | Revisions are not double-counted | verified | `test_b05_*`, `tests/test_selection.py::test_a_correction_in_a_later_batch_*` |
| B06 | Config identity covers every result-affecting file | verified | `test_b06_*`: a breadth-weight change alters `config_hash` and `fingerprint` |
| B07 | `/docs` works offline | not implemented | Phase 2 (vendored Swagger UI, browser test with network blocked) |
| B08 | No overflow at 390 px or on desktop upload | not implemented | Phase 4 (Playwright layout assertions) |
| extra | Overwrite-on-error data loss in the Parquet writer | verified | Writer removed. Published files are immutable (`tests/test_migrations.py::test_a_published_file_is_never_overwritten`, `test_a_batch_is_published_whole_or_not_at_all`) |
| extra | KPI case mismatch (`mttr` vs `MTTR`) | verified | `test_declared_kpis_are_compared_whatever_their_case`, failing with `47f10c9`'s EG10 |
| extra | `seed_default_admin` re-promotes admin on every start | not implemented | Phase 2 |
| extra | Findings CSV covers all runs; HTML report always uses the latest run | not implemented | Phase 4 |

## §3 Evidence eligibility and risk classification (release blocker)

| Requirement | Status | Evidence / remaining work |
|---|---|---|
| Persisted per-rule result states with reason, missing inputs and population | verified | `rule_results` table (migration v1); B01 tests |
| One rule-contract registry | verified | `satsa.rules.contracts`, read by the runner. **Not yet read by** the ingestion preview, UI or reports (Phase 4) |
| `not_applicable` only through audited applicability decisions | implemented, not independently validated | `applicability_decisions` table with audit entries; the runner honours them. **No UI or API to record them yet** (Phase 3) |
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
| Replay bundles with integrity manifest | not implemented | Phase 2 (with backup and restore) |
| Rule-pack draft → approve → active → retired lifecycle | not implemented | Signed import and export exist; the lifecycle is pending |
| Numerical tolerance across hardware | not implemented | Determinism is pinned (single-threaded DuckDB, `uv.lock`); cross-hardware tolerance is unmeasured |

## §7 – §12

| Section | Status |
|---|---|
| §7 Context-aware analytics and peers | not implemented (Phase 4) |
| §8 Examiner workflow | not implemented (Phase 3) |
| §9 Durable jobs and usability | not implemented (Phase 2 / Phase 4) |
| §10 Access control, privacy and secure defaults | not implemented (Phase 2) |
| §11 Offline distribution, upgrades and recovery | partial. Migrations, `satsa migrate`, `verify-data` and `recover` are done; backup, restore, bundle and B07 are Phase 2 |
| §12 Data-model guidance | followed for Phase 1 changes (additive migrations, immutable evidence) |

## §13 – §14 Gates

| Gate | Status |
|---|---|
| Full automated suite, lint, types | verified (end of Phase 1, local Windows 11 / Python 3.13): `coverage run -m pytest tests` 1271 passed, 33 skipped, 0 failed; branch+statement coverage 88 %; `ruff check` clean; `mypy src` clean |
| Browser tests (Playwright) | not implemented (Phases 2 and 4) |
| Security tests and threat model | not implemented (Phase 2 / Phase 5) |
| Independent penetration test | blocked: needs an external tester |
| Benchmarks on the declared reference hardware | blocked: needs the declared 4-vCPU / 8-GiB machine; local results only |
| Offline install on an independent target machine | blocked: needs a separate machine |
| Field validation with expert reviewers and authorised SOC data (§14) | blocked: needs real reviewers and data; must not be simulated |
