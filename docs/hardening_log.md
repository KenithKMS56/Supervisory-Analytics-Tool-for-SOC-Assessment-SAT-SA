# SAT-SA Security & Correctness Hardening Log

Branch `hardening/sih26157`, one commit per step (not pushed). Every item below was implemented and
**verified by running it**: the full test suite, a replay of the CI sequence from a fresh clone
on Python 3.11 and 3.13, and live checks against running servers. Where a claim in the repository
turned out to be wrong, the correction is stated here rather than silently fixed.

## Summary of before / after

| Measure | Before (Step 0 baseline) | After | Note |
|---|---|---|---|
| Test suite, fresh install | 94 passed | **596 passed, 0 failed, 33 skipped** | The 33 skips are public routes in the RBAC matrix, exercised once anonymously instead of once per role |
| Test suite, long-lived dev DB | **92 passed, 2 failed** | 596 passed | Real bug: see Step 7. The README's "94 passed, 0 failed" held only on a fresh install |
| `ruff check src tests` | 37 errors | 0 | Now a blocking CI gate |
| `mypy src/satsa` | 31 errors | 0 | Now a blocking CI gate |
| Demo run findings | 34 | 34 (identical entity/rule/score/confidence/severity) | Thresholds moved into config with identical defaults |
| Entity Rank Precision@7 | 100.0% | 100.0% | Unchanged |
| Injected Defect Recall | 100.0% (13/13) | 100.0% (13/13) | README/slides/validation.md said 11/11: stale, corrected |
| Overall Defect Precision / F1 | 100.0% / 1.0000 | 100.0% / 1.0000 | Unchanged |
| Ranking stability (±20%) | ρ = 1.0000 / 1.0000 | ρ = 1.0000 / 1.0000 | Unchanged |
| Stress scenario | P@k 100%, recall 3/3, precision 60.0%, 2 FP (EG05, NS08) | identical | Unchanged |
| **Review-effort lift, 1% budget** | README/slides/demo claimed **16.60x** | **5.97x** (4.13x at 2%, 1.65x at 5%) | **Corrected headline**, see Step 13 |

> **Superseded by Step 18.** The precision, stress and lift rows above were measured with a harness
> that counted false positives only on clean entities and exempted NS05/EG12/EG10. Note the table's
> own "Demo run findings: 34" next to 13 injected defects: honest precision was 38%, not 100%.

## Step 0 — Baseline
Done. Outputs saved to a scratch directory for diffing: bootstrap, pytest, validate,
validate-stress, ruff, mypy, and copies of both validation reports.

**Findings:**
- **ruff/mypy were not clean** (37 and 31 errors), so they were fixed before becoming blocking CI gates (Step 12).
- **The suite fails on a long-lived dev DB.** On the existing dev database it gave 92 passed / 2 failed (both in systemic correlation); a fresh install gave 94/94. The dev database was preserved as a backup and later used to prove the Step 7 fix.
- **No real ID fails the new regex.** Every entity ID the project produces (primary + stress datasets, sample templates, seeded CSEs; 15 distinct) matches `^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`, so ID validation could not shift the validation population.

## Step 1 — SQL injection and path traversal — done, verified

**SQL injection.** Parameterized every interpolated query:
- **All 20 rules** (22 query sites; each one interpolated `entity_id`).
- **Routes:** `/entity/{id}`; `/alerts` (entity, severity, actor_type and q were all raw); `/blind-review`.
- **Other modules:** the review-queue prioritiser, the report generator, and the SQLite-export table-name read.

**Defense in depth.** A new `satsa.security` module checks IDs at three points:
- **Ingestion** drops rows with an invalid `entity_id` and reports an `invalid_entity_id` DQ issue.
- **`AssessmentRunner`** skips invalid IDs before any rule sees them.
- **The parquet writer** refuses to build a partition directory from an invalid ID.

Routes and admin `{username}` paths return 400 on an invalid value.

**Path traversal:**
- **delete-entity** removes only the exact `entity_id=<id>` partitions. It previously ran `rglob(f"entity_id={id}")`, so `*` would delete every entity.
- **`/templates/{name}`** is allow-listed.
- **Report paths** are validated.
- **`/upload`** uses the file's base name and validates zip members before extracting.

**Session cookies:** HttpOnly on both; the admin cookie is `SameSite=Strict`; `Secure` is set via `SATSA_COOKIE_SECURE`.

**Evidence:**
- `tests/test_injection.py`. Against the unpatched rules, 100 of 100 rule cases fail; they pass after the fix.
- Live check against a running server, on both a rules-engine route and an admin-portal route:
  - Payloads `' OR '1'='1`, `*`, `../../etc/passwd` and `..\..\x` get 400/404 (404 where the router never matches the path).
  - 129 partitions unchanged, and no file created outside `data/`.
  - Because validation runs first, the rejected requests never reach a query; the unit tests show the payload never appears in executed SQL text.

## Step 9 — RBAC (run second, per the agreed priority) — done, verified

Four gaps were closed, none of which needed a crafted payload:

| Gap | Fix |
|---|---|
| Admin `/ws/activity` had no auth | Requires an admin session; otherwise the handshake closes with 1008 |
| Admin Portal admitted `supervisor` and any `is_admin_user=1` user, i.e. a supervisor could create admins, block accounts and reset passwords | Administrator role only; the flag is ignored and its checkbox removed |
| Every `/api/v1/*` read and portfolio/CSV export was anonymous | 401 when anonymous; examiner/supervisor/admin only, so CSE-scoped identities get 403 |
| Admin login said "Account is blocked" before checking the password | Password checked first; unknown user, wrong password, blocked account and wrong role all return one generic 401 |

**Structure:**
- The SAT-SA middleware redirects anonymous page GETs to `/login` and returns 401 for everything else.
- Every route also declares an explicit dependency.
- Admin routes use a dependency that runs before form validation, so an anonymous POST gets 401, not 422.

**Evidence:**
- `tests/test_rbac_matrix.py`: explicit route tables for both apps, a completeness check, and the roles × routes sweep. Against the pre-change code, 66 of its tests fail.
- A fresh-install test proves `nciipc_admin`/`admin` still reach the portal.
- Live checks: supervisor on `/users` gets 403; anonymous `/api/v1/findings` gets 401.

## Step 2 — Config/tuning drift — done, verified
No rule read `self.params`, and `/tuning/save` wrote top-level keys that nothing read.
- **Rules:** EG01, EG04, EG05, EG10, NS01, NS02 and NS03 now read the prescribed params, with defaults equal to the old literals.
- **Config:** `rules.yaml` holds exactly those params. Every unread key was removed, and the descriptions were corrected to the real logic. For example, EG04 never used Jaccard similarity and EG05 has no 30-day window.
- **Tuning page:** it writes `cfg["rules"][RULE]["params"][key]`, validates ranges, and shows labels that describe the real logic.
- **NS07's "6-hour window" was never implemented.** The knob was removed and the rationale no longer claims a time check (follow-up below).

**Evidence:**
- **Tests:** `tests/test_config_drift.py`, both structural and behavioral.
- **Live round-trip on a running server:** the EG04 finding on CSE-07 disappears at `max_comment_hash_share=0.99` and returns at 0.25.
- **Behavior unchanged:** the demo run's 34 findings are identical to the baseline.

## Step 5 — Rule-pack signing key — done, verified
- **Burned key rejected.** The HMAC key `SATSA_RULEPACK_NCIIPC_2026` was hardcoded (as the signer default and in the CLI `--secret` default), so it is now explicitly rejected.
- **No fallback.** The key must come from `SATSA_RULEPACK_SECRET` (at least 32 characters). Without it, the CLI exits 1 and the UI returns 503.
- **Verify before writing.** Import previously called `tar.extractall` before verifying anything. It now validates every member (no absolute paths, `..`, links or devices), verifies the HMAC from memory, checks the SHA-256s from memory, and only then writes, inside the target directory.
- **Found along the way:** export wrote the manifest with `write_text`, which produced CRLF on Windows, so the archived bytes differed from the signed bytes. The old text-mode import masked this.

Existing packs are signed with the burned key and must be re-signed.

## Step 3 — Login lockout — done, verified
- **Counter.** `count_recent_login_failures()` reuses the audit logs, with no new table: it counts failures since the last success within the window. The constants are 5 failures within 15 minutes.
- **Both logins.** `/login` and the admin login reject a locked username even with the correct password, write `login_locked`, and return the same generic error.
- **Timestamps.** `isoformat()` drops the fractional seconds when microseconds are 0, so stored timestamps had mixed precision. All store timestamps are now fixed-precision, and comparisons parse the values rather than comparing strings.
- **Tests.** Existing tests no longer fail logins against the shared `admin` account.

**Evidence:**
- **Tests:** `tests/test_login_lockout.py` covers a space-separated naive timestamp, a `Z` suffix, `+05:30` and the exact boundary.
- **Live:** 5 bad attempts, then the correct password is still rejected with the exact unknown-user response, and the audit log records `login_locked`.

## Step 4 — Audit chain (SHA3-256 + checkpoints) — done, verified
- **Per-row algorithm.** A `hash_alg` column was added (legacy rows `sha256`). New rows hash `"sha3_256:"+payload`, and verification uses each row's own algorithm.
- **Checkpoints.** `satsa audit head` and `satsa audit verify --checkpoint-*` were added.
- **ADR-005.** Documents the choice of SHA3 hash-chain plus external checkpoints over post-quantum signatures, with explicit non-defenses: a full chain recompute by someone with DB write access, and tail truncation without an anchor.
- **Overclaim removed.** "Detects any tampering" was deleted from ADR-004, the README, architecture, functional design, deployment ops and the slides.

**Evidence:**
- **Tests:** `tests/test_audit_tamper.py`. 11 mutations are each detected at the correct row. Honest tests confirm that truncation and full recomputation pass `verify()`, and that a checkpoint catches both.
- **Mixed chain on the real DB:** the dev database's chain holds 474 legacy SHA-256 rows plus 673 SHA3-256 rows and verifies end to end (1,147 entries).

## Step 6 — Concurrency — done, verified
- **The race was real, reproduced before the fix:**
  - 200 concurrent appends produced only 193 distinct `prev_hash` values (a fork).
  - The admin chain broke at row 8.
  - A shared connection raised `InterfaceError`.
- **Fix:** a per-database process lock plus `BEGIN IMMEDIATE` around read-previous-hash and insert.
- **Runs were already additive** (the `run_id` is embedded in every `finding_id`); now pinned by a test.

**Evidence:** `tests/test_concurrency.py`, stable over repeated runs.

## Step 7 — Systemic finding on a fresh install — done, verified
- **Fresh install:** the shared-MSSP systemic finding fires on the very first run from empty stores.
- **Root cause of the dev-DB failure:**
  - Entity rows were appended and de-duplicated on the whole row, so each re-ingest kept another version of the entity (dev partitions held a second row with `soc_provider=NULL`).
  - DuckDB's `INSERT OR REPLACE` kept an arbitrary version. For CSE-09 the `NULL` won, so the MSSP group shrank to 2 entities and the finding vanished.
- **Fix:** entity rows are upserted by `entity_id`, with the latest non-null value winning per column.

**Evidence:**
- **Tests:** `tests/test_systemic_fresh_install.py`; the re-ingest test fails before the fix.
- **Replay of the actual polluted dev DB:** 0 systemic findings before a re-ingest, 1 after.

## Step 8 — Offline / air-gap — done, verified
- **Google Fonts removed.** Three templates loaded Google Fonts, contradicting ADR-003's "no external fonts". Removed, and ADR-003 corrected.
- **Remaining `http://` references are safe:** loopback links to the local SAT-SA app, and an SVG `xmlns` inside a `data:` URI.

**Evidence:** `tests/test_offline_hardening.py`.
- **Socket guard:** patches `connect`, `connect_ex`, `create_connection` and `getaddrinfo`, then requests every GET route in both apps as admin with real IDs. Result: zero outbound attempts, no 5xx.
- **Static scan:** covers every template and static file. It flags all 9 removed font references if they are restored.

## Step 10 — Admin activity feed — done, verified
- **Bounds.** `since_id` must be a non-negative integer and `limit` is capped at 200 in the store; the endpoints add `Query` bounds, so bad input gets 422. The feed is in the RBAC matrix and the offline sweep.
- **Decision (ADR-006).** `live_events` is a supplementary, non-authoritative feed and is deliberately not hash-chained. Every security-relevant event it shows has a counterpart in a chained audit log, and a test enforces this.

## Step 11 — Terminology / PS compliance — done, verified
Checked against the official PS text at https://sih2026.vuce.in/ps/SIH26157.
- **Feed renamed.** "Live telemetry" became "admin activity feed" / "operator session monitor" everywhere: code, docstrings, UI, README, docs and the test file name.
- **Periodic, not continuous.** "Continuously assesses" became "assesses … at each periodic assessment cycle". CSE data is described as periodic submissions, not telemetry feeds.
- **Batch API.** `POST /api/v1/telemetry/ingest`, whose docstring advertised webhooks and SOAR playbooks, is now `POST /api/v1/submissions`:
  - a periodic-batch-only docstring;
  - a validated period;
  - one submission per (entity, period), with 409 on a repeat.

  This also fixed the handler writing to non-canonical tables.
- **Traceability row 9 corrected.** It claimed the PS requires an "optional local-LLM restatement layer". The official PS contains no such requirement; its AI/ML clause is conditional ("Where AI or machine learning is proposed…"), which is **N/A by design** (ADR-001).

**Remaining "telemetry" uses, kept deliberately:**
- NS06's established rule name "Inventory vs Telemetry" (it compares the asset inventory with log sources in the submission).
- "SOAR Playbook" as an alert closure-type value.
- A "Space Systems & Satellite Telemetry" sector option.
- An ingestion filename alias.
- The old bundle URL, still served for bookmarks.
- The traceability line that *negates* continuous telemetry ingestion.

## Step 12 — CI — done, verified locally; badge deferred
- **Workflow.** `.github/workflows/test.yml`: push + PR, ubuntu-latest, `astral-sh/setup-uv`, Python 3.11 and 3.13. It runs every step in the brief and uploads the validation reports; ruff and mypy are blocking.
- **Lockfile.** `uv.lock` now includes `websockets`, which was already declared, so that `uv sync --frozen` installs it in CI.
- **Git hygiene.** The stale tracked `data/*.db-shm` / `*.db-wal` files were untracked and gitignored.
- **Clean-checkout replay.** Run from a fresh `git clone --no-local` with a fresh venv and fresh data, on both 3.13.2 and 3.11.16. All steps pass: 596 passed, validate, validate-stress, audit verify, ruff, mypy.

  Process note: a first replay attempt ran in the dev repository by mistake, because the clone failed on a Windows short-path (`SANJAY~1`) and the chained `cd` never ran. That run was discarded, its stray files removed, and the replay redone in a verified fresh clone.
- **CI badge: deferred.** The brief requires the workflow to have run on GitHub first, and nothing has been pushed yet.

## Step 13 — Validation honesty check — done
- **Metrics identical.** Fresh-clone `satsa validate` and `validate-stress` diffed against the Step 0 baseline: every metric and every per-rule row is identical, and Python 3.11 matches 3.13. The only deltas are run IDs and the audit-entry count (32 → 88), because the larger suite writes more audit entries before validation runs; neither is a metric.
- **Corrected headline: review-effort lift is 5.97x at a 1% budget, not 16.60x.**
  - **Where 16.60x came from:** an older, smaller synthetic dataset (~5,600 alerts, so a 1% budget was 56 records).
  - **Why it is wrong now:** the current default generator produces ~16,200 alerts, so 1% is 162 records, and the same 13 defects give 8.0% vs 1.34% random = 5.97x (4.13x at 2%, 1.65x at 5%).
  - **The repo already knew:** the committed `docs/validation_report.md` already said 5.97x; the README, slides, demo script and `validation.md` still said 16.60x.
  - **Against the README's own target:** "≥ 5.00x" is met at the 1% budget only. The README now says so.
- **Other stale figures corrected:** recall 11/11 → 13/13; test count 94 → 596. `infrastructure.md` benchmark timings are labeled as measured on the older 5,650-alert dataset.

## Deferred, and why
- **NS07 reporting-window check.** Only the presence of an external report is checked; `reported_at` against the case timeline is not. This is a detection change that alters findings, so it is out of scope for a hardening pass; the fake knob was removed instead.
- **CI badge.** Needs a push and a first GitHub run.
- **No CSRF tokens on admin/SAT-SA POST forms.** Partly mitigated: the admin cookie is `SameSite=Strict` and the SAT-SA cookie `SameSite=Lax`.
- **Cross-tenant HTML views.** CSE-scoped identities can still open portfolio-wide HTML pages (portfolio, queue, DQ, alerts); entity pages and the bulk APIs are enforced. Closing this needs a product decision on what CSE users should see.
- **Hardcoded demo KPI panel.** `/entity/{id}` shows hardcoded demo KPI values in its reconciliation panel (`api/routes.py`); noted and left as is.
- **Lockout is per username only (no per-IP rate limiting).** A caller who knows a username can lock it out; accepted for an air-gapped, small-user deployment and documented.
- **HTML report escaping.** The HTML report generator interpolates stored values without HTML escaping. Entity IDs are now validated, but free-text fields are not escaped; this is a follow-up.

## Step 14 — PDF reporting layer (presentation only) — done, verified

**Scope.** Three A4 PDF reports built with ReportLab: portfolio, CSE and finding. Each finding appears as a layered card:
- **Tier 1:** an ESCALATE / MONITOR / NOTE badge plus a plain-language headline.
- **Tier 2:** a shaded Technical Detail box.

No analytical code changed. `git diff` over `rules/`, `scoring/`, `peers/`, `ingest/`, `metrics/`, `validate/`, `store/`, `models/`, `config/`, `pyproject.toml` and `uv.lock` is empty. Charts use `reportlab.graphics.charts` / `shapes` only; no dependency was added and no network access is used.

**What was added:**
- **New modules.** `report/plain_language.py` (20 headline templates and the badge mapping), `report/pdf_layout.py` (A4 page template, "Page X of Y", notice on every page, finding cards, atomic build) and `report/pdf_charts.py`.
- **Generator.** New `generate_portfolio_pdf` and `generate_finding_pdf`. `generate_entity_pdf` was moved from `letter` to A4 and enhanced.
- **Routes.**
  - New `GET /reports/portfolio/pdf` and `GET /reports/finding/{finding_id}/pdf`, both `SUPERVISORY_READ_ROLES`.
  - The entity PDF route keeps `require_authenticated` + `require_cse_access`.
  - All three accept a validated `?run_id=`. New helpers `is_valid_run_id` and `is_valid_finding_id` in `security.py`.
  - Error handling: 400 for invalid IDs, 404 for an unknown run, entity or finding, and a clean 500 JSON (no stack trace) on a generation failure. A failed build leaves no partial file behind.
- **UI.** An "Export Report" dropdown (native `<details>`, no JavaScript) on the portfolio, entity and finding pages. Supervisory-only items are hidden from CSE-scoped roles.
- **Tests.** The RBAC matrix has the two new routes (the completeness guard is unchanged). The offline sweep now also asserts that the three PDF routes return real PDFs with zero outbound connection attempts. New `tests/test_report_pdf.py` (65 tests). The two new RBAC-matrix routes add 8 more (2 routes × 4 roles), for +73 in total.

**Before / after (same fresh-bootstrap → pytest → validate order both times):**

| Measure | Before | After |
|---|---|---|
| `pytest tests -q` | 596 passed, 33 skipped | **669 passed, 33 skipped**, 0 failed |
| Entity Rank Precision@7 / Recall@7 | 100.0% / 100.0% | identical |
| Injected Defect Recall | 100.0% (13/13) | identical |
| Overall Defect Precision / F1 | 100.0% / 1.0000 | identical |
| Spearman ρ (±20%) | 1.0000 / 1.0000 | identical |
| Review-effort lift (1% / 2% / 5%) | 5.97x / 4.13x / 1.65x | identical |
| Stress: P@k, recall, precision, FP | 100.0%, 3/3, 60.0%, 2 | identical (console output byte-identical) |

The only differences in the validation report are the run ID and the audit-entry count (88 → 91, from the new tests' logins). Neither is a metric. `ruff check` and `mypy` are clean, and `satsa audit verify` passes.

**Found while taking the baseline (pre-existing, not fixed here):**
- **A stray unpartitioned parquet file silently emptied the alert table.** The dev `data/` directory contained a stray `data/parquet/alert/data.parquet` next to the `entity_id=*` partitions, written by an earlier process at 23:24 the night before. `DuckDBStore.load_table_from_parquet` then fails with a hive-partition mismatch, and both of its `except duckdb.Error` branches swallow the error. The **alert table loads empty with no error**. Validation dropped to recall 4/13 (P@7 57.1%), and NS08 fired for every entity.
- **Resolution for this step.** A clean re-bootstrap restored 13/13. The polluted directory was kept as a backup, not deleted.
- **Why the loader was not changed.** Fixing it (fail loudly, or reject stray files) is an ingestion/storage change, so it is out of scope for a presentation step. It is recorded here as a follow-up. CI is unaffected because it always bootstraps from a clean checkout.

**Limitations, stated plainly:**
- **No IQR or z-score deviation is shown.** None is persisted on findings, so the Tier-2 box shows the finding's stored `peer_comparison_json` values ("Measured values") instead of a "+x IQR" line.
- **Paired comparison bars appear only for NS03 and EG10.**
  - NS03's baseline is labelled "Portfolio average" because it is a mean over *all* entities, including the flagged one, not a peer median.
  - EG10 compares the declared MTTR with the measured MTTR.
  - EG01 stores a closure *share* against a 5th-percentile *time*. The units differ, so it has no chart.
- **Evidence IDs come only from `finding_evidences`.** Rules that persist no evidence rows (NS03, NS05, NS08, EG11) show no evidence line. `Finding.evidence_ids` is not saved, so the PDFs cannot show it.
- **Badges follow the stored severity.** The mapping is critical → ESCALATE, high → MONITOR, anything else → NOTE. A low-scoring `high` finding (for example NS02 at score 34) is therefore still MONITOR.
- **Systemic (cross-entity) findings are not included** in the portfolio PDF.
- **`dq_issues` is not scoped to a run.** The data-quality section says so. The demo dataset records 0 issues.
- **The HTML reports are unchanged** and still lack HTML escaping (see Deferred). The PDFs escape every stored string before layout.
- **Report downloads accumulate in `reports/`** (gitignored), matching the existing HTML/CSV routes. There is no cleanup job.

## Step 15 — Two-role SAT-SA (analyst / examiner) and ingestion visibility fixes — done, verified

**Ingestion fixes (the follow-up recorded in Step 14):**
- **`DuckDBStore.load_table_from_parquet` no longer empties a table on one bad file.** Partitioned (`entity_id=*`) and stray root-level files are read separately. Only the table's own columns are selected, with `TRY_CAST`, so a pass-through source column or an unparseable timestamp can't fail the insert for every other file.
- **The upload pipeline rejects rows with no `entity_id`** when no target entity is chosen. It records a `missing_entity_id` DQ issue and a clear upload message, instead of writing an unpartitioned file and reporting success.
- **`POST /api/v1/submissions` registers a CSE first seen in the batch**, just as `/upload` already did. Before this, the batch was stored and acknowledged, but the assessment and every UI view skipped the entity.

**Role split:**
- **Roles.** SAT-SA (`:8001`) admits only `analyst` (formerly `supervisor`) and `examiner`. Administrators and CSE-scoped accounts are refused at `/login` (`login_denied_role` audit entry). Any session such a role holds gets HTTP 403 in `enforce_auth_middleware`.
- **Analyst-only.** Upload/ingest, runs, tuning, rule packs, alert explorer, rules catalog, DQ, runs & audit, `/api/v1/audit/verify`, CSV templates and raw CSV exports. The navigation hides these pages from the examiner.
- **Examiner-only.** Review-queue decisions, relabelled *Escalate to Statutory Notice* / *Mark as Justified* / *Request CSE Explanation* (stored values unchanged), and blind-review verdicts. The analyst sees the queue read-only. This is deliberate separation of duties.
- **Migration.** `SQLiteStore._migrate_supervisor_to_analyst` renames the role on startup. The untouched demo `supervisor` account becomes `analyst` / `ChangeMe-Analyst#2026`; a rotated one keeps its username. Audit rows are not rewritten, so the chain still verifies.
- **Tests.** `tests/test_rbac_matrix.py` expects `admin` to get 403 on every gated SAT-SA route. New tests cover login refusal, the migration, the examiner's hidden navigation and analyst-only decisions.


## Step 16 — Shadow-pilot rehearsal (synthetic stand-in) — done, documented

- **What ran.** `scripts/build_shadow_standin.py` builds a stand-in workpaper CSV from the synthetic ground truth (25 `confirmed` rows across the 13 injected defects; 15 `not_an_issue` rows from the clean entities). The labels are deliberately not taken from SAT-SA's own findings, which would make rule recall 100% by construction. `satsa validate --shadow-csv data/generated/shadow_pilot_standin.csv` reported `rule_finding_recall` 1.0 and `queue_record_recall` 0.16. Across every affected ID, 19/223 are queued, with at least one queue item for 7 of 13 defects.
- **How it's documented.** Recorded in `docs/validation.md` §5A as a rehearsal, not evidence.
- **No metric moved.** The regenerated `docs/validation_report.md` differs only in run ID and audit-entry count.
- **Follow-up.** `ShadowPilotAdapter` ignores `not_an_issue` rows and has no precision metric. Add both before a real pilot.

## Step 17 — Shadow pilot in the app and in the validation report — done, verified

- **Web page.** New analyst-only `/shadow-pilot` page (Config & Audit menu): upload a workpaper CSV, evaluate it against the latest run, and see per-row "reproduced / missed" and "queued" outcomes plus an evaluation history. Uploads over 5 MB, non-UTF-8 files and CSVs missing required columns are refused. Each evaluation is audited (`shadow_pilot_evaluated`).
- **Storage.** Results are stored in a new `shadow_pilot_results` table (`SQLiteStore.save_shadow_result` / `list_shadow_results`). `ShadowPilotAdapter.evaluate_shadow_pilot` also returns the run ID, match counts and per-row outcomes; the existing keys are unchanged.
- **Report.** `satsa validate --shadow-csv …` stores its evaluation before writing the report. Section 5 of `docs/validation_report.md` and `.html` now shows the latest stored result for the report's run, with a caveat that the figures are only as independent as the labels. Without the flag, the report still shows the last stored result.
- **Tests.** `tests/test_shadow_pilot.py`; the RBAC matrix lists both routes as analyst-only.


## Step 18 — Validation scoring and generator correctness — done, verified

- **The precision figures were wrong in both directions.** The primary report's 100% precision came from `ValidationHarness.evaluate_rule_detection`, which counted a false positive only on the three clean entities and exempted NS05, EG12 and EG10 there. That run had 34 findings for 13 injected defects: honest precision was 38%. The stress report's 60% came from generator artifacts: stress entities spanned ~1 month, so NS08 (6-month completeness) fired on all three, and the "clean" STRESS-03 was one asset with every alert benign and no tickets, i.e. EG05's own defect.
- **Harness.** Every finding not in the ground truth is now a false positive, split into clean-entity and defect-entity lists, with missed defects named. Report verdicts are computed against targets (they were hardcoded `PASS`), confounder lines are measured rather than fixed prose, and the stability conclusion no longer claims threshold robustness (only domain weights are perturbed).
- **Lift.** Now alert-for-alert on both sides; queue exhaustion is reported instead of dividing by the full budget. On the corrected data every budget exceeds the 109-alert queue, so the three budgets report the same 10.69x.
- **Generator bugs fixed.** Alerts now use each entity's own rule catalog (NS05 fired everywhere); critical cases get a containment lifecycle (EG12 fired everywhere); CSE-08's alert renumbering now carries its closures, workflow events and escalations (EG02/EG03 fired on the small-entity confounder); MTTR is declared for High and Critical at healthy values, and CSE-02's EG10 description no longer claims ">200 min actual".
- **Rule defect fixed.** EG10 compared empirical High+Critical MTTR against whichever severities were declared. It now compares declared severities only, weighted by alert count. `config/rules.yaml` and `docs/analytics_methodology.md` (which described MTTA/SLA reconciliation at 10%) now match the code. NS04's docs no longer claim it detects ID sequence gaps (the ingest DQ check does).
- **Stress generator.** 6-month span over four assets per entity; STRESS-03 has realistic noise, including near-miss repeat-alert patterns that must not trip EG05.
- **Shadow pilot.** `ShadowPilotAdapter` now computes workpaper precision from rule-level `not_an_issue` rows and lists unadjudicated findings separately rather than counting them as false positives. Shown in the CLI, the report, the `/shadow-pilot` page and the audit entry.
- **Fabricated UI numbers removed.** The entity profile's KPI reconciliation panel was hardcoded (CSE-02 always "35 vs 240 min", every other entity "55 vs 52"), and its radar "peer median" was a fixed list. Both are now computed from the data (peer median only with ≥3 peers).
- **Systemic detector.** `config/systemic.yaml` no longer excludes NS05/EG12/EG10 by default; the exclusion existed only to hide the generator artifacts.
- **Result.** Primary and stress precision are both 100% with every finding counted. That is not a stronger claim than before: it shows the corrected generator and the rules agree on synthetic data. 8 of 20 rules have no injected defect anywhere. See `docs/validation.md` §0–0.1.
- **Verified.** Full suite 702 passed / 0 failed / 33 skipped on Python 3.13 from freshly generated data (4 PDF/bundle tests run from a short path because of the Windows 260-character limit in the scratch copy); `satsa validate`, `satsa validate-stress`, ruff and mypy clean. Regression tests: `tests/test_validation_integrity.py`.

## Step 19 — Injected defects for the 8 untested rules — done, verified

- **Gap.** EG07, EG08, EG09, EG11, EG12, NS05, NS07 and NS08 had no injected defect, so validation only ever showed they stay quiet.
- **Defects added** (`satsa/synth/defects.py`, all in entities that already carry defects so CSE-01/04/06 stay clean): CSE-08 one analyst closing 35 alerts in an hour (EG07, spread over distinct minutes to stay clear of EG06's bulk check); CSE-03 four unacknowledged escalations (EG08); CSE-05 four stale open high cases (EG09); CSE-07 no true positive in six months (EG11); CSE-09 three critical cases without containment (EG12) and 25 never-firing legacy rules (NS05); CSE-02 two unreported critical incidents (NS07); CSE-10 no June submission (NS08).
- **Result.** Primary recall 21/21, precision 21 of 21 findings, no finding on any entity for a rule not injected there. Lift fell from 10.69x to 5.50x only because EG11's ~200 relabelled alerts raise the random baseline (1.20% → 2.67%); the queue is unchanged.
- **Guard.** `test_every_rule_has_an_injected_defect` fails if any registered rule lacks a defect in the primary or stress ground truth.
- **Still true.** The new defects clear their thresholds by a wide margin, like the rest of the primary set; only EG02/EG04 are tested near a threshold.
- **Verified.** 704 passed / 0 failed / 33 skipped on Python 3.13 from freshly generated data (4 PDF/bundle tests run from the repo path because of the Windows 260-character limit in the scratch copy); `satsa validate`, `satsa validate-stress`, ruff and mypy clean.

## Step 20 — Rule threshold sensitivity; thresholds made tunable; rule docs matched to code — done, verified

- **Sweep.** `ValidationHarness.evaluate_threshold_sensitivity` moves each tunable threshold ±20% on its own (integers by at least 1, shares/rates capped at 1.0), re-runs that rule on every entity and scores it against the ground truth. Reported in Section 7 of `docs/validation_report.md`, in the stress report, and by both `satsa validate` commands.
- **Coverage.** Only 7 rules had tunable thresholds. EG02, EG06, EG07, EG08, EG09, EG11, EG12, NS04, NS05 and NS06 now read theirs from `config/rules.yaml` (17 new params, defaults identical to the old hardcoded values, also on the Tuning page). EG03 and NS07 (zero tolerance) and NS08 (fixed 6-month period) have none by design; `test_every_rule_is_tunable_or_deliberately_knob_free` enforces the split. Baseline results are unchanged (21/21, 0 false positives).
- **Findings (primary, 5 of 54 moves change an outcome).** EG05 `min_repeat_count` 8 → 6 flags 6 entities including all 3 clean ones; EG11 `max_fp_rate` 0.98 → 0.784 flags 8 of 10. Both thresholds sit close to the synthetic background and are the first calibration candidates on real data. The other three changes (EG05 pairs, EG07, NS05) are injected defects built just over their thresholds.
- **Rule docs corrected.** `config/rules.yaml` descriptions and `docs/analytics_methodology.md` rule logic described checks the code does not perform (EG06 severity downgrades/spikes, EG07 off-shift activity, EG08 SLA delay, EG09 inactivity, EG12 stage ordering, NS05 MITRE coverage, NS06 shadow assets, NS07 6-hour window, NS08 null rates/volume) and wrong numbers (EG01 120 s, EG04 40%, EG05 ≥5 in 30 days, EG07 >25/h, NS02 80% of peers, NS03 z-score/CUSUM). Both now state what the code does.
- **Noted, not changed.** No rule uses the `peer_ids` the runner passes: NS02 and EG01 compare against the whole portfolio, not a sector/size peer group.
- **Verified.** 716 passed / 0 failed / 33 skipped on Python 3.13 from freshly generated data (4 PDF/bundle tests run from the repo path because of the Windows 260-character limit in the scratch copy); `satsa validate`, `satsa validate-stress`, ruff and mypy clean.

## Step 21 — Peer cohorts actually used; unused robust-statistics claims corrected — done, verified

- **Gap.** The runner resolved each entity's peer cohort (`config/peers.yaml`) and passed it to every rule, but no rule used it. EG01's "peer" 5th-percentile close time was computed over the whole portfolio *including the entity itself*, so an entity's own fast closures lowered the baseline they were judged against.
- **Fix.** `BaseRule.peer_filter` selects the resolved cohort, or every other entity when none is given; the target is never in its own baseline. EG01 (p5 close-time baseline), NS02 (standard categories) and NS03 (reported peer night share) use it. NS02's `min_peer_entity_count` (6 portfolio entities) became `min_peer_share` (0.6 of the cohort), since cohort sizes vary. The sensitivity sweep now passes the same cohorts as the runner.
- **Effect on this dataset: none.** With 10 entities over 5 sectors and 3 size bands, no sector or sector+size cohort reaches 3 peers, so large entities fall back to "all large" and the rest to "all other entities". Results are unchanged (21/21, 0 false positives, sweep 5 of 54). Real sector cohorts need a larger portfolio.
- **Claims corrected.** `RobustStats` (median/MAD/robust z/IQR) and `SPCDetector` (CUSUM/EWMA) are implemented and unit-tested but called by no rule, score or metric. README, DECISIONS ADR-001, architecture (text and diagram), deployment_ops, infrastructure, slides, demo script and analytics_methodology §1–2 described them as how findings are produced. `docs/ps_traceability.md` row 7 (PS requirement: benchmark against sector/size peers using robust statistics) is now marked **Partial**. The README rule tables are rewritten from the code (many rows had wrong thresholds or described checks the code doesn't do).
- **Tests.** `test_eg01_baseline_comes_from_peers_not_the_entity_itself` (the old portfolio p5 hid an entity whose every closure took 60 s) and `test_ns02_standard_categories_come_from_the_peer_cohort`.
- **Verified.** 718 passed / 0 failed / 33 skipped on Python 3.13 from freshly generated data (4 PDF/bundle tests run from the repo path); `satsa validate`, `satsa validate-stress`, ruff and mypy clean.

## Step 22 — Robust z-score against peers for NS03 and EG11; zero-spread z-score bug — done, verified

- **Change.** `BaseRule.robust_z` computes $z = (x - \text{median}) / \max(1.4826\,\text{MAD}, s_{min})$ against the peer cohort (≥ 3 peers with enough volume, else the rule falls back to its fixed threshold). NS03 flags a night share with z ≤ −3.5 (`max_robust_z`, `min_spread` 0.02); EG11 flags zero true positives or an FP/benign rate with z ≥ 3.5 (`min_spread` 0.01). Findings record `method`, `robust_z`, `peer_median` and `peer_count`; the PDF chart and plain-language headline use the peer median (older stored findings still render).
- **Why these two.** They measure continuous rates that vary across peers. EG05, the other rule the sweep flagged, was not changed: its measure (a count of chronic repeat pairs) is 0 for nearly every peer, so a z-score is meaningless there; its fix is a volume-aware threshold, best calibrated on real data.
- **Effect.** Planted defects still detected (CSE-10 night share z ≈ −11; CSE-07 FP rate z ≈ +8), 21/21 with 0 false positives. The sweep drops from 5 of 54 to 4 of 62 changed outcomes: EG11 is no longer fragile. New tests show both directions: a 10% night share among ~22% peers is flagged although the old fixed 3% passed it, and a 99% FP rate among ~98.5% peers is not flagged although the old fixed 98% flagged it.
- **Library bug fixed.** `RobustStats.robust_z_score` returned 0 for any value when the reference values had no spread, hiding an outlier among identical peers. It now returns ±inf for a differing value (0 only for an equal one). The function had no callers, so no result changed.
- **Traceability.** PS requirement 7 stays **Partial**: 4 rules use peer cohorts and 2 use robust statistics; the rest use fixed thresholds.
- **Verified.** 720 passed / 0 failed / 33 skipped on Python 3.13 from freshly generated data (4 PDF/bundle tests run from the repo path); `satsa validate`, `satsa validate-stress`, ruff and mypy clean.

## Step 23 — Shadow-pilot readiness: per-rule figures, intervals, blind adjudication, runbook — done, verified

- **Gap.** `docs/validation.md` §5 said a convincing pilot needs frozen thresholds, per-rule recall/precision with confidence intervals, firing rates, and blind adjudication of findings the workpapers don't mention. The tool produced one pooled recall and precision and nothing else.
- **Added to every shadow-pilot evaluation.** Per-rule recall and precision at (entity, rule) level with 95% Wilson intervals; each rule's firing rate across assessed entities; the run's rule-config hash; pair-level overall recall with its interval. Shown by the CLI, `docs/validation_report.md`/`.html`, and the `/shadow-pilot` page.
- **Blind adjudication sheet.** `satsa validate --shadow-csv W --adjudication-csv OUT` writes every finding the workpaper neither confirmed nor cleared, with what to check but no score, confidence, severity or rank, in entity/rule order. The filled sheet is a valid workpaper CSV to append and re-evaluate.
- **Runbook.** `docs/shadow_pilot_runbook.md`: freeze and hash the config first, ingest, map workpapers to rules without looking at findings, evaluate, adjudicate blind, read results with intervals, and re-measure on different entities after any threshold change.
- **What the intervals show already.** On the synthetic stand-in, each rule has about one confirmed case: "1/1" is 100% with a 95% interval of 21–100%. Per-rule claims need many entities.
- **Verified.** 722 passed / 0 failed / 33 skipped on Python 3.13 from freshly generated data (4 PDF/bundle tests run from the repo path); `satsa validate`, `satsa validate-stress`, ruff and mypy clean.

## Step 24 — EG05 chance floor; lift by queue depth — done, verified

- **EG05.** The sweep showed `min_repeat_count` 8 → 6 flagging 6 entities including all 3 clean ones: with ~2,000 alerts over ~1,800 asset × rule pairs, a few pairs repeat 6–7 times by coincidence. `chance_repeat_floor` computes, per entity, the smallest repeat count that fewer than `max_chance_pairs` (0.5) pairs would reach by chance under a Poisson model of its volume; EG05 uses the larger of that and `min_repeat_count`. The floor is capped at 2 × `min_repeat_count`, because in a very busy entity with few pairs the model would excuse any repeat count, while a pair firing dozens of times, always benign and never tuned, is the defect itself. For the medium/large synthetic entities the floor is 8, matching the hand-picked value.
- **Effect.** Baseline unchanged (21/21, 0 false positives). The sweep is now 3 of 64 on both datasets, and no ±20% move creates a false alarm on a clean entity in the primary dataset. Findings record `effective_min_repeats` and `chance_floor`.
- **Lift.** Every 1%/2%/5% budget exceeds the 109-alert queue, so those three rows were identical. The report now also gives lift by queue depth: 14.98x (top 10), 19.47x (top 25), 10.49x (top 50), 5.99x (top 100), 5.50x (all 109). 13 of the 16 affected alerts found are in the first 25 items.
- **Tests.** `test_chance_repeat_floor_scales_with_volume_and_is_capped`, `test_eg05_ignores_coincidental_repeats_but_keeps_chronic_pairs`.
- **Verified.** 724 passed / 0 failed / 33 skipped on Python 3.13 from freshly generated data (4 PDF/bundle tests run from the repo path); `satsa validate`, `satsa validate-stress`, ruff and mypy clean.

## Step 25 — Scoring and review-queue audit — done, verified

- **Risk bands mislabelled serious entities.** The index averages over 8 domains, so one maximum-score finding cannot exceed ~14/100: CSE-09 (silent critical asset, score 95), CSE-08 and CSE-05 were "Low Supervisory Concern". `band_floors` in `config/scoring.yaml` now classifies an entity with a critical-severity finding (confidence ≥ 0.5) at least High, and with a high-severity finding at least Moderate. The index and ranking are unchanged; the entity profile says when the band was raised.
- **Three banding schemes reduced to one.** The dashboard label used the 4 configured bands; badge colours and "action required" used index cut-offs (25/50); the PDFs used a separate 3-band index scheme. An entity's classification, colour and action flag now all come from the stored band (`band_tier`); index cut-offs remain only for colouring raw domain scores.
- **Review queue was not 70/30.** Cited records are limited to the evidence rules attach, while every entity always gets 9 random controls: the synthetic queue is 44 cited / 90 random (33/67). The `review_queue` block of `config/scoring.yaml` was read by nothing (the runner hardcoded 30; `stratified_random_ratio` and `default_sample_size` had no effect). The runner now reads `top_risk_ratio`, `queue_size_per_entity` and `random_seed`; the dead keys are removed; README, architecture, functional design, slides, demo script and the queue page describe the real composition.
- **Queue page counters always showed 0.** They were incremented with `{% set %}` inside a `{% for %}`, which Jinja scopes to the loop. Now computed with filters.
- **EG07 scored 2/100.** Confidence used the number of offending analyst-hours (1) as the sample size instead of the closures observed (35). Fixed; CSE-08's EG07 finding now scores normally.
- **Methodology §4 rewritten from the code.** It stated severity weights 1.0/0.8/0.5/0.25 (actual: per-rule 70–95), breadth weight 0.15 (actual 0.10), and bands at 20/40/70 with an "Elevated" band (actual 25/50/75: Low/Moderate/High/Critical).
- **Noted, not changed.** For EG03, EG08, EG09, EG12, NS04, NS06 and NS07 the confidence input is the number of offending items, so a few serious cases score low (EG12: 3 critical cases without containment score 12). Changing it would move most risk indices; documented in methodology §4.1 as a known limitation.
- **Verified.** 728 passed / 0 failed / 33 skipped on Python 3.13 from freshly generated data (PDF/report/bundle tests run from the repo path); detection unchanged (21/21, 0 false positives); `satsa validate`, `satsa validate-stress`, ruff and mypy clean.
