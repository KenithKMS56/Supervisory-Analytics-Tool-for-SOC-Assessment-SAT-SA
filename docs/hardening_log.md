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
