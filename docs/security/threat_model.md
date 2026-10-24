# Threat model (version 4, Phase 5)

Scope: one SAT-SA deployment, made up of:
- the Admin Portal (:8000);
- SAT-SA (:8001);
- the job worker;
- `data/`, which holds SQLite, published Parquet, keys and job inputs;
- `config/`.

The deployment is offline: there is no outbound network, and both portals listen on loopback
unless the operator opts in.

**This is our own analysis, not an independent assessment.** An external penetration test is a
release gate that is still **blocked** (docs/release_readiness.md).

## Assets

- **Submitted SOC evidence** (published batches): its integrity and its confidentiality, even
  though it is pseudonymised.
- **Assessment results**: runs, findings, scores, rule results and review decisions. Their
  integrity and reproducibility matter most.
- **The audit chain.**
- **Pseudonymisation keys** (`data/secrets/`). Disclosing them re-identifies analysts.
- **Credentials**: passphrase hashes, session tokens, service-credential verifiers, the setup
  token.
- **Configuration**: rules, scoring and thresholds.

## Actors

- Authenticated analysts and examiners, and a careless or malicious insider among them.
- A deployment administrator.
- A CSE or connector submitting batches through a service credential.
- A malicious web page visited by an operator's browser.
- A malicious or malformed submission.
- Someone with local file access to the host. **Out of scope** as an attacker: see residual
  risks.

## Threats, controls and evidence

| # | Threat | Controls | Verified by |
|---|---|---|---|
| T1 | Unauthorised access to a route or resource | Middleware plus route dependency; complete route matrix | `tests/test_rbac_matrix.py` (every route x 4 roles), `tests/test_access_controls.py` |
| T2 | Credential stuffing or guessing | PBKDF2-SHA256 (200k); lockout after 5 failures in 15 min, generic errors; setup-token throttling; administrator TOTP second factor (5 wrong codes end the session) | `tests/test_login_lockout.py`, `tests/test_deployment_setup.py::test_setup_token_guessing_is_throttled`, `tests/test_admin_mfa.py` |
| T3 | CSRF / cross-site WebSocket hijacking | SameSite cookies; same-origin check on unsafe methods and on the WS handshake (`satsa.web_security`) | `tests/test_csrf.py` |
| T4 | Session theft or reuse | Random 256-bit tokens, stored hashed; HttpOnly; Secure under TLS; 8 h absolute and 30 min idle expiry; blocking ends sessions | `tests/test_access_controls.py::test_an_idle_session_ends`, `tests/test_auth*.py` |
| T5 | Published default passphrases in production | Production has no seeded accounts; one-time setup token; demo mode is isolated and labelled; demo accounts must change their passphrase at first login | `tests/test_deployment_setup.py`, `tests/test_first_login_password_change.py` |
| T6 | Leaked machine credential | Scoped to entities and `submit`, expiring (at most 365 d), revocable, verifier only, shown once, every use audited | `tests/test_access_controls.py` |
| T7 | Malicious upload: zip slip, decompression bomb, oversize | Member-path validation, entry, ratio and expanded-size limits before extraction; byte budget on uploads; API body cap | `tests/test_injection.py`, `tests/test_access_controls.py::test_an_oversized_submission_is_refused_before_it_is_read`, `tests/test_security_suite.py` (chunked body cut off at the cap; bombs by ratio, member count, expanded size and a forged size header). **Gap:** no parse-time limit. |
| T8 | Injection: SQL, path traversal, XSS (stored, reflected, DOM) | Parameterised SQL; entity-id and run-id allow-lists; `safe_join`; Jinja autoescape with no `\| safe`; inline-script values through `tojson` or escaped data attributes; the Admin Portal's live feed escapes every value it renders; CSP confines scripts, connections and forms to the portal | `tests/test_injection.py`, `tests/test_offline_hardening.py`, `tests/test_security_suite.py` |
| T9 | CSV / formula injection in exports | Formula-like text cells are prefixed with `'` (`satsa.csv_safe`) | `tests/test_access_controls.py::test_the_queue_export_neutralises_a_formula_in_submitted_text` |
| T10 | Silent loss or alteration of evidence | Immutable published batches with SHA-256; retirement instead of deletion; an append-only, hash-chained audit log | `tests/test_migrations.py`, `tests/test_access_controls.py::test_retiring_an_entity_keeps_its_evidence_and_replays`, `tests/test_audit_tamper*.py` |
| T11 | Re-identification of analysts | HMAC pseudonyms under a key kept in `data/secrets/`, never served; rotation versioned and audited | `tests/test_keys.py` |
| T12 | Data exfiltration over the network | Loopback bind by default; egress guard (defence in depth); no external assets | `tests/test_netguard.py`, `tests/test_offline_hardening.py`, `tests/browser/test_offline_browser.py` |
| T13 | Resource exhaustion by long requests | Imports and assessments run in the worker (one writer), not in requests; disk preflight | `tests/test_jobs.py`. **Gap:** no memory preflight. |
| T14 | Secrets in logs or exports | Admin audit strips password fields; tokens are never logged; `keys status` and `service-credential list` show no secrets | `tests/test_access_controls.py` (no secret stored or audited). **Gap:** there is no structured-log redaction test yet (Phase 5). |
| T15 | Tampered, forged or replayed entity response package; malicious attachment | HMAC-SHA256 token per request under a key in `data/secrets/`; must answer the case's current request; same package is idempotent, a different one to an answered request is refused; zip member, count, size and ratio limits; attachments stored by hash, served only as `nosniff` downloads, hash re-checked on download | `tests/test_case_packages.py`, `tests/test_case_http.py` |
| T16 | Rewriting a supervisory decision or its history; lost update by a concurrent edit | Append-only `case_events` (triggers refuse UPDATE/DELETE); superseding decisions instead of edits; every action in the audit chain; `expected_version` check inside one IMMEDIATE transaction | `tests/test_cases.py::test_history_is_immutable_and_corrections_supersede`, `::test_conflicting_concurrent_edits_are_detected` |
| T17 | Self-approval of a decision | Owner-only actions; closure and verification need an examiner other than the owner and the decision maker; adjudication by a third examiner | `tests/test_cases.py::test_unauthorised_transitions_fail`, `::test_a_disagreement_must_be_adjudicated_by_a_third_examiner` |
| T18 | Supervisor-only evidence leaking to an entity, or scores leaking into a blind task | Request packages carry no score, peer, severity, evidence record or other entity; blind-task pages are built without any scored field until the reveal | `tests/test_case_packages.py::test_the_request_package_carries_only_what_the_entity_needs`, `tests/test_blind_tasks.py::test_a_task_serves_nothing_scored_until_its_examiner_reveals_it` |
| T19 | Hiding a concern through context: a self-approved or open-ended exception, maintenance stretched over a silent period, or a rule ruled not applicable | Exceptions and maintenance need an examiner other than the requester (also a database `CHECK`); exceptions expire within 366 days and never cover a critical finding; maintenance covers at most 92 days and only its asset and dates; an excepted finding is still recorded and shown; every request, approval and revocation is in the audit chain; runs record which context was in force and replays use it | `tests/test_context_analytics.py`, `tests/test_context_http.py` |
| T20 | Stored text rendered as markup in a downloaded report | The HTML reports escape every value; they are built per request in a private temporary directory, not a shared path | `tests/test_context_http.py::test_report_html_escapes_stored_text` |
| T21 | Open redirect after sign-in (`next=//host`, `/\host`) used for phishing | `next` must be a path on this site: one leading `/`, no backslash or control character; anything else goes to the portfolio | `tests/test_security_suite.py::test_a_sign_in_never_redirects_off_the_portal` |
| T22 | Clickjacking and content-type sniffing | `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin` on every response of both portals | `tests/test_security_suite.py::test_every_response_carries_the_security_headers` |
| T23 | An analyst-controlled value (a file name, a finding id in a URL) running script in an administrator's browser through the live activity feed | Every event and session value is HTML-escaped before `innerHTML` (`esc()` in `admin_overview.html`) | `tests/test_security_suite.py::test_the_admin_live_feed_escapes_what_it_renders` |

## Residual risks (accepted or open)

- **A privileged host administrator** can read the databases, the keys and the setup token. File
  permissions and encryption at rest by the application cannot stop them. Volume encryption and
  custody of recovery keys are deployment controls (docs/key_management.md).
- **MFA covers Admin Portal accounts only.** Administrators use offline TOTP, required in
  production. Analyst and examiner accounts on SAT-SA have passphrases only.
- **Reverse proxies** that rewrite `Host` must set `SATSA_ALLOWED_ORIGINS`, or CSRF checks will
  refuse legitimate posts. That fails closed.
- **Shared deployments** are not multi-tenant: analysts and examiners see the whole portfolio by
  design.
