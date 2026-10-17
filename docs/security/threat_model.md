# Threat model (version 1, Phase 2)

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
| T2 | Credential stuffing or guessing | PBKDF2-SHA256 (200k); lockout after 5 failures in 15 min, generic errors; setup-token throttling | `tests/test_login_lockout.py`, `tests/test_deployment_setup.py::test_setup_token_guessing_is_throttled` |
| T3 | CSRF / cross-site WebSocket hijacking | SameSite cookies; same-origin check on unsafe methods and on the WS handshake (`satsa.web_security`) | `tests/test_csrf.py` |
| T4 | Session theft or reuse | Random 256-bit tokens, stored hashed; HttpOnly; Secure under TLS; 8 h absolute and 30 min idle expiry; blocking ends sessions | `tests/test_access_controls.py::test_an_idle_session_ends`, `tests/test_auth*.py` |
| T5 | Published default passphrases in production | Production has no seeded accounts; one-time setup token; demo mode is isolated and labelled; demo accounts must change their passphrase at first login | `tests/test_deployment_setup.py`, `tests/test_first_login_password_change.py` |
| T6 | Leaked machine credential | Scoped to entities and `submit`, expiring (at most 365 d), revocable, verifier only, shown once, every use audited | `tests/test_access_controls.py` |
| T7 | Malicious upload: zip slip, decompression bomb, oversize | Member-path validation, entry, ratio and expanded-size limits before extraction; byte budget on uploads; API body cap | `tests/test_injection.py`, `tests/test_access_controls.py::test_an_oversized_submission_is_refused_before_it_is_read`. **Gap:** no parse-time limit; chunked API bodies without Content-Length are not capped before parsing. |
| T8 | Injection: SQL, path traversal, XSS | Parameterised SQL; entity-id and run-id allow-lists; `safe_join`; Jinja autoescape | `tests/test_injection.py`, `tests/test_offline_hardening.py` |
| T9 | CSV / formula injection in exports | Formula-like text cells are prefixed with `'` (`satsa.csv_safe`) | `tests/test_access_controls.py::test_the_queue_export_neutralises_a_formula_in_submitted_text` |
| T10 | Silent loss or alteration of evidence | Immutable published batches with SHA-256; retirement instead of deletion; an append-only, hash-chained audit log | `tests/test_migrations.py`, `tests/test_access_controls.py::test_retiring_an_entity_keeps_its_evidence_and_replays`, `tests/test_audit_tamper*.py` |
| T11 | Re-identification of analysts | HMAC pseudonyms under a key kept in `data/secrets/`, never served; rotation versioned and audited | `tests/test_keys.py` |
| T12 | Data exfiltration over the network | Loopback bind by default; egress guard (defence in depth); no external assets | `tests/test_netguard.py`, `tests/test_offline_hardening.py`, `tests/browser/test_offline_browser.py` |
| T13 | Resource exhaustion by long requests | Imports and assessments run in the worker (one writer), not in requests; disk preflight | `tests/test_jobs.py`. **Gap:** no memory preflight. |
| T14 | Secrets in logs or exports | Admin audit strips password fields; tokens are never logged; `keys status` and `service-credential list` show no secrets | `tests/test_access_controls.py` (no secret stored or audited). **Gap:** there is no structured-log redaction test yet (Phase 5). |

## Residual risks (accepted or open)

- **A privileged host administrator** can read the databases, the keys and the setup token. File
  permissions and encryption at rest by the application cannot stop them. Volume encryption and
  custody of recovery keys are deployment controls (docs/key_management.md).
- **No MFA yet** for privileged accounts. This is planned and is not implemented in this phase.
- **Reverse proxies** that rewrite `Host` must set `SATSA_ALLOWED_ORIGINS`, or CSRF checks will
  refuse legitimate posts. That fails closed.
- **Shared deployments** are not multi-tenant: analysts and examiners see the whole portfolio by
  design.
