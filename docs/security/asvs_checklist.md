# Security verification checklist (version 1, Phase 2)

This checklist uses OWASP ASVS 4.0.3 requirements at Level 2, for the areas that apply to an
offline web application. It records **our own verification**. It is not a certification, and it
is not an independent assessment.

Statuses:
- **verified**: an automated test named here checks it.
- **partial**: implemented, with a stated gap.
- **not implemented**
- **n/a**: does not apply to this application.

| ASVS | Requirement (short) | Status | Evidence / gap |
|---|---|---|---|
| V2.1.1 | Passphrases at least 12 characters | verified | `passphrase_policy_error`; `tests/test_first_login_password_change.py` |
| V2.1.7 | Reject known or breached passwords | partial | Published defaults are rejected; there is no offline breach list |
| V2.2.1 | Anti-automation on authentication | verified | Lockout; `tests/test_login_lockout.py`; setup throttling |
| V2.2.2 / V2.8 | Multi-factor authentication for privileged users | partial | Admin Portal: offline TOTP (RFC 6238 vector tested), replay protection, hashed one-time recovery codes, audited reset; required in production (`tests/test_admin_mfa.py`). **SAT-SA analyst and examiner accounts have no MFA yet** |
| V2.4.1 | Passwords stored with an approved KDF | verified | PBKDF2-HMAC-SHA256, 200k iterations, per-user salt |
| V2.5.4 | No shared or default accounts | verified (production) | Production starts empty; demo accounts exist only in a demo deployment; `tests/test_deployment_setup.py` |
| V2.10.1–4 | Service authentication without static, long-lived secrets in code | verified | Service credentials expire, can be revoked, and only their verifiers are stored; `tests/test_access_controls.py` |
| V3.2.1 | New session token at authentication | verified | `create_session` on every login |
| V3.3.1 | Logout invalidates the session | verified | `tests/test_auth_flow.py` |
| V3.3.2 | Idle and absolute timeouts | verified | 30 min idle, 8 h absolute; `tests/test_access_controls.py::test_an_idle_session_ends` |
| V3.4.1–3 | Cookie Secure, HttpOnly and SameSite | partial | HttpOnly and SameSite always; Secure only under TLS (`SATSA_COOKIE_SECURE`) |
| V3.5.3 / V4.2.2 | CSRF protection | verified | Origin, Referer and Sec-Fetch-Site checks; `tests/test_csrf.py` |
| V4.1.1 / V4.1.3 | Access control enforced server-side, least privilege | verified | `tests/test_rbac_matrix.py` (every route x every role) |
| V4.2.1 | IDOR: data scoped to the principal | partial | A service credential's entity scope is verified. Operators are portfolio-wide by design (docs/security/permission_matrix.md) |
| V4.3.1 | Admin interfaces need appropriate authentication | verified | Separate portal and roles; MFA required in production (`tests/test_admin_mfa.py`) |
| V5.1.3 / V5.1.4 | Input validation by allow-list | verified | Entity, run, job and batch id patterns; `tests/test_injection.py` |
| V5.2.2 / V5.3.3 | Output encoding / XSS | verified | Jinja autoescape; `tests/test_injection.py` |
| V5.3.4 | Parameterised queries | verified | DuckDB and SQLite parameters; `tests/test_injection.py` |
| V5.3.9 | Path traversal / local file inclusion | verified | `safe_join`, `safe_archive_member`; zip-slip test |
| V5.3.x (CSV) | Formula injection in exports | verified | `satsa.csv_safe`; `tests/test_access_controls.py` |
| V6.2.1 | Approved cryptography | verified | HMAC-SHA256, SHA-256 and SHA3-256 (stdlib); `cryptography` for signing |
| V6.4.1 / V6.4.2 | Key management, keys not in code | partial | Keys live in `data/secrets/`, are versioned and audited (`tests/test_keys.py`). There is no HSM or KMS (offline); host custody applies |
| V7.1.1 | No credentials or session tokens in logs | partial | Tokens and passwords are never logged by design; there is no automated log-scan test yet |
| V7.2.1 | Authentication decisions logged | verified | Login, lockout and setup are written to the audit logs |
| V7.3.1 / V7.3.3 | Log integrity | verified | Hash-chained audit log; `tests/test_audit_tamper*.py` |
| V8.3.4 | Sensitive data identified and protected | verified | Pseudonymisation and redaction on every ingestion transport; `tests/test_brief_defects.py::test_b02_*` |
| V9.1.1 | TLS for all client connections | partial | Optional TLS; loopback by default; a warning when the deployment is exposed without TLS |
| V10.3.2 | Integrity of updates | partial | Signed rule packs; the offline release bundle is not signed yet (Phase 2/5) |
| V12.1.1 | Upload size limits | verified | Upload byte budget, zip limits, API body cap |
| V12.1.2 | Decompression bombs | verified | Ratio and expanded-size limits before extraction |
| V12.4.1 | Uploads stored outside the web root | verified | `data/jobs/<id>/input`, never served |
| V13.1.3 | API URLs do not expose sensitive information | verified | Service tokens travel in a header, never in a URL |
| V13.2.1 | Methods restricted | verified | Route matrix |
| V14.2.1 | Dependencies up to date / audited | **not implemented** | No `pip-audit` run in this phase (Phase 5) |
| V14.3.2 | No debug modes in production | verified | `/docs` needs a session; no debug server |
| V14.5.3 | Origin header validated | verified | `satsa.web_security` |
