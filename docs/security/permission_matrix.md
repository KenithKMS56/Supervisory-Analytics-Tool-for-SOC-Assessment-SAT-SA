# Permission matrix

The executable source of truth is `tests/test_rbac_matrix.py`. It lists every route of both
portals with its allowed roles, and fails if a route is added without being classified. For every
route it checks each role: anonymous, examiner, analyst and admin. This page summarises it by
resource.

## Roles

| Role | Where | Scope | Status |
|---|---|---|---|
| Deployment administrator (`admin`, `NCIIPC Super Administrator`) | Admin Portal (:8000) only | Deployment-wide: users, organisations, CSEs, audit, activity feed | implemented |
| Analyst | SAT-SA (:8001) | **Portfolio-wide by design**: ingests for, assesses and tunes every entity | implemented |
| Examiner | SAT-SA (:8001) | **Portfolio-wide by design**: reviews findings of every entity; records decisions | implemented |
| Service account (service credential) | `POST /api/v1/submissions` only | Explicit list of entities, `submit` scope, expiry | implemented (Phase 2) |
| Reviewer / approver | (none) | (none) | **not implemented**. Approval workflows such as rule-pack approval and case sign-off come in Phase 3. The role will be added only with a complete workflow. |
| Read-only auditor | (none) | (none) | **not implemented** |
| CSE-scoped roles (`CSE Administrator`, `SOC Manager`, `SOC Analyst`, `CSE Viewer`) | can be created in the Admin Portal | one CSE | **refused by SAT-SA**. No CSE-facing workflow exists yet; a session holding such a role gets 403 on every gated path. |

Analysts and examiners are deliberately not scoped to entities: a supervisory team assesses the
whole portfolio. Separation of duties is between the two roles. Whoever tunes rules cannot sign
off findings, and the reverse. If per-entity examiner assignment is needed, it comes with the
Phase 3 case workflow.

## Resources

| Resource | Anonymous | Examiner | Analyst | Admin | Service credential |
|---|---|---|---|---|---|
| Portfolio, entity, finding pages, review queue, blind review | login redirect | read | read | 403 | 401 |
| Review decisions (`/api/v1/feedback`, blind-review submit) | 401 | **write** | 403 | 403 | 401 |
| Upload, held-batch publish/discard, register or retire entity | 401 | 403 | **write** | 403 | 401 |
| JSON batch submission `/api/v1/submissions` | 401 | 403 | write | 403 | **write, own entities only** |
| Jobs: list, page, `/api/v1/jobs/{id}` | 401 | read | read | 403 | 401 |
| Jobs: cancel | 401 | 403 | **write** | 403 | 401 |
| Runs and audit page, data quality, raw alerts, templates | 401 | 403 | read | 403 | 401 |
| Rule tuning (save, preview), rule-pack export/import | 401 | 403 | **write** | 403 | 401 |
| Reports (PDF/HTML), API reads (runs, entities, findings, queue) | 401 | read | read | 403 | 401 |
| CSV exports (findings, queue), audit verification | 401 | 403 | read | 403 | 401 |
| `/docs`, `/openapi.json` | login redirect / 401 | read | read | 403 | 401 |
| Admin Portal: users, organisations, CSEs, admin audit, activity feed and WebSocket | login redirect / 401 | 403 | 403 | **write** | n/a |
| First-run setup `/setup` (Admin Portal) | only while setup is pending, with the one-time token | n/a | n/a | n/a | n/a |

"Read" and "write" mean the role passes authorization. Every state-changing request must also
pass the same-origin check (`satsa.web_security`).

## Enforcement points

1. **SAT-SA middleware** (`enforce_auth_middleware`): no session means a login redirect or 401. A
   role that is not an operator gets 403. An account that still owes a passphrase change gets 403
   or is redirected. Service credentials are resolved here, on every request.
2. **Route dependency** (`require_role`, `require_submitter`): the role allowed for the route.
3. **Handler checks**:
   - entity-id validation;
   - a service credential's entity scope;
   - an analyst-only cancel button on the job page; the cancel route itself is analyst-only.
4. **CSRF middleware** on both portals, and an origin check on the WebSocket handshake.

Blocking a user ends all their sessions on the next request, because `get_session` joins the
identity's status. Revoking or expiring a service credential takes effect on its next request,
since nothing is cached. Sessions end after 8 hours, or after 30 minutes idle
(`SATSA_SESSION_IDLE_MINUTES`).
