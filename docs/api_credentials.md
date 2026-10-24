# Service credentials for the submission API

Machine clients, such as a CSE's connector or a scheduled export script, submit batches to
`POST /api/v1/submissions` with a **service credential**. They do not use a browser session.

## Issue

```
satsa service-credential create --name "CSE-01 Splunk connector" --entity CSE-01 --expires-days 90
```

The command prints the token **once**:
`satsa_sc_<16-hex id>_<43-character secret>`.

Store it in the client's secret store. SAT-SA keeps only a SHA-256 verifier and cannot show the
token again.

- **Scope:** `submit` only, for the entities named with `--entity` (repeatable). A batch for any
  other entity gets `403`.
- **Lifetime:** 1–365 days. There is no non-expiring credential.
- **Audit:** issuing, revoking and every use (`service_credential_used` or
  `service_credential_refused`) are written to the audit chain with the credential id and name,
  never the secret. Batches record `submitted_by = service:<name>`.

## Use

```
curl -X POST http://127.0.0.1:8001/api/v1/submissions \
     -H "Authorization: Bearer satsa_sc_..." -H "Content-Type: application/json" \
     -d @batch.json
```

- A request body over `SATSA_MAX_API_BODY_MB` (default 64) gets `413`, whether it declares its
  length or is sent in chunks.
- An invalid, expired or revoked credential gets `401`. This applies from its next request,
  because nothing is cached.
- Validation, idempotency and overlap rules are those in `docs/data_contract.md`.

## Rotate and revoke

```
satsa service-credential list                  # ids, scopes, expiry, last use: never secrets
satsa service-credential create ...            # issue the replacement first
satsa service-credential revoke <credential id>
```

## Compatibility

An analyst's signed-in session still works on this endpoint, for the interactive and test uses
documented earlier. It is not the machine integration contract.
