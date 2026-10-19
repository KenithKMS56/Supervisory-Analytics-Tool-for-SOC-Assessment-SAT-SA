# Administrator manual

For the person who installs, runs, secures and recovers a SAT-SA deployment. Each task gives
the commands; the linked page holds the detail. The drills these commands were run in, and
their results, are in `docs/drills.md`.

SAT-SA is one on-premises deployment for many Critical Sector Entities (CSEs). It runs three
processes against one data directory:

| Process | Command | Port | Who uses it |
|---|---|---|---|
| SAT-SA web app | `satsa serve` | 8001 | analysts, examiners, the submission API |
| Administration Portal | `satsa admin` | 8000 | deployment administrators only |
| Worker | `satsa worker` | — | runs imports, assessments and demo loads as durable jobs |

`python entrypoint.py` (and the container) starts all three with the same `data/`.

## 1. Install

- **Offline install** from a signed release bundle: `docs/offline_install.md`. Verify the bundle
  first with the release public key you obtained separately:

  ```
  satsa release verify <extracted bundle> --public-key release_public_key.pem
  ```

- **Container**: `docs/deployment_ops.md`, section 1.2. The Compose file mounts `./data`
  (database, published Parquet, manifests, `data/secrets/`), `./reports` and `./certs`; nothing
  that must survive a container recreation lives in the image.
- **Path length on Windows.** Data paths nest about 90 characters below the data directory.
  Install under a short path (for example `C:\SATSA`), or enable Windows long paths; under a
  deep directory an import fails with `WinError 206` (seen in Phase 5 testing).

## 2. First-run setup

A production deployment starts empty: no accounts, no data, no published passphrases. Follow
`docs/first_run_setup.md`. The Administration Portal's `/setup` page, or from the shell:

```
SATSA_SETUP_PASSPHRASE=... satsa setup --admin-username ops-admin --deployment-name "SOC supervision" \
    --timezone Asia/Kolkata --organisation-name "Example Authority"
```

`--organisation-name` is optional. It is the organisation the portals and reports name (titles,
role labels, report headers). Leave it out for neutral wording ("Administration Portal", "the
supervisory authority"); name only the organisation that actually runs the deployment. Change
it later, audited:

```
satsa deployment brand --organisation "Example Authority" --actor ops-admin
satsa deployment brand --organisation "" --actor ops-admin      # back to neutral wording
satsa deployment show                                          # mode, name, retention (no secrets)
```

Demo mode (`SATSA_DEMO=1` when the database is first created) is for demonstrations only: it
publishes default passphrases and shows a banner on every page. It is never turned on for an
existing production database.

## 3. Accounts and access

- Accounts are issued in the Administration Portal (Users → Create). Roles: *Super
  Administrator* (Administration Portal only), *Analyst* (ingestion, assessments, tuning),
  *Examiner* (review decisions). Analysts and examiners are portfolio-wide by design; see
  `docs/security/permission_matrix.md`.
- Administrators must enrol a second factor (TOTP, offline) at first sign-in, and receive
  recovery codes: `docs/security/mfa.md`.
- Blocking a user in the portal ends their sessions at once.
- Sessions end after 8 hours, or after `SATSA_SESSION_IDLE_MINUTES` of inactivity.
- Five failed sign-ins lock an account for 15 minutes. The message never says whether the
  account exists.
- Machine clients submit with **service credentials**, never a session:
  `docs/api_credentials.md`.

  ```
  satsa service-credential create --name "CSE-01 connector" --entity CSE-01 --expires-days 90
  satsa service-credential list
  satsa service-credential revoke <id>
  ```

## 4. Network exposure and TLS

On loopback, cookies are not marked Secure, which is explicit development mode. Anything
reachable from another machine needs TLS (`SATSA_TLS_CERT`, `SATSA_TLS_KEY`) and
`SATSA_COOKIE_SECURE=1`: `docs/deployment_ops.md`, section 1.3. Behind a reverse proxy that
rewrites `Host`, list the public origin in `SATSA_ALLOWED_ORIGINS`, or state-changing requests
are refused as cross-site.

Every response carries a Content-Security-Policy (only the portal's own scripts, styles, fonts
and connections; no framing by other sites), `X-Content-Type-Options: nosniff`,
`X-Frame-Options: DENY` and `Referrer-Policy: same-origin`. Request bodies are capped as they
arrive, so a chunked body is cut off too:

| Request | Default cap | Setting |
|---|---|---|
| `/upload` | 1024 MiB + 1 MiB of form framing | `SATSA_MAX_UPLOAD_MB` |
| Every other SAT-SA request | 64 MiB | `SATSA_MAX_API_BODY_MB` |
| Administration Portal | 1 MiB | fixed |

## 5. Jobs and health

```
satsa jobs list                 # state, stage, attempts, errors
satsa jobs cancel <job id>
satsa ops ready                 # database, schema, catalog, disk, worker heartbeat (also GET /readyz)
```

A job survives a restart. An expired lease is retried or failed, never run twice at once. The
Jobs page shows the same state. There is one worker per deployment (single writer); readers
keep using the last published data while it works.

## 6. Backups, restore and recovery

`docs/backup_restore.md`. A backup is consistent: SQLite's backup API, published Parquet,
manifests and secrets, with a checksum manifest.

```
satsa backup --dest /backups --keep 7                         # --encrypt: one AES-256-GCM file
satsa restore /backups/<backup> --target /srv/satsa-restored --replay <run id>   # a new, empty directory
satsa verify-data --data-dir /srv/satsa-restored/data
```

`--replay` re-runs a recorded assessment in the restored instance and compares its analytical
fingerprint and results with the recorded ones.

Recovery objectives are measured in drills (`docs/backup_restore.md`, "Recovery objectives"),
not promised.

## 7. Upgrades and migrations

`docs/migrations.md`. Stop the web app, the portal and the worker. Copy the data directory,
then:

```
satsa migrate --data-dir data          # backs up the database before the first pending migration
satsa verify-data --data-dir data
```

Every migration only adds tables and columns. The previous release ignores what it does not
know, and the recovery path is written per version.

## 8. Keys and retention

- The pseudonymisation key lives in `data/secrets/` and is never regenerated silently:
  `docs/key_management.md`.

  ```
  satsa keys status
  satsa keys rotate --i-understand-pseudonyms-will-not-link
  ```

  Rotation is versioned, and the flag is required because a person pseudonymised under the old
  key no longer links to the same person under the new one (explained on that page).
- Retention of job inputs and the number of local backups are set at setup. Apply them with:

  ```
  satsa ops retention --dry-run                     # what would go
  satsa ops retention --backups-dir /backups
  ```

  Assessment evidence is never deleted by ordinary UI actions. Retiring an entity keeps its
  data and history.
- Support diagnostics: `satsa ops diagnostics --out diag.zip` writes a redacted package (no
  data, secrets or usernames) to review before sharing. Nothing is uploaded anywhere.

## 9. Rule configuration

`config/rules.yaml` changes through versions: proposed, approved by a different person, then put
in force (`docs/rule_governance.md`). Do not edit it by hand: an edit is recorded as an
`external_edit` version and flagged, because it skipped approval. Signed rule packs are imported
on Rule Tuning and recorded with their signature as the approval.

## 10. When something is wrong

| Symptom | Look at |
|---|---|
| Import job failed | its job page (structured error); `/dq` for data-quality issues |
| Upload held | Upload → Held submissions: publish as is, or discard (both audited) |
| `/readyz` not ready | `satsa ops ready` names the failing check |
| A page is slow for many readers during an import | expected on one worker: `docs/benchmarks.md`, "Ten concurrent readers" |
| Audit chain doubt | `satsa audit verify` |
