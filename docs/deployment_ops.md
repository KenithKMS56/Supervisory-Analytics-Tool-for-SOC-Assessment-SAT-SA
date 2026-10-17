# SAT-SA Deployment & Operations Guide

> **Supervisory Notice:** *Indicators requiring supervisory review; not a compliance determination.*

This guide provides operational procedures for deploying, maintaining, updating, and backing up **SAT-SA** in air-gapped supervisory environments.

---

## 1. Installation Procedures

### 1.1 Air-Gapped Python Environment
The bundle must be built with a wheelhouse for the target's OS and Python version
(`scripts/build_wheelhouse.sh`, then `satsa offline-bundle --wheelhouse wheelhouse`). The install
scripts take every package from that wheelhouse and never fall back to downloading; without one
they stop with an error. Full procedure and its limits: [offline_install.md](offline_install.md).

1. Extract the offline distribution archive:
   ```bash
   tar -xzf dist/satsa_bundle.tar.gz
   cd satsa_bundle
   ```
2. Run the automated air-gapped setup script:
   - **Linux / RHEL / Ubuntu:** `bash install_offline.sh`
   - **Windows Server:** `install_offline.bat`
3. Verify offline installation and air-gap integrity:
   ```bash
   satsa version
   # Output: SAT-SA version 0.1.0 (Air-gapped, No AI/ML)
   ```

### 1.2 Containerized OCI Deployment (Podman / Docker)
Build and deploy using the `Containerfile` in the bundle. It installs from the bundled
`wheelhouse/`, which for a container must hold Linux wheels for Python 3.11, and the
`python:3.11-slim` base image must already be loaded on the host ([offline_install.md](offline_install.md) §5):
```bash
# Build local container image without network
podman build -t satsa:latest -f Containerfile .

# Launch container, published on this machine's loopback only
podman run -d \
  --name satsa-soc \
  -p 127.0.0.1:8000:8000 \
  -v ./data:/app/data:Z \
  satsa:latest
```

### 1.3 Network exposure, first login and TLS

**Bind address.** The portals are reachable from the local machine only, unless you say otherwise.

| How it is started | Default | To accept connections from other machines |
|---|---|---|
| `satsa serve` / `satsa admin` | listens on `127.0.0.1` | `--host <address>` or `SATSA_HOST=<address>` |
| `docker compose up` (`docker-compose.yml`) | ports published on `127.0.0.1` | `SATSA_BIND_ADDRESS=0.0.0.0` (or one interface address) |
| `python entrypoint.py` outside a container | listens on `127.0.0.1` | `SATSA_HOST=<address>` |
| `docker run` / `podman run` | wherever `-p` publishes | use `-p 127.0.0.1:8000:8000`; a bare `-p 8000:8000` publishes on every interface |

Inside the container image the processes listen on `0.0.0.0` (`ENV SATSA_HOST=0.0.0.0` in the
`Dockerfile`), because container port publishing cannot reach a container-internal loopback.
What other machines can reach is decided by the published address, which is why that is the
setting that defaults to loopback. When the portals listen beyond loopback over plain HTTP,
start-up prints a warning.

**First login.** A new database is seeded with four accounts whose passphrases are published
in the README (`nciipc_admin`, `admin`, `analyst`, `examiner`). Each is created owing a
passphrase change: signing in with the published passphrase opens a session that can reach
the change-password page and nothing else (pages redirect there; APIs, downloads and every
mutating request return HTTP 403). The same applies to any account an administrator creates
or resets with "force password change" ticked. The new passphrase must be at least 12
characters, differ from the current one and not be one of the published defaults; the current
passphrase is asked for again, and wrong attempts count towards the login lockout (5 failures
in 15 minutes). Changing it ends that user's other sessions and is written to the audit log
(`password_changed` / `PASSWORD_CHANGED`). A database created before this rule existed is
covered at start-up: any seeded account still on its published passphrase is flagged then.
There is no setting that turns this off. From the CLI, `satsa users set-password <username>`
sets a passphrase directly.

**TLS (optional).** Serving is plain HTTP unless both a certificate and a key are configured.

```bash
# 1. Create a self-signed certificate offline (needs the local `openssl` command; no CA, no network).
#    Name every hostname and IP address the portals will be reached by.
python scripts/generate_selfsigned_cert.py --out certs --hostname satsa.internal --ip 10.0.0.5
#    (equivalently: satsa tls-cert --out certs --hostname satsa.internal --ip 10.0.0.5)

# 2a. Local processes
satsa serve --ssl-certfile certs/satsa-cert.pem --ssl-keyfile certs/satsa-key.pem
satsa admin --ssl-certfile certs/satsa-cert.pem --ssl-keyfile certs/satsa-key.pem

# 2b. Docker Compose (./certs is mounted read-only at /app/certs)
SATSA_TLS_CERT=/app/certs/satsa-cert.pem SATSA_TLS_KEY=/app/certs/satsa-key.pem docker compose up -d
```

- `SATSA_TLS_CERT` and `SATSA_TLS_KEY` are the environment equivalents of the two flags. One
  without the other, or a path that does not exist, stops start-up: a half-configured TLS
  setup never falls back to plain HTTP.
- With TLS on, session cookies are issued with the `Secure` flag (`SATSA_COOKIE_SECURE=1` is
  set for the portal processes).
- The certificate is self-signed (RSA 3072, SHA-256, server-auth only, default 365 days,
  maximum 825). Browsers will warn until `certs/satsa-cert.pem` is added to the client
  machines' trust store; distribute that file, never `satsa-key.pem`. `certs/` is git-ignored.
  An existing pair is not replaced unless `--force` is given. For a certificate issued by an
  organisational CA, point the same two settings at its files instead.
- The container healthcheck (`python /app/entrypoint.py --healthcheck`) follows the same
  settings and probes over HTTPS when TLS is on.

---

## 2. Standard Operating Procedures (SOP)

### SOP-01: Ingesting Periodic SOC Submissions
When a CSE submits its periodic CSV batch:
```bash
satsa ingest --data-dir /path/to/extracted_csvs --parquet-dir data --db-path data/satsa.db

# A product's own export instead of the canonical CSV layout (see docs/connectors.md):
satsa ingest --data-dir /path/to/splunk_export --source splunk --entity CSE-07
```
- The command ends with a rule-coverage report: which rules will not be assessed because a table was never submitted, and which cannot fire because an alert column they need is empty. Read it before running the assessment.
- Ingestion pipeline validates schemas, executes DQ checks, applies HMAC-SHA256 pseudonymisation, redacts PII, and appends a batch entry to the cryptographic audit trail.

### SOP-02: Executing Quarterly Assessment
```bash
satsa run --period 2026-Q1
```
- Resolves each entity's peer cohort, evaluates rules EG01–EG12 and NS01–NS08 in DuckDB SQL, aggregates domain scores via Noisy-OR, updates SQLite state, and logs execution to the audit chain.

### SOP-03: Generating Supervisory Reports
```bash
# Generate all reports (HTML, PDF, and CSV exports)
satsa report --entity all --format all --output-dir reports/2026-Q1
```
- Produces individual entity reports (`CSE-01_supervisory_report.pdf`, etc.), the portfolio summary HTML and A4 portfolio PDF (`SAT-SA_Portfolio_Report_<run_id>.pdf`), and CSV extracts (`findings_export.csv`, `review_queue_export.csv`, `metrics_export.csv`). The web UI's **Export Report** menu downloads the same PDFs as `SAT-SA_Portfolio_Report_<run_id>.pdf`, `SAT-SA_CSE_<entity_id>_Report_<run_id>.pdf` and `SAT-SA_Finding_<finding_id>.pdf`. The report routes accept an optional `?run_id=` to pin an earlier assessment run.

### SOP-04: Launching Offline Examiner Portal
```bash
satsa serve --port 8000
```
- Navigate to `http://127.0.0.1:8000` in local browser (loopback is the default bind address; see Section 1.3).
- Examiner views portfolio heatmap, inspects entity profiles, reviews finding cards, and marks feedback.

### SOP-05: The job worker

Uploads, re-assessments after rule tuning or an entity change, assessments requested through
the API (`run_assessment_now`), and demo seeding run as **durable jobs** in a worker process,
not inside the web request.

```bash
satsa worker                 # run jobs until stopped (Ctrl+C / SIGTERM)
satsa worker --once          # run what is queued, then exit
satsa jobs list              # recent jobs and live workers
satsa jobs cancel JOB-...    # cancel a queued job; a running one stops at its next stage
```

- **Starting it.** `entrypoint.py` (the container) starts exactly one worker next to the two
  portals. On a native install, start `satsa worker` in the deployment directory, the same
  directory the portals run in.
- **Single writer.** One worker is the deployment's single analytical writer. Two are safe,
  because claims are atomic and publication takes the catalog's writer lock, but they gain
  nothing.
- **What users see.** An upload goes to its job page (`/jobs/<id>`). The page shows the state
  (queued, running, succeeded, failed, cancelled), the current stage, attempts and heartbeat,
  then the outcome. It refreshes itself while the job runs. There is no percentage, because
  none would be measured. If no worker has reported for 60 seconds, the page says so.
- **Restarts.**
  - Jobs live in `data/satsa.db` (table `jobs`) and uploaded files in `data/jobs/<id>/input/`,
    so restarting the portals or the worker loses nothing.
  - A running job holds a lease that its worker renews every lease/4 seconds (lease 120 s by
    default).
  - If the worker dies, the next worker finds the expired lease and requeues the job (imports
    and assessments, up to 3 attempts) or fails it with a `WorkerLost` error (demo seeding,
    which is not retried automatically).
- **No duplicates on retry.**
  - An assessment job's run id is `RUN-<job id>`. A retry after the run was published returns
    that run instead of publishing a second one.
  - An import job's batch id is `BATCH-<job id>-a<attempt>`. A retry continues from a batch an
    earlier attempt published or held instead of ingesting the files again.
- **Disk preflight.** An import refuses to start (`InsufficientDisk`) unless the data volume
  has three times the upload's size free, plus `SATSA_MIN_FREE_DISK_MB` (default 512).
- **Still synchronous** (kept small by design):
  - the JSON submission API's validation and publication (capped by the request size);
  - held-batch publish and discard;
  - the rule-tuning *preview*, which is a dry run and writes nothing.

---

## 3. Signed Rule-Pack Updates

To update detection thresholds or supervisory criteria without altering code:

### Signing key (required)
Rule-pack signing and import use an HMAC key taken from the `SATSA_RULEPACK_SECRET`
environment variable (at least 32 characters; `--secret` overrides it). There is **no built-in
default key**: without one, `satsa rules export/import` exit with an error and the UI's
export/import endpoints return HTTP 503. The key that earlier versions embedded in this repository
is public and permanently compromised; it is explicitly rejected. Generate a fresh key per
deployment, e.g. `python -c "import secrets; print(secrets.token_urlsafe(48))"`, and distribute it
to field stations out of band. Packs signed with the old embedded key must be re-signed.

### Exporting & Signing a Rule Pack (Regulatory Headquarters)
```bash
export SATSA_RULEPACK_SECRET="<deployment-specific key, >= 32 chars>"
satsa rules export   --config-dir config   --output dist/rule_pack_2026_q2.tar.gz   --version 2.0.0
```

### Importing & Verifying a Rule Pack (Field Examiner Station)
```bash
export SATSA_RULEPACK_SECRET="<same key>"
satsa rules import dist/rule_pack_2026_q2.tar.gz --target-dir config
```
- Before anything is written to disk, SAT-SA rejects any archive member that is not a regular file
  under `rule_pack/` (absolute paths, `..` components, links and devices are refused), verifies the
  HMAC signature over the manifest, and checks every file's SHA-256. Files are then written only
  inside the target directory, and the import is logged to the audit trail with the real actor.

---

## 4. Cryptographic Audit Verification & Backup

### Audit Log Integrity Check
Supervisors can verify database integrity at any time:
```bash
satsa audit verify --db-path data/satsa.db            # SAT-SA chain
satsa audit verify --db-path data/satsa.db --chain admin   # Admin Portal chain
```
- Recomputes every entry's hash with the algorithm recorded on that entry (SHA3-256 for new
  entries, SHA-256 for legacy ones). If an entry in the chain was edited, inserted, deleted or
  reordered outside the application, the command fails and reports the first affected row.
- **Limit:** removing the newest entries, or recomputing the entire chain, cannot be detected by
  the chain alone (DECISIONS.md ADR-005). Record a **signed checkpoint** off-box at each
  examination and verify against it later (DECISIONS.md ADR-008):
  ```bash
  # once, on the examiner's own machine or removable media (never leave the private key on the host)
  satsa audit keygen --out-dir E:/satsa-keys
  # at each examination
  satsa audit checkpoint --sign --key E:/satsa-keys/satsa_audit_ed25519.key --out E:/checkpoints/2026-10-01.json
  # later, by anyone holding the public key
  satsa audit verify --checkpoint E:/checkpoints/2026-10-01.json --pubkey satsa_audit_ed25519.pub
  ```
  Verification checks the signature, then that the live chain matches or extends the
  checkpoint. A key readable by other accounts is refused. Without a key pair, `satsa audit
  head` prints the entry count and head hash to copy by hand, checked with
  `satsa audit verify --checkpoint-count <entries> --checkpoint-head <head_hash>`. Either way
  the trail is tamper-evident, not tamper-proof.

### Backup & Disaster Recovery

Use `satsa backup` and `satsa restore`. See docs/backup_restore.md for the full procedure.

Copying `data/` by hand is not a backup:
- copying a live SQLite file leaves out what is still in its write-ahead log;
- the two databases and the published Parquet files must come from the same moment.

```bash
satsa backup --dest /mnt/backup-disk --encrypt --keep 7
satsa restore /mnt/backup-disk/satsa-backup-<time>.satsa-backup --target /srv/satsa-restored --replay RUN-...
```

### SOP-06: Health and readiness

- `GET /healthz` on either portal is liveness: the process answers.
- `GET /readyz` on SAT-SA is readiness. It checks:
  - the database (`quick_check`);
  - the schema version;
  - the catalog;
  - free disk on the data volume (`SATSA_MIN_FREE_DISK_MB`, default 512).

  It answers 503 if any check fails. It also reports whether a worker is alive and how many jobs
  are queued. A missing worker does not make it 503, because reads still work.
- The container healthcheck uses `/healthz`.
- From the shell: `satsa ops ready` (exit status 1 when not ready).

### SOP-07: Retention

```bash
satsa ops retention --dry-run                      # what would go
satsa ops retention --backups-dir /mnt/backup-disk
```

Retention deletes only:
- the uploaded files of finished jobs older than the configured number of days;
- local backups beyond the configured number.

The settings are made in first-run setup (docs/first_run_setup.md). Published submissions, runs,
findings, decisions and the audit log are never deleted by retention. Every deletion is audited
(`retention_applied`). Run it from a scheduler, for example daily.

### SOP-08: Diagnostics for support

```bash
satsa ops diagnostics --out diag.zip
```

The package contains:
- versions and schema migrations;
- table row counts;
- job states and error types;
- worker heartbeats;
- recent run ids and their fingerprints;
- configuration file hashes;
- disk space and readiness.

It contains no submitted data, keys, tokens, passphrase hashes or usernames. Actors appear only
as hashes valid within that one package. Nothing is uploaded anywhere: review the package, then
hand it over.

---

## 5. Maintenance & Operational Effort

| Activity | Frequency | Estimated Effort | Personnel |
|---|---|---|---|
| Ingesting Entity Batch | Monthly / Quarterly | ~15 minutes per entity | Data Analyst / Admin |
| Assessment Execution | Quarterly | < 5 minutes (automated) | NCIIPC Analyst |
| Examiner Finding Review | Each assessment cycle (e.g. quarterly) | ~2 hours per entity | Supervisory Examiner |
| Rule Calibration & Update | Bi-annually | ~4 hours | Lead Regulatory Specialist |
| Audit Chain Verification | Weekly | < 1 minute (automated CLI) | Security Auditor |

The effort column is a planning estimate of staff time, not a measurement: no examiner session
has been timed (`docs/usability_protocol.md`). Measured machine times are in `docs/benchmarks.md`.
