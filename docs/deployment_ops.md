# SAT-SA Deployment & Operations Guide

> **Supervisory Notice:** *Indicators requiring supervisory review; not a compliance determination.*

This guide provides operational procedures for deploying, maintaining, updating, and backing up **SAT-SA** in air-gapped supervisory environments.

---

## 1. Installation Procedures

### 1.1 Air-Gapped Python Environment
1. Extract the offline distribution archive:
   ```bash
   tar -xzf dist/satsa_offline_bundle.tar.gz
   cd satsa_offline_bundle
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
Build and deploy using the self-contained production `Containerfile`:
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
```
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
  the chain alone (DECISIONS.md ADR-005). Record a checkpoint off-box at each examination and
  compare against it later:
  ```bash
  satsa audit head                      # note entries + head_hash on paper / a separate system
  satsa audit verify --checkpoint-count <entries> --checkpoint-head <head_hash>
  ```

### Backup & Disaster Recovery
To back up the complete supervisory state:
```bash
# 1. Snapshot SQLite database safely using SQLite online backup
sqlite3 data/satsa.db ".backup backup/satsa_$(date +%Y%m%d).db"

# 2. Archive the Parquet submission directory
tar -czf backup/parquet_$(date +%Y%m%d).tar.gz data/parquet/
```

---

## 5. Maintenance & Operational Effort

| Activity | Frequency | Estimated Effort | Personnel |
|---|---|---|---|
| Ingesting Entity Batch | Monthly / Quarterly | ~15 minutes per entity | Data Analyst / Admin |
| Assessment Execution | Quarterly | < 5 minutes (automated) | NCIIPC Analyst |
| Examiner Finding Review | Each assessment cycle (e.g. quarterly) | ~2 hours per entity | Supervisory Examiner |
| Rule Calibration & Update | Bi-annually | ~4 hours | Lead Regulatory Specialist |
| Audit Chain Verification | Weekly | < 1 minute (automated CLI) | Security Auditor |
