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

# Launch container exposing port 8000
podman run -d \
  --name satsa-soc \
  -p 8000:8000 \
  -v ./data:/app/data:Z \
  satsa:latest
```

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
- Computes daily SQL metrics in DuckDB, runs robust statistics and SPC break detection, evaluates rules EG01–EG12 and NS01–NS08, aggregates domain scores via Noisy-OR, updates SQLite state, and logs execution to the audit chain.

### SOP-03: Generating Supervisory Reports
```bash
# Generate all reports (HTML, PDF, and CSV exports)
satsa report --entity all --format all --output-dir reports/2026-Q1
```
- Produces individual entity reports (`CSE-01_supervisory_report.pdf`, etc.), the portfolio summary HTML and A4 portfolio PDF (`SAT-SA_Portfolio_Report_<run_id>.pdf`), and CSV extracts (`findings_export.csv`, `review_queue_export.csv`, `metrics_export.csv`). The web UI's **Export Report** menu downloads the same PDFs as `SAT-SA_Portfolio_Report_<run_id>.pdf`, `SAT-SA_CSE_<entity_id>_Report_<run_id>.pdf` and `SAT-SA_Finding_<finding_id>.pdf`. The report routes accept an optional `?run_id=` to pin an earlier assessment run.

### SOP-04: Launching Offline Examiner Portal
```bash
satsa serve --host 127.0.0.1 --port 8000
```
- Navigate to `http://127.0.0.1:8000` in local browser.
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
