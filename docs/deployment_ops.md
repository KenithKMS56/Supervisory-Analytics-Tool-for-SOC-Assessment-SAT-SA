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
When a CSE submits periodic CSV telemetries:
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
- Produces individual entity reports (`CSE-01_supervisory_report.pdf`, etc.), portfolio summary HTML, and CSV extracts (`findings_export.csv`, `review_queue_export.csv`, `metrics_export.csv`).

### SOP-04: Launching Offline Examiner Portal
```bash
satsa serve --host 127.0.0.1 --port 8000
```
- Navigate to `http://127.0.0.1:8000` in local browser.
- Examiner views portfolio heatmap, inspects entity profiles, reviews finding cards, and marks feedback.

---

## 3. Signed Rule-Pack Updates

To update detection thresholds or supervisory criteria without altering code:

### Exporting & Signing a Rule Pack (Regulatory Headquarters)
```bash
satsa rules export \
  --config-dir config \
  --output dist/rule_pack_2026_q2.tar.gz \
  --version 2.0.0 \
  --secret "REGULATOR_PRIVATE_HMAC_KEY"
```

### Importing & Verifying a Rule Pack (Field Examiner Station)
```bash
satsa rules import dist/rule_pack_2026_q2.tar.gz \
  --target-dir config \
  --secret "REGULATOR_PRIVATE_HMAC_KEY"
```
- SAT-SA verifies cryptographic HMAC signature and individual SHA-256 file checksums before writing to disk. Tampered files are rejected immediately and logged to the audit trail.

---

## 4. Cryptographic Audit Verification & Backup

### Audit Log Integrity Check
Supervisors can verify database integrity at any time:
```bash
satsa audit verify --db-path data/satsa.db
```
- Verifies SHA-256 `prev_hash` chaining across all historical records. If any row was edited or removed outside the application, the command fails and reports the exact tampered row ID.

### Backup & Disaster Recovery
To back up the complete supervisory state:
```bash
# 1. Snapshot SQLite database safely using SQLite online backup
sqlite3 data/satsa.db ".backup backup/satsa_$(date +%Y%m%d).db"

# 2. Archive Parquet telemetry directory
tar -czf backup/parquet_$(date +%Y%m%d).tar.gz data/parquet/
```

---

## 5. Maintenance & Operational Effort

| Activity | Frequency | Estimated Effort | Personnel |
|---|---|---|---|
| Ingesting Entity Batch | Monthly / Quarterly | ~15 minutes per entity | Data Analyst / Admin |
| Assessment Execution | Quarterly | < 5 minutes (automated) | Supervisor |
| Examiner Finding Review | Continuous / Quarterly | ~2 hours per entity | Supervisory Examiner |
| Rule Calibration & Update | Bi-annually | ~4 hours | Lead Regulatory Specialist |
| Audit Chain Verification | Weekly | < 1 minute (automated CLI) | Security Auditor |
