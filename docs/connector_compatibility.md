# Connector compatibility matrix

What each source connector has been checked against, and how. "Fixture-verified" means a
sample export, built to the product's documented export or API field names, goes through
ingestion and assessment in the test suite and meets the conformance contract below. It does
**not** mean the mapping has been run against a live installation of the product.

**No connector is production-verified.** That needs an authentic, authorised export from a
real CSE system for each product (matrix row in `docs/release_readiness.md`, status blocked).

| Source | Mapping | Input | Fixture | Status | Tests |
|---|---|---|---|---|---|
| Canonical layout (any SOC) | none: `docs/data_requirements.md` | CSV, TSV, Excel, JSON, ZIP; JSON API | synthetic generator, `data/templates/` | fixture-verified | `test_ingest.py`, `test_columnar_ingest.py`, `test_batch_submission.py` |
| Splunk Enterprise Security | `config/mappings/cse_splunk.yaml` | notable-event export, `incident_review` lookup | `tests/fixtures/connectors/splunk/` (hand-built, 209 notables) | fixture-verified | `test_connectors.py`, `test_connector_conformance.py` |
| ServiceNow Security Incident Response | `config/mappings/cse_servicenow.yaml` | `sn_si_incident`, `sys_audit` table exports | `tests/fixtures/connectors/servicenow/` (hand-built) | fixture-verified | `test_connectors.py`, `test_connector_conformance.py` |
| TheHive 5 | `config/mappings/cse_thehive.yaml` | alerts and cases as JSON (API schema) | `tests/fixtures/connectors/thehive/` (hand-built) | fixture-verified | `test_connectors.py`, `test_connector_conformance.py` |
| Cortex XSIAM | `config/mappings/cse_cortex_xsiam.yaml` | Cases page CSV export (57 columns, Windows-1252) | synthetic export in `tests/test_xsiam_mapping.py`, shaped from one real single-case export that is not committed | fixture-verified | `test_xsiam_mapping.py`, `test_connector_conformance.py` |
| Local REST ticketing API | `config/mappings/cse_api_ticketing.yaml` | JSON over HTTP, loopback or on-premises only (non-loopback refused) | loopback test server in the tests | fixture-verified (not in the file-export conformance suite) | `test_anomaly_scan.py` (staged and ingested; non-loopback endpoint refused) |

Product versions are those whose export or API documentation the field names were taken from.
A site's export can differ (custom fields, renamed statuses, local time zones), so the first
real export of each CSE must be checked against its ingest report.

## Conformance contract

`tests/test_connector_conformance.py` runs every shipped file-export mapping through the same
checks. A new mapping must pass them before it is used:

1. The mapping loads, and the pipeline accepts it (no flat, single-table shortcut).
2. Its fixture ingests into one published batch for the named entity, with no row stored under
   another entity.
3. Every timestamp is stored in UTC (naive datetimes, as the store holds them), whatever the
   source's offset or zone.
4. No personal identifier from the export (analyst names, e-mail addresses) is stored.
5. Every source row is accounted for: stored, or reported as rejected with a reason.
6. The ingest report states which rules the export lets SAT-SA assess and which it does not.

## Reporting a new product

To move a connector to "production-verified", record: the product and version, the export
method, the number of rows, the ingest report (rejected rows and unmapped columns), the rules it
supports, and who authorised the use of the export. Commit only a de-identified sample.
