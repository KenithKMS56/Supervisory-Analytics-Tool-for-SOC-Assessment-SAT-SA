# Demo submission bundles (manual upload)

Synthetic data for 10 Critical Sector Entities, January to June 2026. Upload the ZIPs on
the **Upload & Ingest** page; nothing here needs the command line.

| File | Use |
|---|---|
| `staged/1_Jan-Feb_2026.zip`, `2_Mar-Apr_2026.zip`, `3_May-Jun_2026.zip` | Upload in this order. Three assessment runs, so the portfolio trend chart draws. |
| `SATSA_demo_full_submission.zip` | The same data in one upload. One run only, so the trend chart stays empty. |

Use one or the other, not both.

## Before recording

Start from an empty store, otherwise earlier runs appear in the trend chart and the
CSE-06 finding below does not fire. Stop the server, then in File Explorer rename or
delete `data/parquet` and `data/satsa.db`. On the next start the seeded accounts ask for
a new passphrase at first login.

## Steps

1. Sign in as `analyst` (only the analyst role can upload).
2. Upload & Ingest, card 2, leave the target entity on Auto-Detect, choose
   `1_Jan-Feb_2026.zip`, press **Validate, Pseudonymise & Execute Assessment**.
   Each upload takes about 10 seconds and reports the rows ingested and findings flagged.
3. Repeat with bundle 2, then bundle 3.

| After upload | Rules with findings | Findings | Highest risk index |
|---|---|---|---|
| 1 | 15 of 20 | 15 | CSE-08, 19.3 |
| 2 | 18 of 20 | 20 | CSE-08, 29.6 |
| 3 | 20 of 20 | 22 | CSE-02, 41.5 |

## What fires where (after the third upload)

| Entity | Rules |
|---|---|
| CSE-02 Apex Central Bank | EG10, NS01, NS07 |
| CSE-03 Bharat Telecom Infra | EG01, EG03, EG08 |
| CSE-05 National Rail Freight Logistics | EG09, NS01, NS06 |
| CSE-06 Solaris Energy Transmission | EG02 |
| CSE-07 Mercantile Merchant Bank | EG04, EG06, EG11 |
| CSE-08 Metro Fiber Communications | EG07, NS02, NS04 |
| CSE-09 Coastal Hydrocarbon Offshore | EG05, EG12, NS01, NS05 |
| CSE-10 Metro Transit Automated Rail | NS03, NS08 |
| CSE-01, CSE-04 | none (clean entities, for contrast) |

Also populated: one systemic (shared-provider) finding on NS01, the review queue, the
alert explorer, 21 data-quality issues, and the hash-chained audit trail.

## Known limit

All three runs are labelled `2026-Q1` on the trend chart's axis: an upload takes the
period of the latest run. The points themselves are real and differ per upload.

Rebuild the bundles with `python scripts/build_demo_upload_bundles.py`.
