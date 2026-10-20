# Baseline before the product-brief work (docs/product_brief.md §15.1)

Recorded on 2026-10-16 against commit `47f10c9`, the reference commit named in the brief.
The working tree was clean apart from the new files of this branch. Machine: Windows 11 Home
(10.0.26300), Python 3.13, dependencies from `uv.lock` (`uv sync --frozen`).

## Commands and results

| Command | Result |
|---|---|
| `uv run coverage run --branch --source=src/satsa -m pytest tests -q -p no:cacheprovider` | **1222 passed, 33 skipped**, 0 failed, in 1075.9 s (17 min 56 s) |
| `uv run coverage report` | **84 %** line+branch coverage of `src/satsa` (11253 statements, 1657 missed) |
| `uv run ruff check` | All checks passed |
| `uv run mypy src` | No errors in the files at `47f10c9`. (The 7 errors in this run came from three uncommitted files of this branch and were fixed before integration.) |

`pytest-cov` is not a dependency, so `pytest --cov` is unavailable. Coverage is measured with
`coverage run`, as CI does.

## Defect reproduction (brief §2, B01–B06)

`tests/test_brief_defects.py` has one test per defect, or two where the brief names two
behaviours. Each asserts the result the brief requires. All 9 failed at `47f10c9`. This is the
recorded output of `uv run pytest tests/test_brief_defects.py`:

| Test | Failure at `47f10c9` |
|---|---|
| B01 asset-only entity is insufficient evidence | `no such column: classification_status`: no coverage or classification existed, and the entity was scored 0.0 / "Low Supervisory Concern" |
| B01 missing escalation table is not a clean result | `no such table: rule_results`: no per-rule result states existed |
| B02 JSON submission applies privacy processing | the analyst e-mail `alice@example.org` was stored verbatim in Parquet |
| B02 malformed timestamps are rejected | HTTP 200 `"status":"success"`; the value `31/31/2026 99:99` was stored |
| B03 row entity must match batch entity | HTTP 200; the row was stored under the other entity |
| B03 alternate period labels cannot evade the duplicate rule | `2026-02` accepted after `2026-Q1` for the same entity (HTTP 200) |
| B04 Q1 and Q2 read their own period | the entity scores of Q1 and Q2 were identical: the period was only a label |
| B05 an updated alert replaces its earlier version | 2 rows for one alert: both versions were counted |
| B06 a scoring change changes the config identity | `config_hash` stayed `d647f16de51d3b49`: only `rules.yaml` was hashed |

B07 (offline `/docs`) and B08 (layout overflow) need a browser. They are reproduced in Phase 2
and Phase 4 with Playwright.

## Source-review findings confirmed at baseline (not in the brief's register)

- `store/duckdb.py` (write path): on any error while reading or merging an existing Parquet
  file, it overwrote the file with only the new rows. Earlier submissions were lost silently.
- `SQLiteStore.seed_default_admin` re-promotes and re-activates `admin` on every start.
- KPI case mismatch: the web form writes `mttr`/`all`, while EG10 reads `MTTR` with
  `high`/`critical`.
- The findings CSV export covers all runs while the UI shows the latest. The HTML report
  always uses the latest run.
