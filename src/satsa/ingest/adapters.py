"""Data source adapters for reading CSV, JSON/NDJSON, SQLite dumps, and local REST APIs."""

import json
import sqlite3
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import polars as pl

from satsa.ingest.sanitise import read_delimited, read_excel, read_json_records

# Air-gap guarantee: read_api() will only ever contact these hostnames. Any
# other host raises ValueError before a socket is opened. In a real
# deployment this points at an entity's own on-prem/local REST endpoint
# reachable within the air-gapped network boundary (e.g. a ticketing system
# exposed on the entity's internal network) -- never at the public internet.
ALLOWED_API_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


class SourceAdapter:
    """Reads raw datasets across multiple input file formats."""

    @staticmethod
    def read_csv_frame(file_path: Path | str) -> pl.DataFrame:
        """Read a CSV/TSV file as a columnar frame (an empty frame if the file does not exist).

        Any common encoding and separator is accepted; see `sanitise.read_delimited`.
        """
        return read_delimited(file_path).frame

    @staticmethod
    def read_excel_frame(file_path: Path | str) -> pl.DataFrame:
        """Read the first sheet of an .xlsx workbook as a columnar frame."""
        return read_excel(file_path).frame

    @staticmethod
    def read_csv(file_path: Path | str) -> list[dict[str, Any]]:
        """Read CSV file into list of row dictionaries."""
        return SourceAdapter.read_csv_frame(file_path).to_dicts()

    @staticmethod
    def read_json(file_path: Path | str) -> list[dict[str, Any]]:
        """Read a JSON array, object, `{"data": [...]}` envelope or newline-delimited JSON."""
        return read_json_records(file_path)

    @staticmethod
    def list_sqlite_tables(file_path: Path | str) -> list[str]:
        """User tables of an SQLite database export, in name order (SQLite's own are skipped).

        The file is opened read-only, so reading a submission can never modify it.
        """
        uri = Path(file_path).resolve().as_uri() + "?mode=ro"
        conn = sqlite3.connect(uri, uri=True)
        try:
            rows = conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            ).fetchall()
        finally:
            conn.close()
        return [r[0] for r in rows]

    @staticmethod
    def read_sqlite(file_path: Path | str, table_name: str) -> list[dict[str, Any]]:
        """Read table from an SQLite database export."""
        path = Path(file_path)
        if not path.exists():
            return []

        conn = sqlite3.connect(str(path))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        # Identifiers can't be bound as parameters, so only read a table that
        # actually exists in the export, quoted as an identifier ('"' doubled).
        cursor.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (table_name,)
        )
        if cursor.fetchone() is None:
            conn.close()
            return []
        quoted = '"' + table_name.replace('"', '""') + '"'
        cursor.execute(f"SELECT * FROM {quoted}")
        rows = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return rows

    @staticmethod
    def read_api(endpoint_config: dict[str, Any]) -> list[dict[str, Any]]:
        """Read records from a local REST API endpoint (PS requirement #2: APIs alongside
        CSV/JSON/DB exports).

        `endpoint_config` keys:
          - `fixture_path` (str | Path, optional): read a local JSON file that simulates
            the API's response body. Use this in tests and offline demos -- it exercises
            the exact same parsing/records_key logic as a live call, with zero network I/O.
          - `url` (str, optional): a live local REST endpoint to GET. MUST resolve to
            127.0.0.1/localhost/::1 -- any other host raises ValueError before any socket
            is opened, so this can never become an accidental air-gap violation. In a real
            deployment this would point at an entity's own on-prem/local API reachable
            within the air-gapped network boundary, never at the public internet.
          - `headers` (dict, optional): extra HTTP headers (e.g. a local API token) for the
            `url` path.
          - `records_key` (str, optional): if the JSON response is an object wrapping the
            record list (e.g. `{"tickets": [...]}`), the key holding that list. If omitted,
            the response body itself must already be a JSON list.
          - `timeout_seconds` (float, optional, default 5.0): request timeout for the
            `url` path.

        Exactly one of `fixture_path` or `url` must be provided.
        """
        fixture_path = endpoint_config.get("fixture_path")
        url = endpoint_config.get("url")
        records_key = endpoint_config.get("records_key")

        if fixture_path and url:
            raise ValueError("read_api: provide only one of fixture_path or url, not both.")

        if fixture_path:
            payload = json.loads(Path(fixture_path).read_text(encoding="utf-8"))
        elif url:
            parsed = urlparse(url)
            if parsed.hostname not in ALLOWED_API_HOSTS:
                raise ValueError(
                    f"read_api: refusing to contact non-loopback host '{parsed.hostname}'. "
                    f"Only {sorted(ALLOWED_API_HOSTS)} are permitted, consistent with SAT-SA's "
                    "air-gapped operation -- point this at a local/on-prem endpoint."
                )
            headers = endpoint_config.get("headers", {})
            timeout = float(endpoint_config.get("timeout_seconds", 5.0))
            req = urllib.request.Request(url, headers=headers, method="GET")
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    payload = json.loads(resp.read().decode("utf-8"))
            except urllib.error.URLError as e:
                raise ValueError(f"read_api: failed to reach local endpoint '{url}': {e}") from e
        else:
            raise ValueError("read_api: must provide either fixture_path or url.")

        if records_key is not None:
            payload = payload.get(records_key, []) if isinstance(payload, dict) else []

        if isinstance(payload, dict):
            payload = [payload]
        if not isinstance(payload, list):
            return []
        return payload


def stage_api_submission(config_path: Path | str, out_dir: Path | str) -> dict[str, int]:
    """Fetch a submission from local REST endpoints and stage it as JSON files for ingest.

    `config_path` is a YAML file:

        endpoints:
          alert: {url: "http://127.0.0.1:9000/api/alerts", records_key: items}
          case: {url: "http://127.0.0.1:9000/api/cases"}
          escalation: {fixture_path: "tests/fixtures/escalations.json"}

    Each key names the table (a canonical name or any name the ingest pipeline recognises) and
    each value is a `SourceAdapter.read_api` config, so the loopback-only rule applies to every
    endpoint. Every table is written to `<out_dir>/<key>.json`; staging the records as files means
    an API submission goes through exactly the checks a file upload does (data quality,
    pseudonymisation, redaction, submission manifest). An endpoint that returns no records still
    writes an empty file, declaring the table submitted and empty. Returns key -> record count.
    """
    import yaml

    cfg = yaml.safe_load(Path(config_path).read_text(encoding="utf-8")) or {}
    endpoints = cfg.get("endpoints") or {}
    if not isinstance(endpoints, dict) or not endpoints:
        raise ValueError(f"{config_path}: no 'endpoints' mapping of table name to endpoint config.")
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    counts: dict[str, int] = {}
    for key, endpoint in endpoints.items():
        name = str(key)
        if not name.replace("_", "").isalnum():
            raise ValueError(f"{config_path}: table name '{name}' must be letters, digits and underscores.")
        if not isinstance(endpoint, dict):
            raise TypeError(f"{config_path}: endpoint '{name}' must be a mapping.")
        records = SourceAdapter.read_api(endpoint)
        (out / f"{name}.json").write_text(json.dumps(records, default=str), encoding="utf-8")
        counts[name] = len(records)
    return counts
