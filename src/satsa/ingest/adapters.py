"""Data source adapters for reading CSV, JSON/NDJSON, SQLite dumps, and local REST APIs."""

import json
import sqlite3
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import polars as pl

# Air-gap guarantee: read_api() will only ever contact these hostnames. Any
# other host raises ValueError before a socket is opened. In a real
# deployment this points at an entity's own on-prem/local REST endpoint
# reachable within the air-gapped network boundary (e.g. a ticketing system
# exposed on the entity's internal network) -- never at the public internet.
ALLOWED_API_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


class SourceAdapter:
    """Reads raw datasets across multiple input file formats."""

    @staticmethod
    def read_csv(file_path: Path | str) -> list[dict[str, Any]]:
        """Read CSV file into list of row dictionaries."""
        path = Path(file_path)
        if not path.exists():
            return []
        df = pl.read_csv(path, infer_schema_length=1000)
        return df.to_dicts()

    @staticmethod
    def read_json(file_path: Path | str) -> list[dict[str, Any]]:
        """Read standard JSON or newline-delimited JSON (NDJSON)."""
        path = Path(file_path)
        if not path.exists():
            return []

        content = path.read_text(encoding="utf-8").strip()
        if not content:
            return []

        # Check if standard JSON array
        if content.startswith("["):
            data = json.loads(content)
            return data if isinstance(data, list) else [data]

        # NDJSON
        records = []
        for line in content.splitlines():
            line_str = line.strip()
            if line_str:
                records.append(json.loads(line_str))
        return records

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
        # actually exists in the export, and quote it with ']' escaped.
        cursor.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (table_name,)
        )
        if cursor.fetchone() is None:
            conn.close()
            return []
        quoted = "[" + table_name.replace("]", "]]") + "]"
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
