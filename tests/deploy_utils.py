"""A private, consistent copy of the session's deployment directory, for tests that start real
processes (a server, a worker) or otherwise must not touch the shared `data/`."""

from __future__ import annotations

import shutil
from pathlib import Path

from satsa.store.catalog import CATALOG_FILE, Catalog
from satsa.store.migrations import backup_database
from satsa.store.sqlite import SQLiteStore


def copy_deployment(dest: Path) -> Path:
    """Copy `config/` and `data/` into `dest`. Databases are copied with SQLite's backup API
    (consistent under WAL); published Parquet, templates and secrets are plain files."""
    dest.mkdir(parents=True, exist_ok=True)
    shutil.copytree("config", dest / "config")
    data = dest / "data"
    shutil.copytree("data/parquet", data / "parquet")
    for name in ("templates", "secrets"):
        if Path("data", name).is_dir():
            shutil.copytree(Path("data", name), data / name)
    catalog = Catalog("data")
    try:
        backup_database(catalog.conn, data / CATALOG_FILE)
    finally:
        catalog.close()
    store = SQLiteStore("data/satsa.db")
    try:
        backup_database(store.conn, data / "satsa.db")
    finally:
        store.close()
    return dest
