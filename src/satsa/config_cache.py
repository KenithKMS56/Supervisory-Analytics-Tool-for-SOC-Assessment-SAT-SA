"""Parsed configuration files, kept between requests.

Several pages read the same YAML files (rules, peers) on every request; parsing them is a large
share of a page's time. A file is parsed again whenever its path, size or modification time
changes, so an edit (the Tuning page, a rule-pack import, a hand edit) is seen on the next read.
Each caller gets its own deep copy, so nothing it changes leaks into another request.
"""

from __future__ import annotations

import copy
import threading
from pathlib import Path
from typing import Any

import yaml

_lock = threading.Lock()
_parsed: dict[str, tuple[tuple[int, int], Any]] = {}


def load_yaml(path: Path | str) -> Any:
    """The parsed content of `path` (None for an empty file); FileNotFoundError if it is missing."""
    p = Path(path)
    st = p.stat()
    key, stamp = str(p.resolve()), (st.st_mtime_ns, st.st_size)
    with _lock:
        hit = _parsed.get(key)
    if hit is None or hit[0] != stamp:
        value = yaml.safe_load(p.read_text(encoding="utf-8"))
        with _lock:
            _parsed[key] = hit = (stamp, value)
    return copy.deepcopy(hit[1])
