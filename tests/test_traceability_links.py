"""docs/ps_traceability.md names only files and tests that exist.

The matrix is one table: requirement, feature, code, test, evidence. Every path in backticks in
the Code, Test and Evidence columns must exist in the repository, and every `file.py::name`
must name a function defined in that file. Every requirement of the problem statement has a
row with code and a test.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
MATRIX = REPO / "docs" / "ps_traceability.md"
EXPECTED_IDS = [f"F{i}" for i in range(1, 18)] + [f"D{i}" for i in range(1, 7)] + ["O1-O6", "S1", "S2"]
PATH_LIKE = re.compile(r"^[\w.\-]+(/[\w.\-]+)*\.(py|md|yaml|yml|toml|lock|html)(::\w+)?$|^[\w.\-]+/[\w.\-/]+$|^Containerfile$")


def _rows() -> dict[str, list[str]]:
    rows: dict[str, list[str]] = {}
    for line in MATRIX.read_text(encoding="utf-8").splitlines():
        if not line.startswith("| ") or line.startswith(("| #", "|---")):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split(" | ")]
        rows[cells[0]] = cells
    return rows


def _references(cell: str) -> list[str]:
    return [token for token in re.findall(r"`([^`]+)`", cell) if PATH_LIKE.match(token)]


def test_every_requirement_has_one_row_with_code_and_a_test():
    rows = _rows()
    assert list(rows) == EXPECTED_IDS
    for rid, cells in rows.items():
        assert len(cells) == 6, f"{rid}: expected 6 columns, got {len(cells)}"
        _, requirement, feature, code, test, evidence = cells
        assert requirement and feature and evidence.startswith("**"), rid
        assert _references(code), f"{rid}: no code path"
        assert _references(test), f"{rid}: no test"
    assert "{{" not in MATRIX.read_text(encoding="utf-8")


def test_every_named_file_and_test_exists():
    missing: list[str] = []
    checked = 0
    for rid, cells in _rows().items():
        for cell in cells[3:]:
            for ref in _references(cell):
                path, _, name = ref.partition("::")
                target = REPO / path
                checked += 1
                if not target.exists():
                    missing.append(f"{rid}: {path}")
                elif name and not re.search(rf"^def {name}\(", target.read_text(encoding="utf-8"), re.MULTILINE):
                    missing.append(f"{rid}: {ref}")
    assert checked > 60
    assert not missing, missing


def test_the_checker_catches_a_missing_file_and_a_missing_test():
    assert _references("`src/satsa/no_such_module.py`, `tests/test_api.py::no_such_test`") == [
        "src/satsa/no_such_module.py",
        "tests/test_api.py::no_such_test",
    ]
    assert not (REPO / "src/satsa/no_such_module.py").exists()
    assert not re.search(r"^def no_such_test\(", (REPO / "tests/test_api.py").read_text(encoding="utf-8"), re.MULTILINE)


def test_every_cited_decision_record_exists():
    decisions = (REPO / "DECISIONS.md").read_text(encoding="utf-8")
    headings = set(re.findall(r"^## (ADR-\d{3}):", decisions, re.MULTILINE))
    cited = set(re.findall(r"ADR-\d{3}", MATRIX.read_text(encoding="utf-8")))
    assert cited, "the matrix cites no decision record"
    assert cited <= headings, sorted(cited - headings)
