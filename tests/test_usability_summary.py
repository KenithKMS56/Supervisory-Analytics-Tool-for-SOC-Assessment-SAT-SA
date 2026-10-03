"""scripts/usability_summary.py: per-task medians and error counts, and honest about no data."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
TEMPLATE = REPO / "docs" / "usability" / "usability_results_template.csv"
_spec = importlib.util.spec_from_file_location("usability_summary", REPO / "scripts" / "usability_summary.py")
assert _spec and _spec.loader
summary = importlib.util.module_from_spec(_spec)
sys.modules["usability_summary"] = summary  # dataclasses look their module up here
_spec.loader.exec_module(summary)

HEADER = "participant_id,task_id,seconds,completed,errors,notes\n"


def _write(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "results.csv"
    path.write_text(HEADER + body, encoding="utf-8")
    return path


def test_the_shipped_template_is_a_header_with_no_results(capsys):
    assert TEMPLATE.read_text(encoding="utf-8").splitlines() == [HEADER.strip()]  # any line ending
    assert summary.main([str(TEMPLATE)]) == 0
    assert "No sessions recorded" in capsys.readouterr().out


def test_medians_count_completed_attempts_and_errors_count_all(tmp_path, capsys):
    path = _write(
        tmp_path,
        "P01,T1,30,yes,0,\n"
        "P02,T1,50,yes,1,opened the queue first\n"
        "P03,T1,400,no,3,gave up\n"
        "P01,T10,20,yes,0,\n"
        "P02,T2,90,no,2,\n",
    )
    rows = summary.read_results(path)
    by_task = {s.task_id: s for s in summary.summarise(rows)}
    assert [s.task_id for s in summary.summarise(rows)] == ["T1", "T2", "T10"]
    t1 = by_task["T1"]
    assert (t1.participants, t1.completed, t1.median_seconds, t1.total_errors, t1.median_errors) == (3, 2, 40.0, 4, 1.0)
    assert by_task["T2"].median_seconds is None
    assert summary.main([str(path)]) == 0
    out = capsys.readouterr().out
    assert "| T1 | 3 | 2/3 | 40 s | 4 | 1 |" in out
    assert "| T2 | 1 | 0/1 | none completed | 2 | 2 |" in out


@pytest.mark.parametrize(
    "body,problem",
    [
        ("P01,T1,30,maybe,0,\n", "completed must be yes or no"),
        ("P01,T1,-4,yes,0,\n", "seconds must be a whole number"),
        ("P01,T1,30,yes,1.5,\n", "errors must be a whole number"),
        (",T1,30,yes,0,\n", "participant_id and task_id are required"),
        ("P01,T1,30,yes,0,\nP01,T1,35,yes,0,\n", "second row for T1"),
    ],
)
def test_a_malformed_row_is_refused_with_its_line(tmp_path, capsys, body, problem):
    path = _write(tmp_path, body)
    assert summary.main([str(path)]) == 2
    err = capsys.readouterr().err
    assert problem in err and "line " in err


def test_a_file_with_the_wrong_header_is_refused(tmp_path, capsys):
    path = tmp_path / "results.csv"
    path.write_text("participant,task,time\nP01,T1,30\n", encoding="utf-8")
    assert summary.main([str(path)]) == 2
    assert "expected the header" in capsys.readouterr().err
