"""Summarise examiner usability sessions run under docs/usability_protocol.md.

    python scripts/usability_summary.py docs/usability/usability_results_template.csv

Reads a results file with the columns participant_id, task_id, seconds, completed (yes/no),
errors and notes, and prints per task: participants, completion rate, median time over
completed attempts, and total and median errors. A file with no rows is reported as such.
Standard library only, so it runs on the offline machine as shipped.
"""

from __future__ import annotations

import argparse
import csv
import statistics
import sys
from dataclasses import dataclass
from pathlib import Path

COLUMNS = ["participant_id", "task_id", "seconds", "completed", "errors", "notes"]


@dataclass(frozen=True)
class TaskSummary:
    task_id: str
    participants: int
    completed: int
    median_seconds: float | None  # over completed attempts; None when none completed
    total_errors: int
    median_errors: float


def read_results(path: Path) -> list[dict[str, str]]:
    """The rows of a results file, checked. Raises ValueError naming the first problem."""
    with open(path, encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames is None or [c.strip() for c in reader.fieldnames] != COLUMNS:
            raise ValueError(f"expected the header {','.join(COLUMNS)}, found {reader.fieldnames}")
        rows = list(reader)
    seen: set[tuple[str, str]] = set()
    for number, row in enumerate(rows, start=2):  # line 1 is the header
        where = f"line {number}"
        participant, task = (row["participant_id"] or "").strip(), (row["task_id"] or "").strip()
        if not participant or not task:
            raise ValueError(f"{where}: participant_id and task_id are required")
        if (participant, task) in seen:
            raise ValueError(f"{where}: {participant} has a second row for {task}")
        seen.add((participant, task))
        if (row["completed"] or "").strip().lower() not in ("yes", "no"):
            raise ValueError(f"{where}: completed must be yes or no")
        for column in ("seconds", "errors"):
            value = (row[column] or "").strip()
            if not value.isdigit():
                raise ValueError(f"{where}: {column} must be a whole number of 0 or more, got {value!r}")
    return rows


def summarise(rows: list[dict[str, str]]) -> list[TaskSummary]:
    by_task: dict[str, list[dict[str, str]]] = {}
    for row in rows:
        by_task.setdefault(row["task_id"].strip(), []).append(row)
    summaries = []
    for task_id in sorted(by_task, key=lambda t: (len(t), t)):  # T2 before T10
        attempts = by_task[task_id]
        done = [int(r["seconds"]) for r in attempts if r["completed"].strip().lower() == "yes"]
        errors = [int(r["errors"]) for r in attempts]
        summaries.append(
            TaskSummary(
                task_id=task_id,
                participants=len(attempts),
                completed=len(done),
                median_seconds=float(statistics.median(done)) if done else None,
                total_errors=sum(errors),
                median_errors=float(statistics.median(errors)),
            )
        )
    return summaries


def render(summaries: list[TaskSummary]) -> str:
    if not summaries:
        return "No sessions recorded: the results file has no rows. No usability figure exists yet."
    lines = [
        "| Task | Participants | Completed | Median time (completed) | Errors (total) | Errors (median) |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for s in summaries:
        median = f"{s.median_seconds:.0f} s" if s.median_seconds is not None else "none completed"
        lines.append(
            f"| {s.task_id} | {s.participants} | {s.completed}/{s.participants} | {median} | "
            f"{s.total_errors} | {s.median_errors:g} |"
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("results", type=Path, help="results CSV (see docs/usability_protocol.md)")
    args = parser.parse_args(argv)
    try:
        rows = read_results(args.results)
    except (OSError, ValueError) as exc:
        print(f"error: {args.results}: {exc}", file=sys.stderr)
        return 2
    print(render(summarise(rows)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
