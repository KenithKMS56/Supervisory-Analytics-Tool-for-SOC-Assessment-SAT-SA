"""The durable job queue, stored in the operational database (`jobs`, migration v3).

States: queued -> running -> succeeded | failed | cancelled. A running job holds a *lease*: its
worker renews `lease_until` with every heartbeat. A worker that dies stops renewing; once the
lease has expired the next worker to look either requeues the job (if it has attempts left and
its kind is safe to retry) or fails it with a structured error. Nothing is kept in memory only.

Claiming is one `BEGIN IMMEDIATE` transaction, so two workers can never run the same job. A
job's input fingerprint is unique among queued and running jobs: submitting the same work twice
while the first is pending returns the pending job instead of queuing a duplicate.

Progress is reported as a named *stage* ("validating", "publishing", "assessing"), never as an
invented percentage.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import sqlite3
import uuid
from typing import Any

from satsa.store.sqlite import SQLiteStore

QUEUED, RUNNING, SUCCEEDED, FAILED, CANCELLED = "queued", "running", "succeeded", "failed", "cancelled"
ACTIVE = (QUEUED, RUNNING)
TERMINAL = (SUCCEEDED, FAILED, CANCELLED)
DEFAULT_LEASE_SECONDS = 120


class LeaseLost(RuntimeError):
    """This worker no longer holds the job's lease (it expired and the job moved on)."""


def utc_now() -> _dt.datetime:
    return _dt.datetime.now(_dt.UTC)


def iso(moment: _dt.datetime) -> str:
    return moment.astimezone(_dt.UTC).isoformat(timespec="microseconds")


def new_job_id() -> str:
    return f"JOB-{utc_now().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:10]}"


def fingerprint(kind: str, params: dict[str, Any], extra: str = "") -> str:
    """Identity of a job's input: its kind, parameters and (e.g.) the hash of its input files."""
    body = json.dumps({"kind": kind, "params": params, "extra": extra}, sort_keys=True, default=str)
    return hashlib.sha256(body.encode()).hexdigest()


def _row(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    job = dict(row)
    job["params"] = json.loads(job.pop("params_json") or "{}")
    job["result"] = json.loads(job.pop("result_json")) if job.get("result_json") else None
    job["error"] = json.loads(job.pop("error_json")) if job.get("error_json") else None
    job["cancel_requested"] = bool(job["cancel_requested"])
    return job


class JobQueue:
    def __init__(self, store: SQLiteStore):
        self.store = store
        self.conn = store.conn

    # ---- submitting and reading -------------------------------------------------------------

    def enqueue(
        self,
        kind: str,
        params: dict[str, Any],
        created_by: str,
        *,
        input_fingerprint: str | None = None,
        max_attempts: int = 3,
        job_id: str | None = None,
    ) -> dict[str, Any]:
        """Queue a job, or return the queued/running job with the same input fingerprint."""
        fp = input_fingerprint or fingerprint(kind, params)
        now = iso(utc_now())
        jid = job_id or new_job_id()
        with self.store.transaction():
            existing = self.conn.execute(
                "SELECT * FROM jobs WHERE input_fingerprint = ? AND state IN ('queued', 'running')", (fp,)
            ).fetchone()
            if existing is not None:
                job = _row(existing)
                assert job is not None
                job["deduplicated"] = True
                return job
            self.conn.execute(
                """
                INSERT INTO jobs (job_id, kind, state, stage, params_json, input_fingerprint, created_by,
                                  created_at, updated_at, max_attempts)
                VALUES (?, ?, 'queued', 'waiting for a worker', ?, ?, ?, ?, ?, ?)
                """,
                (jid, kind, json.dumps(params, sort_keys=True, default=str), fp, created_by, now, now, max_attempts),
            )
        job = self.get(jid)
        assert job is not None
        job["deduplicated"] = False
        return job

    def get(self, job_id: str) -> dict[str, Any] | None:
        return _row(self.conn.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone())

    def recent(self, limit: int = 50, states: tuple[str, ...] | None = None) -> list[dict[str, Any]]:
        if states:
            marks = ",".join("?" for _ in states)
            rows = self.conn.execute(
                f"SELECT * FROM jobs WHERE state IN ({marks}) ORDER BY created_at DESC LIMIT ?", (*states, limit)
            ).fetchall()
        else:
            rows = self.conn.execute("SELECT * FROM jobs ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        return [j for j in (_row(r) for r in rows) if j is not None]

    def cancel(self, job_id: str) -> dict[str, Any] | None:
        """Cancel a queued job at once; ask a running one to stop at its next stage boundary."""
        now = iso(utc_now())
        with self.store.transaction():
            self.conn.execute(
                "UPDATE jobs SET state = 'cancelled', stage = 'cancelled before it started', finished_at = ?, "
                "updated_at = ? WHERE job_id = ? AND state = 'queued'",
                (now, now, job_id),
            )
            self.conn.execute(
                "UPDATE jobs SET cancel_requested = 1, updated_at = ? WHERE job_id = ? AND state = 'running'",
                (now, job_id),
            )
        return self.get(job_id)

    # ---- worker side ------------------------------------------------------------------------

    def recover_expired(self, retry_safe: set[str]) -> list[str]:
        """Requeue or fail running jobs whose lease has expired. Returns the job ids touched."""
        now = iso(utc_now())
        touched: list[str] = []
        with self.store.transaction():
            rows = self.conn.execute(
                "SELECT job_id, kind, attempts, max_attempts, lease_owner, cancel_requested FROM jobs "
                "WHERE state = 'running' AND lease_until < ?",
                (now,),
            ).fetchall()
            for r in rows:
                touched.append(r["job_id"])
                if r["cancel_requested"]:
                    self.conn.execute(
                        "UPDATE jobs SET state = 'cancelled', stage = 'cancelled (its worker stopped)', "
                        "finished_at = ?, updated_at = ?, lease_owner = NULL, lease_until = NULL WHERE job_id = ?",
                        (now, now, r["job_id"]),
                    )
                elif r["kind"] in retry_safe and r["attempts"] < r["max_attempts"]:
                    self.conn.execute(
                        "UPDATE jobs SET state = 'queued', stage = ?, updated_at = ?, lease_owner = NULL, "
                        "lease_until = NULL WHERE job_id = ?",
                        (f"requeued: worker {r['lease_owner']} stopped responding during attempt {r['attempts']}",
                         now, r["job_id"]),
                    )
                else:
                    error = {
                        "type": "WorkerLost",
                        "message": (
                            f"worker {r['lease_owner']} stopped responding during attempt {r['attempts']} "
                            f"of {r['max_attempts']}"
                            + ("" if r["kind"] in retry_safe else "; this kind of job is not retried automatically")
                        ),
                    }
                    self.conn.execute(
                        "UPDATE jobs SET state = 'failed', stage = 'failed', error_json = ?, finished_at = ?, "
                        "updated_at = ?, lease_owner = NULL, lease_until = NULL WHERE job_id = ?",
                        (json.dumps(error), now, now, r["job_id"]),
                    )
        return touched

    def claim(
        self, worker_id: str, lease_seconds: int = DEFAULT_LEASE_SECONDS, job_id: str | None = None
    ) -> dict[str, Any] | None:
        """Take the oldest queued job (or the queued job `job_id`) and lease it to `worker_id`.
        None if there is no such queued job."""
        now = utc_now()
        with self.store.transaction():
            row = self.conn.execute(
                "SELECT job_id FROM jobs WHERE state = 'queued' AND (? IS NULL OR job_id = ?) "
                "ORDER BY created_at, job_id LIMIT 1",
                (job_id, job_id),
            ).fetchone()
            if row is None:
                return None
            self.conn.execute(
                """
                UPDATE jobs SET state = 'running', stage = 'starting', attempts = attempts + 1,
                    lease_owner = ?, lease_until = ?, heartbeat_at = ?, updated_at = ?,
                    started_at = COALESCE(started_at, ?)
                WHERE job_id = ? AND state = 'queued'
                """,
                (worker_id, iso(now + _dt.timedelta(seconds=lease_seconds)), iso(now), iso(now), iso(now),
                 row["job_id"]),
            )
        return self.get(row["job_id"])

    def heartbeat(
        self, job_id: str, worker_id: str, stage: str | None = None, lease_seconds: int = DEFAULT_LEASE_SECONDS
    ) -> bool:
        """Renew the lease (and optionally record the stage). Returns whether cancellation was asked.

        Raises LeaseLost if this worker no longer holds the job."""
        now = utc_now()
        with self.store.transaction():
            cur = self.conn.execute(
                "UPDATE jobs SET lease_until = ?, heartbeat_at = ?, updated_at = ?, stage = COALESCE(?, stage) "
                "WHERE job_id = ? AND state = 'running' AND lease_owner = ?",
                (iso(now + _dt.timedelta(seconds=lease_seconds)), iso(now), iso(now), stage, job_id, worker_id),
            )
            if cur.rowcount != 1:
                raise LeaseLost(f"worker {worker_id} no longer holds job {job_id}")
            row = self.conn.execute("SELECT cancel_requested FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
        return bool(row["cancel_requested"])

    def _finish(self, job_id: str, worker_id: str, state: str, stage: str, column: str, value: Any) -> None:
        now = iso(utc_now())
        with self.store.transaction():
            cur = self.conn.execute(
                f"UPDATE jobs SET state = ?, stage = ?, {column} = ?, finished_at = ?, updated_at = ?, "
                "lease_owner = NULL, lease_until = NULL WHERE job_id = ? AND state = 'running' AND lease_owner = ?",
                (state, stage, json.dumps(value, default=str), now, now, job_id, worker_id),
            )
            if cur.rowcount != 1:
                raise LeaseLost(f"worker {worker_id} no longer holds job {job_id}")

    def succeed(self, job_id: str, worker_id: str, result: dict[str, Any]) -> None:
        self._finish(job_id, worker_id, SUCCEEDED, "done", "result_json", result)

    def fail(self, job_id: str, worker_id: str, error: dict[str, Any]) -> None:
        self._finish(job_id, worker_id, FAILED, "failed", "error_json", error)

    def cancelled(self, job_id: str, worker_id: str, note: str) -> None:
        self._finish(job_id, worker_id, CANCELLED, "cancelled", "error_json", {"type": "Cancelled", "message": note})

    def requeue(self, job_id: str, worker_id: str, reason: str) -> None:
        """Give a job back after a transient failure (it keeps its attempt count)."""
        now = iso(utc_now())
        with self.store.transaction():
            self.conn.execute(
                "UPDATE jobs SET state = 'queued', stage = ?, updated_at = ?, lease_owner = NULL, lease_until = NULL "
                "WHERE job_id = ? AND state = 'running' AND lease_owner = ?",
                (f"requeued: {reason}", now, job_id, worker_id),
            )

    # ---- workers ----------------------------------------------------------------------------

    def worker_beat(self, worker_id: str, hostname: str, pid: int, current_job_id: str | None) -> None:
        now = iso(utc_now())
        with self.store.transaction():
            self.conn.execute(
                """
                INSERT INTO worker_heartbeats (worker_id, hostname, pid, started_at, heartbeat_at, current_job_id)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT (worker_id) DO UPDATE SET heartbeat_at = excluded.heartbeat_at,
                    current_job_id = excluded.current_job_id, stopped_at = NULL
                """,
                (worker_id, hostname, pid, now, now, current_job_id),
            )

    def worker_stopped(self, worker_id: str) -> None:
        now = iso(utc_now())
        with self.store.transaction():
            self.conn.execute(
                "UPDATE worker_heartbeats SET stopped_at = ?, current_job_id = NULL WHERE worker_id = ?",
                (now, worker_id),
            )

    def live_workers(self, within_seconds: int = 60) -> list[dict[str, Any]]:
        since = iso(utc_now() - _dt.timedelta(seconds=within_seconds))
        rows = self.conn.execute(
            "SELECT * FROM worker_heartbeats WHERE heartbeat_at >= ? AND stopped_at IS NULL ORDER BY heartbeat_at DESC",
            (since,),
        ).fetchall()
        return [dict(r) for r in rows]
