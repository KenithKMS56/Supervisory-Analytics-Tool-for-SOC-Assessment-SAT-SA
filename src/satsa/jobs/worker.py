"""The local job worker (`satsa worker`): claims queued jobs one at a time and runs them.

One worker is the deployment's single analytical writer: imports and assessments run there,
not inside web requests, so readers keep reading completed runs while it publishes. The
concurrency bound is the number of worker processes, which is one by default (entrypoint.py
starts exactly one). Two workers are still safe, because claims are atomic and publication
goes through the catalog's writer lock, but they would only queue behind that lock.

While a job runs, a heartbeat thread renews its lease on its own database connection. A
worker that is killed stops renewing, and the next worker requeues or fails the job
(JobQueue.recover_expired). Cancellation is checked at every stage boundary. The work between
two stages (e.g. one assessment, which publishes in a single transaction) is never interrupted
half-way.
"""

from __future__ import annotations

import logging
import os
import shutil
import socket
import sqlite3
import threading
import time
import traceback
import uuid
from pathlib import Path
from typing import Any

from satsa.jobs.handlers import HANDLERS, RETRY_SAFE, JobFailed
from satsa.jobs.queue import DEFAULT_LEASE_SECONDS, JobQueue, LeaseLost
from satsa.store.sqlite import SQLiteStore

logger = logging.getLogger(__name__)

MIN_FREE_DISK_BYTES = int(os.environ.get("SATSA_MIN_FREE_DISK_MB", "512")) * 1024 * 1024

# Memory a job is expected to need, from the peaks measured in docs/benchmarks.md: an
# assessment held about 180 bytes per stored row on top of ~130 MiB (0.5 to 21 million rows), an
# import 3 to 4 times its input. The estimates round both up; SATSA_MEMORY_PREFLIGHT=off skips
# the check (for a host whose free-memory figure is misleading, e.g. a container without limits).
MEMORY_BASE_BYTES = 256 * 1024 * 1024
ASSESS_BYTES_PER_ROW = 200
IMPORT_BYTES_PER_INPUT_BYTE = 4


def available_memory_bytes() -> int | None:
    """Physical memory available to new allocations now, or None where it cannot be read."""
    if os.name == "nt":
        import ctypes

        class Status(ctypes.Structure):
            _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong)] + [
                (name, ctypes.c_ulonglong)
                for name in ("ullTotalPhys", "ullAvailPhys", "ullTotalPageFile", "ullAvailPageFile",
                             "ullTotalVirtual", "ullAvailVirtual", "ullAvailExtendedVirtual")
            ]

        status = Status()
        status.dwLength = ctypes.sizeof(Status)
        if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):  # type: ignore[attr-defined]
            return None
        return int(status.ullAvailPhys)
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemAvailable:"):
                return int(line.split()[1]) * 1024
    except OSError:
        pass
    try:
        return int(os.sysconf("SC_AVPHYS_PAGES") * os.sysconf("SC_PAGE_SIZE"))  # type: ignore[attr-defined,unused-ignore]
    except (ValueError, OSError, AttributeError):
        return None


class JobCancelled(Exception):
    pass


class InsufficientDisk(JobFailed):
    pass


class InsufficientMemory(JobFailed):
    pass


class JobContext:
    """What a handler may use: the job, the stores' locations and stage reporting."""

    def __init__(self, worker: Worker, job: dict[str, Any], store: SQLiteStore):
        self.worker = worker
        self.job = job
        self.store = store
        self.data_dir = worker.data_dir
        self.mappings_dir = worker.mappings_dir
        self.lease_lost = threading.Event()

    def stage(self, name: str) -> None:
        """Record the stage the job has reached; stop here if cancellation was asked."""
        if self.lease_lost.is_set():
            raise LeaseLost(f"job {self.job['job_id']} lost its lease")
        if self.worker.queue.heartbeat(self.job["job_id"], self.worker.worker_id, stage=name,
                                       lease_seconds=self.worker.lease_seconds):
            raise JobCancelled(f"cancelled before stage '{name}'")

    def preflight_memory(self, needed: int, what: str) -> None:
        """Refuse to start a job the host cannot hold in memory now (estimate: see above), rather
        than let it fail part-way or push the web portals into swapping."""
        if os.environ.get("SATSA_MEMORY_PREFLIGHT", "on").strip().lower() in ("off", "0", "false", "no"):
            return
        available = available_memory_bytes()
        if available is None or available >= needed:
            return
        raise InsufficientMemory(
            f"only {available // (1024 * 1024)} MiB of memory is free; {what} needs about "
            f"{needed // (1024 * 1024)} MiB. Free memory (or add it) and retry; the job was not started",
            available_bytes=available, needed_bytes=needed,
        )

    def preflight_disk(self, input_bytes: int) -> None:
        """Refuse to start when the data volume could fill up (needs 3x the input plus a margin)."""
        free = shutil.disk_usage(self.data_dir).free
        needed = 3 * input_bytes + MIN_FREE_DISK_BYTES
        if free < needed:
            raise InsufficientDisk(
                f"only {free // (1024 * 1024)} MiB free on the data volume; this import needs about "
                f"{needed // (1024 * 1024)} MiB (3x its {input_bytes // (1024 * 1024)} MiB input plus "
                f"a {MIN_FREE_DISK_BYTES // (1024 * 1024)} MiB margin)",
                free_bytes=free, needed_bytes=needed,
            )


class Worker:
    def __init__(
        self,
        db_path: Path | str = "data/satsa.db",
        data_dir: Path | str = "data",
        mappings_dir: Path | str = "config/mappings",
        worker_id: str | None = None,
        lease_seconds: int = DEFAULT_LEASE_SECONDS,
    ):
        self.db_path = Path(db_path)
        self.data_dir = Path(data_dir)
        self.mappings_dir = Path(mappings_dir)
        self.worker_id = worker_id or f"{socket.gethostname()}-{os.getpid()}-{uuid.uuid4().hex[:6]}"
        self.lease_seconds = lease_seconds
        self.store = SQLiteStore(self.db_path)
        self.queue = JobQueue(self.store)

    def close(self) -> None:
        self.queue.worker_stopped(self.worker_id)
        self.store.close()

    def _beat(self, current_job_id: str | None) -> None:
        self.queue.worker_beat(self.worker_id, socket.gethostname(), os.getpid(), current_job_id)

    def _heartbeat_loop(self, ctx: JobContext, stop: threading.Event) -> None:
        """Renew the lease on a separate connection until the job ends."""
        store = SQLiteStore(self.db_path)
        queue = JobQueue(store)
        try:
            while not stop.wait(max(1.0, self.lease_seconds / 4)):
                try:
                    queue.heartbeat(ctx.job["job_id"], self.worker_id, lease_seconds=self.lease_seconds)
                    queue.worker_beat(self.worker_id, socket.gethostname(), os.getpid(), ctx.job["job_id"])
                except LeaseLost:
                    ctx.lease_lost.set()
                    return
                except sqlite3.Error:
                    logger.warning("heartbeat for %s failed; retrying", ctx.job["job_id"], exc_info=True)
        finally:
            store.close()

    def run_once(self, job_id: str | None = None) -> dict[str, Any] | None:
        """Recover expired leases, then claim and run one job (the oldest, or `job_id` if it is
        queued). Returns the finished job, or None."""
        self.queue.recover_expired(RETRY_SAFE)
        self._beat(None)
        job = self.queue.claim(self.worker_id, self.lease_seconds, job_id=job_id)
        if job is None:
            return None
        handler = HANDLERS.get(job["kind"])
        ctx = JobContext(self, job, self.store)
        stop = threading.Event()
        beat = threading.Thread(target=self._heartbeat_loop, args=(ctx, stop), daemon=True)
        beat.start()
        try:
            if handler is None:
                raise JobFailed(f"no handler for job kind {job['kind']!r}")
            result = handler(ctx)
            stop.set()
            beat.join()
            self.queue.succeed(job["job_id"], self.worker_id, result)
        except JobCancelled as exc:
            stop.set()
            beat.join()
            self.queue.cancelled(job["job_id"], self.worker_id, str(exc))
        except LeaseLost:
            stop.set()
            beat.join()
            logger.warning("job %s: lease lost; another worker will recover it", job["job_id"])
        except JobFailed as exc:
            stop.set()
            beat.join()
            self.queue.fail(job["job_id"], self.worker_id,
                            {"type": type(exc).__name__, "message": str(exc), **exc.details})
        except sqlite3.OperationalError as exc:
            # Transient (e.g. the database was locked for longer than busy_timeout): try again later.
            stop.set()
            beat.join()
            if job["kind"] in RETRY_SAFE and job["attempts"] < job["max_attempts"]:
                self.queue.requeue(job["job_id"], self.worker_id, f"transient database error: {exc}")
            else:
                self.queue.fail(job["job_id"], self.worker_id, {"type": "OperationalError", "message": str(exc)})
        except Exception as exc:  # recorded on the job; the worker keeps serving
            stop.set()
            beat.join()
            logger.exception("job %s failed", job["job_id"])
            self.queue.fail(job["job_id"], self.worker_id, {
                "type": type(exc).__name__,
                "message": str(exc)[:2000],
                "stage": (self.queue.get(job["job_id"]) or {}).get("stage"),
                "trace_tail": traceback.format_exc(limit=3)[-1500:],
            })
        return self.queue.get(job["job_id"])

    def run_until_idle(self, max_jobs: int = 100) -> list[dict[str, Any]]:
        """Run jobs until none is queued (used by tests and `satsa worker --once`)."""
        done: list[dict[str, Any]] = []
        while len(done) < max_jobs:
            job = self.run_once()
            if job is None:
                break
            done.append(job)
        return done

    def run_forever(self, stop: threading.Event, poll_seconds: float = 2.0) -> None:
        logger.info("worker %s started", self.worker_id)
        while not stop.is_set():
            try:
                if self.run_once() is None:
                    stop.wait(poll_seconds)
            except sqlite3.Error:
                logger.exception("worker loop: database error; retrying")
                stop.wait(poll_seconds)
        logger.info("worker %s stopped", self.worker_id)


def run_pending_jobs(db_path: Path | str = "data/satsa.db", data_dir: Path | str = "data") -> list[dict[str, Any]]:
    """Run every queued job now, in this process (tests, CLI and single-process tools)."""
    worker = Worker(db_path, data_dir)
    try:
        return worker.run_until_idle()
    finally:
        worker.close()


def run_jobs(*job_ids: str, db_path: Path | str = "data/satsa.db", data_dir: Path | str = "data") -> list[dict[str, Any]]:
    """Run exactly these queued jobs now, in this process (tests: never someone else's job)."""
    worker = Worker(db_path, data_dir)
    try:
        return [job for jid in job_ids if (job := worker.run_once(jid)) is not None]
    finally:
        worker.close()


def wait_for(job_id: str, db_path: Path | str = "data/satsa.db", timeout: float = 600.0) -> dict[str, Any]:
    """Block until a job is finished (for callers that need the result and a worker runs it)."""
    store = SQLiteStore(db_path)
    try:
        queue = JobQueue(store)
        deadline = time.monotonic() + timeout
        while True:
            job = queue.get(job_id)
            if job is None or job["state"] in ("succeeded", "failed", "cancelled"):
                return job or {}
            if time.monotonic() > deadline:
                return job
            time.sleep(0.5)
    finally:
        store.close()
