"""Drill (docs/drills.md): kill the worker in the middle of a large assessment and start another.

Run from a deployment directory (cwd). Prints every observation with a timestamp."""

import json
import os
import sqlite3
import subprocess
import sys
import time

LEASE = 30
t0 = time.monotonic()


def say(msg: str) -> None:
    print(f"[{time.monotonic() - t0:7.1f}s] {msg}", flush=True)


def q(sql: str, *args):
    conn = sqlite3.connect("data/satsa.db", timeout=30)
    try:
        return conn.execute(sql, args).fetchall()
    finally:
        conn.close()


def worker() -> subprocess.Popen:
    return subprocess.Popen([sys.executable, "-m", "satsa.cli", "worker", "--lease-seconds", str(LEASE),
                             "--poll-seconds", "1"], stdout=open("drill_worker.log", "ab"), stderr=subprocess.STDOUT,
                            env={**os.environ, "PYTHONIOENCODING": "utf-8"})


from satsa.jobs.queue import JobQueue
from satsa.store.sqlite import SQLiteStore

store = SQLiteStore("data/satsa.db")
job = JobQueue(store).enqueue("assessment", {"period": "2026-H1", "reason": "worker-kill drill"}, "drill")
store.close()
job_id = job["job_id"]
runs_before = q("SELECT count(*) FROM runs")[0][0]
say(f"queued {job_id}; runs before: {runs_before}")

w1 = worker()
say(f"worker 1 started (pid {w1.pid})")
while True:
    state, stage = q("SELECT state, stage FROM jobs WHERE job_id = ?", job_id)[0]
    if state == "running" and stage == "assessing":
        break
    time.sleep(0.5)
say("job is running, stage 'assessing'; letting it work for 20 s")
time.sleep(20)
w1.kill()
w1.wait()
killed_at = time.monotonic()
say(f"worker 1 killed (exit {w1.returncode}); job: {q('SELECT state, stage, attempts, lease_until FROM jobs WHERE job_id = ?', job_id)[0]}")
say(f"runs now: {q('SELECT count(*) FROM runs')[0][0]} (a killed assessment must leave none)")

w2 = worker()
say(f"worker 2 started (pid {w2.pid})")
while True:
    state, attempts = q("SELECT state, attempts FROM jobs WHERE job_id = ?", job_id)[0]
    if state in ("succeeded", "failed", "cancelled"):
        break
    time.sleep(1)
done_at = time.monotonic()
w2.terminate()
w2.wait()
result = q("SELECT state, attempts, result_json, error_json FROM jobs WHERE job_id = ?", job_id)[0]
say(f"job finished: state={result[0]} attempts={result[1]}; {done_at - killed_at:.0f} s after the kill")
runs = q("SELECT run_id, status FROM runs ORDER BY created_at")
new = runs[runs_before:]
say(f"runs added: {new}")
say(f"result: {json.loads(result[2]) if result[2] else None}; error: {result[3]}")
assert result[0] == "succeeded" and len(new) == 1 and new[0][1] == "completed", "drill failed"
say("DRILL PASSED: one completed run, no partial or duplicate run")
