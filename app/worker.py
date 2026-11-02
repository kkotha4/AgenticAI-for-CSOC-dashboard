"""Worker process: claims jobs from the queue and runs the agent.

    python -m app.worker --id w1 --concurrency 2

Run as many workers as you like, on as many machines as can reach the database.
Each one heartbeats its leases; if it dies, another worker takes over its jobs.
Ctrl+C (SIGINT) or SIGTERM stops claiming new jobs and lets running ones finish.
"""
import argparse
import logging
import os
import signal
import socket
import threading
import time

from . import actions, agent, cache, circuit, config, db, obs, queue, ratelimit
from .bus import bus

log = logging.getLogger("worker")
stopping = threading.Event()


def heartbeat_loop(job_id, worker_id, attempt, done):
    """Keep the lease alive while the agent works (a run can pause for minutes on an approval)."""
    while not done.wait(queue.LEASE_SECONDS / 3):
        if not queue.heartbeat(job_id, worker_id, attempt):
            log.warning("Lost lease on job %s - another worker took it over", job_id)
            return


def process(job, worker_id):
    run_id = job["run_id"]
    log.info("Claimed job %s (run %s, %s, attempt %d)", job["id"], run_id, job["alert_id"], job["attempts"])
    obs.set_run(run_id)  # the run id is the trace id, so its spans join up across processes and attempts
    obs.record_span("queue.wait", job["available_at"], time.time(), attempt=job["attempts"], priority=job["priority"])
    done = threading.Event()
    threading.Thread(target=heartbeat_loop, args=(job["id"], worker_id, job["attempts"], done), daemon=True).start()
    fence = lambda: queue.owns(job["id"], worker_id, job["attempts"])
    try:
        result = agent.execute_job(run_id, job["alert_id"], job["mode"], job["attempts"], fence)
        if not queue.complete(job, worker_id):
            raise agent.LeaseLost(run_id)
        db.finish_run(run_id, "completed" if result.report else "failed", result.report)
        obs.inc("runs_finished", status="completed" if result.report else "failed")
        result.emit("end")
        log.info("Finished run %s: %s", run_id, "completed" if result.report else "failed")
    except agent.LeaseLost:
        log.warning("Run %s moved to another worker; this attempt stopped without recording anything", run_id)
    except circuit.CircuitOpen as e:
        if queue.defer(job, worker_id, e.retry_after + 1, str(e)):
            obs.inc("runs_deferred")
            db.set_run_status(run_id, "queued")
            agent.Run(run_id, job["alert_id"], job["mode"], job["attempts"]).emit("deferred", retry_after=round(e.retry_after), message=str(e))
            log.warning("Run %s deferred: %s", run_id, e)
        else:
            _give_up(job, worker_id, f"Provider unavailable for too long: {e}")
    except agent.AgentFailed as e:
        dead = queue.fail(job, worker_id, str(e))
        obs.inc("job_failures", outcome="dead_letter" if dead else "retry")
        if dead:
            db.finish_run(run_id, "failed")
            obs.inc("runs_finished", status="failed")
            run = agent.Run(run_id, job["alert_id"], job["mode"], job["attempts"])
            run.emit("error", message=f"Gave up after {job['attempts']} attempts (dead-lettered).")
            run.emit("end")
            log.error("Run %s dead-lettered: %s", run_id, e)
        else:
            db.set_run_status(run_id, "queued")
            run = agent.Run(run_id, job["alert_id"], job["mode"], job["attempts"])
            run.emit("retry", attempt=job["attempts"], error=str(e))
            log.warning("Run %s failed (attempt %d), will retry: %s", run_id, job["attempts"], e)
    finally:
        done.set()
        obs.set_run(None)


def _give_up(job, worker_id, reason):
    queue.fail(job, worker_id, reason, force_dead=True)
    _finish_dead(job, reason)


def _finish_dead(job, reason):
    db.finish_run(job["run_id"], "failed")
    obs.inc("runs_finished", status="failed")
    obs.inc("job_failures", outcome="dead_letter")
    run = agent.Run(job["run_id"], job["alert_id"], job["mode"], job["attempts"])
    run.emit("error", message=reason)
    run.emit("end")
    log.error("Run %s dead-lettered: %s", job["run_id"], reason)


def slot_loop(worker_id):
    """One concurrency slot: poll for a job, run it, repeat."""
    with bus.subscribe("jobs") as sub:
        while not stopping.is_set():
            sub.clear()
            for dead_job in queue.reap_poison():
                _finish_dead(dead_job, f"Gave up after {dead_job['attempts']} attempts: workers died each time.")
            job = queue.claim(worker_id)
            if job is None:
                sub.wait()  # idle: sleep until the server publishes "jobs" (or the fallback poll)
                continue
            process(job, worker_id)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--id", default=f"{socket.gethostname()}-{os.getpid()}")
    parser.add_argument("--concurrency", type=int, default=2, help="jobs this process runs at once")
    args = parser.parse_args()
    config.enforce("worker")
    os.environ["WORKER_ID"] = args.id
    obs.configure_logging(args.id)

    db.init()
    queue.init()
    cache.init()
    ratelimit.init()
    obs.init()
    actions.init()
    circuit.init()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: (log.info("Shutting down: finishing current jobs..."), stopping.set()))

    slots = [threading.Thread(target=slot_loop, args=(args.id,), daemon=True) for _ in range(args.concurrency)]
    for t in slots:
        t.start()
    log.info("Worker started with %d slot(s)", args.concurrency)
    while any(t.is_alive() for t in slots):
        time.sleep(0.5)
    log.info("Worker stopped")


if __name__ == "__main__":
    main()
