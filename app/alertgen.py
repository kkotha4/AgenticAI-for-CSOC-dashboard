"""A steady stream of simulated alerts.

    python -m app.alertgen --every 60 --max 100

Alerts wait in the queue for a person to start a run, so this never spends model usage.
When the backlog is full it pauses, instead of burying what's already waiting.
"""
import argparse
import logging
import random
import signal
import threading

from . import alerts, db, obs
from .bus import bus

log = logging.getLogger("alertgen")
stopping = threading.Event()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--every", type=float, default=60, help="average seconds between incidents")
    parser.add_argument("--max", type=int, default=100, help="stop after this many incidents")
    args = parser.parse_args()
    obs.configure_logging("alertgen")
    db.init()
    obs.init()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stopping.set())
    rng = random.Random()
    made = 0
    log.info("Generating an alert about every %gs", args.every)
    while made < args.max and not stopping.wait(rng.uniform(args.every * 0.5, args.every * 1.5)):
        try:
            alert, is_new = alerts.generate()
        except alerts.BacklogFull as e:
            log.warning("Paused: %s", e)
            continue
        made += 1
        if alert and is_new:
            bus.publish("alerts")
            log.info("Raised %s: %s", alert["id"], alert["title"])
    log.info("Stopped after %d incidents", made)


if __name__ == "__main__":
    main()
