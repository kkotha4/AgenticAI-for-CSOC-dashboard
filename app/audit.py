"""Append-only audit trail. Every event the agent produces is written as one JSON line."""
import json
import os
import threading
from pathlib import Path

LOG_PATH = Path(os.environ.get("SOC_AUDIT_PATH", Path(__file__).resolve().parent.parent / "audit.jsonl"))
_lock = threading.Lock()


def audit(run_id, event):
    with _lock, LOG_PATH.open("a") as f:
        f.write(json.dumps({"run": run_id, **event}, default=str) + "\n")
