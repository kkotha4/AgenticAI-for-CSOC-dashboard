"""Client for the pub/sub broker, shared by the web server and the workers.

Usage pattern everywhere in this app ("doorbell + fallback poll"):

    sub = bus.subscribe("approval.ab12")
    while not done:
        sub.clear()                    # 1. reset the doorbell BEFORE looking
        check_the_database()           # 2. the database is the source of truth
        sub.wait(FALLBACK_POLL)        # 3. sleep until a ring, or the fallback timeout

Clearing before checking means a ring that arrives during the check is not lost.
If the broker is down, publish() is a no-op and wait() simply times out, so the
system keeps working - it just falls back to slow polling until the broker returns.
"""
import fnmatch
import json
import logging
import os
import socket
import threading
import time

log = logging.getLogger("bus")
HOST = os.environ.get("BROKER_HOST", "127.0.0.1")
PORT = int(os.environ.get("BROKER_PORT", 7070))
FALLBACK_POLL = 5.0  # seconds between database checks when no notification arrives


class Subscription:
    def __init__(self, bus, topic):
        self._bus, self.topic = bus, topic
        self._event = threading.Event()

    def clear(self):
        self._event.clear()

    def wait(self, timeout=FALLBACK_POLL):
        """Returns True if notified, False on timeout."""
        return self._event.wait(timeout)

    def close(self):
        self._bus._remove(self)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class Bus:
    def __init__(self):
        self._lock = threading.Lock()
        self._send_lock = threading.Lock()  # one writer at a time, or two messages could interleave on the wire
        self._first_attempt = threading.Event()  # set once the first connection attempt has finished
        self._sock = None
        self._subs: dict[str, list[Subscription]] = {}  # topic -> local subscriptions
        self._started = False

    # --- public API ---------------------------------------------------------

    def publish(self, topic, data=None):
        """Best effort. A lost notification only costs latency, never correctness."""
        self._send({"op": "pub", "topic": topic, "data": data})

    def subscribe(self, topic):
        sub = Subscription(self, topic)
        with self._lock:
            first = topic not in self._subs
            self._subs.setdefault(topic, []).append(sub)
        self._ensure_started()
        if first:
            self._send({"op": "sub", "topic": topic})
        return sub

    # --- internals ----------------------------------------------------------

    def _remove(self, sub):
        with self._lock:
            subs = self._subs.get(sub.topic, [])
            if sub in subs:
                subs.remove(sub)
            last = not subs
            if last:
                self._subs.pop(sub.topic, None)
        if last:
            self._send({"op": "unsub", "topic": sub.topic})

    def _ensure_started(self):
        with self._lock:
            if self._started:
                return
            self._started = True
        threading.Thread(target=self._reader, daemon=True, name="bus-reader").start()

    def _send(self, msg):
        self._ensure_started()
        line = (json.dumps(msg) + "\n").encode()
        self._first_attempt.wait(1.0)  # right after startup, give the connection a moment to open
        with self._lock:
            sock = self._sock
        if sock is None:
            return  # broker unavailable: degrade to polling
        try:
            with self._send_lock:
                sock.sendall(line)
        except OSError:
            self._drop(sock)

    def _drop(self, sock):
        with self._lock:
            if self._sock is sock:
                self._sock = None
        try:
            sock.close()
        except OSError:
            pass

    def _reader(self):
        """Background thread: (re)connect, resubscribe, and ring doorbells for incoming messages."""
        backoff = 0.5
        while True:
            try:
                sock = socket.create_connection((HOST, PORT), timeout=2)
                sock.settimeout(None)
            except OSError:
                self._first_attempt.set()
                time.sleep(backoff)
                backoff = min(backoff * 2, 10)  # reconnect with exponential backoff
                continue
            backoff = 0.5
            with self._lock:
                self._sock = sock
                topics = list(self._subs)
            self._first_attempt.set()
            log.info("connected to broker %s:%d", HOST, PORT)
            for topic in topics:  # the broker forgot us when we disconnected
                self._send({"op": "sub", "topic": topic})
            self._ring_all()      # we may have missed messages while disconnected
            try:
                for line in sock.makefile("rb"):
                    msg = json.loads(line)
                    with self._lock:
                        targets = [s for t, subs in self._subs.items()
                                   if _match(t, msg["topic"]) for s in subs]
                    for sub in targets:
                        sub._event.set()
            except (OSError, ValueError):
                pass
            log.warning("lost connection to broker - falling back to polling")
            self._drop(sock)

    def _ring_all(self):
        with self._lock:
            subs = [s for subs in self._subs.values() for s in subs]
        for sub in subs:
            sub._event.set()


def _match(pattern, topic):
    return fnmatch.fnmatchcase(topic, pattern)


bus = Bus()  # one connection per process
