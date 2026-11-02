"""A minimal publish/subscribe message broker - the same idea as Redis pub/sub.

    python -m app.broker            # listens on 127.0.0.1:7070 (BROKER_PORT to change)

Protocol: one JSON object per line over TCP.
    client -> broker   {"op": "sub",   "topic": "run.*"}        wildcards allowed
                       {"op": "unsub", "topic": "run.*"}
                       {"op": "pub",   "topic": "run.ab12", "data": {...}}
    broker -> client   {"topic": "run.ab12", "data": {...}}

Delivery is fire-and-forget (at-most-once): the broker stores nothing, and a subscriber
that is disconnected at publish time misses the message. That is fine here because
messages are only doorbells - "something changed, go look" - and the database stays
the source of truth.
"""
import asyncio
import fnmatch
import json
import logging
import os

log = logging.getLogger("broker")
MAX_BUFFER = 1_000_000  # bytes queued for one subscriber before we drop it (slow-consumer protection)


class Broker:
    def __init__(self):
        self.subs: dict[asyncio.StreamWriter, set[str]] = {}
        self.published = 0
        self.delivered = 0

    async def handle(self, reader, writer):
        self.subs[writer] = set()
        peer = writer.get_extra_info("peername")
        log.info("client connected %s (%d total)", peer, len(self.subs))
        try:
            while line := await reader.readline():
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError:
                    continue
                op, topic = msg.get("op"), msg.get("topic")
                if not isinstance(topic, str):
                    continue
                if op == "sub":
                    self.subs[writer].add(topic)
                elif op == "unsub":
                    self.subs[writer].discard(topic)
                elif op == "pub":
                    self.publish(topic, msg.get("data"))
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            self.subs.pop(writer, None)
            writer.close()
            log.info("client disconnected %s (%d total)", peer, len(self.subs))

    def publish(self, topic, data):
        self.published += 1
        frame = (json.dumps({"topic": topic, "data": data}) + "\n").encode()
        for writer, patterns in list(self.subs.items()):
            if not any(fnmatch.fnmatchcase(topic, p) for p in patterns):
                continue
            if writer.transport.get_write_buffer_size() > MAX_BUFFER:
                log.warning("dropping slow subscriber %s", writer.get_extra_info("peername"))
                writer.close()
                self.subs.pop(writer, None)
                continue
            writer.write(frame)  # fan-out: every matching subscriber gets a copy
            self.delivered += 1


async def report(broker):
    while True:
        await asyncio.sleep(30)
        log.info("stats: %d clients, %d published, %d delivered", len(broker.subs), broker.published, broker.delivered)


async def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [broker] %(message)s", datefmt="%H:%M:%S")
    broker = Broker()
    port = int(os.environ.get("BROKER_PORT", 7070))
    # Set BROKER_BIND only on a private network: there's no authentication, because messages only say "go look".
    host = os.environ.get("BROKER_BIND", "127.0.0.1")
    server = await asyncio.start_server(broker.handle, host, port)
    log.info("listening on %s:%d", host, port)
    asyncio.create_task(report(broker))
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
