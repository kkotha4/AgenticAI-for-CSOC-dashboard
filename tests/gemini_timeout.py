"""Real Google SDK against a local server that accepts requests and never answers.

    .venv/bin/python tests/gemini_timeout.py
"""
import os, socket, sys, threading, time
srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(16)
conns = []
threading.Thread(target=lambda: [conns.append(srv.accept()) for _ in iter(int, 1)], daemon=True).start()
os.environ.update(GEMINI_API_KEY="fake", GEMINI_TIMEOUT_SECONDS="1", GOOGLE_GEMINI_BASE_URL=f"http://127.0.0.1:{srv.getsockname()[1]}")
sys.path.insert(0, ".")
from app import llm
p = llm.GeminiProvider("sys", [{"name": "t", "description": "d", "input_schema": {"type": "object", "properties": {}, "additionalProperties": False}}], "hi")
t = time.time()
try:
    p.next_turn(); print("FAIL no exception"); sys.exit(1)
except llm.TransientError as e:
    print(f"PASS stalled request ended in {time.time()-t:.1f}s after {len(conns)} connection(s): {e}")
