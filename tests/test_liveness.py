"""Liveness controls: a server that answers /health but never completes a
request must be refused, not reported as live.

The wedge server below is a faithful reproduction of the measured failure:
GET /health -> 200, POST /v1/chat/completions -> accepted and never answered.
"""
import json
import os
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

import backends as B

fails = []


def ck(cond, label, detail=""):
    print(f"[{'PASS' if cond else 'FAIL'}] {label}" + (f"\n        {detail}" if detail else ""))
    if not cond:
        fails.append(label)


class WedgeHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'{"status":"ok"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        # Accept, read, and never answer. This is the wedge.
        n = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(n)
        time.sleep(30)

    def log_message(self, *a):
        pass


class LiveHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'{"status":"ok"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(n)
        body = json.dumps({"choices": [{"message": {"content": "ALIVE"},
                                        "finish_reason": "stop"}],
                           "usage": {"completion_tokens": 2}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def serve(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    srv.daemon_threads = True
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class FakeJudge:
    name = "fake"

    def probe(self):
        return {"live": True, "raw": 1.2, "level": 3.3, "seconds": 0.01}


print("=== 1. /health 200 while completions hang is a WEDGE, not live ===")
wsrv, wurl = serve(WedgeHandler)
gen = B.ApiGenerator(url=wurl, timeout=1)
health = gen.health(timeout=2)
ck(health.get("ok") is True, "health endpoint answers 200 (the trap)", str(health))
p = gen.probe(timeout=1)
ck(p.get("live") is False, "completion probe fails despite health 200",
   str(p.get("error")))
w = B.wedge_verdict(gen, attempts=2, probe_timeout=1, health_timeout=2)
ck(w["verdict"] == "wedged", "verdict is 'wedged'", str(w["verdict"]))
ck(w["attempts"] == 2, "two consecutive probe failures required", str(w["attempts"]))
ck("recovery" in w, "recovery command recorded")

print("\n=== 2. preflight refuses to run against the wedge ===")
pf = B.preflight(FakeJudge(), gen, attempts=2, probe_timeout=1)
ck(pf["ok"] is False, "preflight refuses", str(pf.get("detail")))
ck(pf["class"] == "GENERATOR_WEDGED", "class is GENERATOR_WEDGED", str(pf["class"]))
wsrv.shutdown()

print("\n=== 3. a working server is live ===")
lsrv, lurl = serve(LiveHandler)
gen2 = B.ApiGenerator(url=lurl, timeout=3)
w2 = B.wedge_verdict(gen2, attempts=2, probe_timeout=2, health_timeout=2)
ck(w2["verdict"] == "live", "verdict is 'live'", str(w2["verdict"]))
ck(w2["attempts"] == 1, "one successful probe is enough", str(w2["attempts"]))
pf2 = B.preflight(FakeJudge(), gen2, attempts=2, probe_timeout=2)
ck(pf2["ok"] is True, "preflight passes")
lsrv.shutdown()

print("\n=== 4. a refused socket is DOWN, distinguishable from wedged ===")
port = free_port()
gen3 = B.ApiGenerator(url=f"http://127.0.0.1:{port}", timeout=1)
w3 = B.wedge_verdict(gen3, attempts=1, probe_timeout=1, health_timeout=1)
ck(w3["verdict"] == "down", "verdict is 'down'", str(w3["verdict"]))
ck(w3["health"].get("ok") is False, "health did not answer", str(w3["health"]))

print("\n=== 5. a probe that raises is not live ===")


class BoomGen(B.Generator):
    name = "boom"

    def probe(self, timeout=None):
        raise RuntimeError("boom")

    def generate(self, prompt, workdir=None, max_tokens=None):
        raise RuntimeError("boom")


w4 = B.wedge_verdict(BoomGen(), attempts=2)
ck(w4["verdict"] == "down", "raising probe -> down (no health url)", str(w4["verdict"]))

print("\n=== 6. judge preflight refuses a dead judge ===")


class DeadJudge:
    name = "dead"

    def probe(self):
        return {"live": False, "error": "ConnectionRefusedError"}


pf3 = B.preflight(DeadJudge(), gen2, attempts=1)
ck(pf3["ok"] is False and pf3["class"] == "JUDGE_UNAVAILABLE",
   "dead judge -> JUDGE_UNAVAILABLE", str(pf3["class"]))

print()
if fails:
    print(f"FAILED ({len(fails)}):")
    for f in fails:
        print("  -", f)
    sys.exit(1)
print("LIVENESS: wedge refused, live accepted, down distinguished")
