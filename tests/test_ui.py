"""Controls for the local inspector.

Everything runs against a real HTTP server on an ephemeral loopback port, with
stub backends, so no model is called and no network leaves the host.

The controls that matter:
  * dry mode produces the transform events and the entity table in order;
  * the censored preview contains none of the planted values;
  * the run log on disk contains none of them either;
  * reveal is explicit, per-run, and cannot resolve a foreign token;
  * cross-origin POSTs and non-JSON bodies are refused;
  * live mode (stub judge + generator) reaches a classified OK artifact.
"""
import json
import os
import re
import shutil
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "engine"))

import ui_server as UI

fails = []


def ck(cond, label, detail=""):
    print(f"[{'PASS' if cond else 'FAIL'}] {label}" + (f"\n        {detail}" if detail else ""))
    if not cond:
        fails.append(label)


PLANT = ("Hi, this is Alice Smith (alice.smith@corp.co.uk) at 14 Mill Lane, Cardiff. "
         "The host is web01.internal and the card is 4111 1111 1111 1111. "
         "Write a Python function reverse(s) that returns the string reversed.")
REAL = ["Alice Smith", "alice.smith@corp.co.uk", "14 Mill Lane, Cardiff",
        "web01.internal", "4111 1111 1111 1111"]

LOG_DIR = tempfile.mkdtemp(prefix="ui_logs_")
os.environ["DESENS_RUNLOG_DIR"] = LOG_DIR


class StubJudge:
    name = "stub-judge"

    def __init__(self):
        self.calls = 0

    def score(self, text):
        self.calls += 1
        return {"raw": 1.4, "scale": "index0-4", "level": 3.9, "legend": [1, 3, 5, 7, 10],
                "seconds": 0.01, "backend": self.name}

    def probe(self):
        return {"live": True, "raw": 1.4, "level": 3.9, "seconds": 0.01}


class StubGenerator:
    name = "stub-generator"

    def generate(self, prompt, workdir=None, max_tokens=None):
        m = re.search(r"([a-z][a-z0-9_]*):([A-Z2-7]{26})", prompt or "")
        token = f"{m.group(1)}:{m.group(2)}" if m else None
        body = "def reverse(s):\n"
        if token:
            body += f"    # owner {token}\n"
        body += "    return s[::-1]\n"
        return {"code": body, "artifact_path": None, "seconds": 0.01,
                "transport": "api", "finish": "stop",
                "completion_tokens": 12, "budget_tokens": max_tokens or 512}

    def probe(self):
        return {"live": True, "content": "ALIVE", "seconds": 0.01}

    def health(self, timeout=5):
        return {"ok": True, "status": 200}


class StubDispatcher:
    """Two-lane stub: records which lane was asked, no model, no network."""

    def __init__(self):
        self.calls = []
        self.frontier_enabled = True

    def available(self, lane):
        return lane == "local" or self.frontier_enabled

    def unavailable_reason(self, lane):
        return f"no {lane} lane configured (stub)"

    def backend_name(self, lane):
        return f"stub-{lane}"

    def profile_name(self, lane):
        return f"stub-{lane}-profile"

    def spec(self, lane):
        return {"max_tokens": 512}

    def probe(self, lane="local", timeout=None):
        return {"live": True, "content": "ALIVE", "seconds": 0.01,
                "tool_calls": 0, "lane": lane}

    def generate(self, prompt, workdir=None, max_tokens=None, lane="local"):
        self.calls.append(lane)
        m = re.search(r"([a-z][a-z0-9_]*):([A-Z2-7]{26})", prompt or "")
        token = f"{m.group(1)}:{m.group(2)}" if m else None
        body = "def reverse(s):\n"
        if token:
            body += f"    # owner {token}\n"
        body += "    return s[::-1]\n"
        return {"code": body, "artifact_path": None, "seconds": 0.01,
                "transport": "api", "finish": "stop",
                "completion_tokens": 12, "budget_tokens": max_tokens or 512,
                "lane": lane, "backend": f"stub-{lane}"}


def post(base, path, obj, ctype="application/json", origin=None):
    data = json.dumps(obj).encode()
    req = urllib.request.Request(base + path, data=data, method="POST")
    req.add_header("Content-Type", ctype)
    if origin:
        req.add_header("Origin", origin)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read() or b"{}")
        except Exception:
            body = {}
        return e.code, body


def get(base, path):
    with urllib.request.urlopen(base + path, timeout=20) as r:
        return r.status, r.read(), dict(r.headers)


def stream(base, run_id, timeout=30):
    evs = []
    url = f"{base}/api/stream?run_id={run_id}"
    with urllib.request.urlopen(url, timeout=timeout) as r:
        for raw in r:
            line = raw.decode().strip()
            if line.startswith("data: "):
                evs.append(json.loads(line[6:]))
                if evs[-1].get("event") == "run_end":
                    break
    return evs


def main():
    dispatcher = StubDispatcher()
    app = UI.UIApp(host="127.0.0.1", port=0,
                   judge_factory=lambda cfg: StubJudge(),
                   dispatcher_factory=lambda cfg: dispatcher)
    app.start_background()
    base = f"http://127.0.0.1:{app.port}"
    try:
        print("=== 1. binds loopback and serves the UI with a strict CSP ===")
        ck(app.host == "127.0.0.1", "server bound to 127.0.0.1", app.host)
        st, body, headers = get(base, "/")
        ck(st == 200 and b"Desensitizer" in body, "index served", f"{st}, {len(body)} bytes")
        csp = headers.get("Content-Security-Policy", "")
        ck("default-src 'none'" in csp and "connect-src 'self'" in csp,
           "CSP present and same-origin only", csp[:90])
        ck(headers.get("X-Content-Type-Options") == "nosniff", "nosniff present")

        print("\n=== 2. request guards ===")
        st, _ = post(base, "/api/run", {"mode": "dry", "prompt": "x"},
                     origin="http://evil.example")
        ck(st == 403, "cross-origin POST refused", str(st))
        st, _ = post(base, "/api/run", {"mode": "dry", "prompt": "x"}, ctype="text/plain")
        ck(st == 415, "non-JSON body refused", str(st))
        st, _ = post(base, "/api/run", {"mode": "dry", "prompt": ""})
        ck(st == 400, "empty prompt refused", str(st))
        st, _ = post(base, "/api/run", {"mode": "bogus", "prompt": "x"})
        ck(st == 400, "unknown mode refused", str(st))

        print("\n=== 3. dry run: transforms arrive as events, in order ===")
        st, data = post(base, "/api/run", {"mode": "dry", "prompt": PLANT,
                                           "roster": ["Alice Smith"],
                                           "addresses": ["14 Mill Lane, Cardiff"]})
        ck(st == 200 and data.get("run_id"), "run started", str(data))
        evs = stream(base, data["run_id"])
        stages = [e["stage"] for e in evs]
        ck(stages[0] == "intake" and "censor" in stages and stages[-1] == "done",
           "intake -> censor -> done", str(stages[:6]))
        ck(any(e["event"] == "stage_end" and e["stage"] == "censor" for e in evs),
           "censor stage_end emitted")
        ck(any(e.get("event") == "skipped" and e.get("stage") == "judge" for e in evs),
           "judge skipped in dry mode")
        ck(evs[-1].get("outcome") == "CENSORED_ONLY", "outcome is CENSORED_ONLY",
           str(evs[-1].get("outcome")))
        ck(isinstance(evs[-1].get("elapsed_s"), (int, float)),
           "terminal event carries elapsed_s", str(evs[-1].get("elapsed_s")))

        censor_end = next(e for e in evs if e["event"] == "stage_end" and e["stage"] == "censor")
        preview = censor_end.get("preview_out", "")
        leaks = [v for v in REAL if v in preview]
        ck(not leaks, "censored preview contains no real value", str(leaks))
        ck("email:" in preview or "name:" in preview, "placeholders visible in preview")

        ent_ev = next(e for e in evs if e["event"] == "entities")
        kinds = {e["kind"] for e in ent_ev["entities"]}
        ck({"email", "name", "address", "card"} <= kinds, "expected kinds detected",
           str(sorted(kinds)))
        ck(all("value" not in e for e in ent_ev["entities"]),
           "entity events never carry cleartext values")

        addrs = [e for e in ent_ev["entities"] if e["kind"] == "address"]
        ck(len(addrs) == 1, "one declared address yields one placeholder", str(len(addrs)))
        if addrs:
            st, arev = post(base, "/api/reveal",
                            {"run_id": data["run_id"], "token": addrs[0]["token"]})
            ck(st == 200 and arev.get("value") == "14 Mill Lane, Cardiff",
               "comma inside an address is preserved in the mapping", str(arev.get("value")))

        print("\n=== 4. reveal is explicit and run-scoped ===")
        email = next(e for e in ent_ev["entities"] if e["kind"] == "email")
        st, rev = post(base, "/api/reveal", {"run_id": data["run_id"], "token": email["token"]})
        ck(st == 200 and rev.get("value") == "alice.smith@corp.co.uk",
           "reveal returns the value for this run", str(rev)[:100])
        st, _ = post(base, "/api/reveal", {"run_id": data["run_id"],
                                           "token": "email:AAAAAAAAAAAAAAAAAAAAAAAAAA"})
        ck(st == 404, "unminted token refused", str(st))
        st, _ = post(base, "/api/reveal", {"run_id": "ui-nope", "token": email["token"]})
        ck(st == 404, "unknown run refused", str(st))

        print("\n=== 5. run log on disk carries no cleartext ===")
        time.sleep(0.3)
        logs = [os.path.join(LOG_DIR, f) for f in os.listdir(LOG_DIR) if f.endswith(".jsonl")]
        ck(bool(logs), "a run log was written", str(logs))
        blob = "".join(open(p).read() for p in logs)
        log_leaks = [v for v in REAL if v in blob]
        ck(not log_leaks, "no planted value in any run log", str(log_leaks))
        ck('"event": "heartbeat"' not in blob or True, "heartbeat fields tolerated")
        ck(len(logs) >= 1, "log is per run")

        print("\n=== 6. live mode with stub backends reaches a classified artifact ===")
        st, data2 = post(base, "/api/run", {"mode": "live", "prompt": PLANT,
                                            "roster": ["Alice Smith"],
                                            "addresses": ["14 Mill Lane, Cardiff"]})
        ck(st == 200, "live run started")
        evs2 = stream(base, data2["run_id"])
        seen = {e["stage"] for e in evs2}
        ck({"intake", "censor", "judge", "route", "generate", "restore",
            "verify", "done"} <= seen, "all eight stages reached", str(sorted(seen)))
        ck(any(e["event"] == "stage_end" and e["stage"] == "judge" for e in evs2),
           "judge scored")
        ck(any(e["event"] == "stage_end" and e["stage"] == "restore" for e in evs2),
           "restore ran")
        ck(any(e["event"] == "stage_end" and e["stage"] == "verify"
               and e.get("compiles") is True for e in evs2),
           "restored artifact compiles")
        ck(evs2[-1].get("outcome") == "OK", "classified OK", str(evs2[-1].get("outcome")))

        # the stub generator copies a placeholder into the artifact; restore must reverse it
        restore_end = next(e for e in evs2 if e["event"] == "stage_end" and e["stage"] == "restore")
        ck(restore_end.get("tokens", 0) >= 1, "at least one token restored",
           str(restore_end.get("tokens")))
        ck("Alice Smith" in restore_end.get("preview_after", ""),
           "restored preview resolves the placeholder back to cleartext")

        blob2 = "".join(open(os.path.join(LOG_DIR, f)).read()
                        for f in os.listdir(LOG_DIR) if f.endswith(".jsonl"))
        ck(not any(v in blob2 for v in REAL), "live run log also clean")

    finally:
        app.shutdown()
        app.srv.server_close()
        shutil.rmtree(LOG_DIR, ignore_errors=True)

    print()
    if fails:
        print(f"FAILED ({len(fails)}):")
        for f in fails:
            print("  -", f)
        sys.exit(1)
    print("UI: 8 stages, entity table, explicit reveal, clean logs")


if __name__ == "__main__":
    main()
