"""Local prompt-flow inspector for the desensitizer pipeline.

A browser UI over the REAL pipeline, not a mock:

    prompt -> censor -> judge -> route -> generate -> restore -> verify

What the UI is for
  1. show each transform as it happens, with timings, so a "slow" run is
     visibly slow rather than apparently hung;
  2. show every detected identifier as a placeholder, with an explicit
     local-only reveal for the operator;
  3. state plainly what leaves the machine, what never does, and what is
     written to disk.

Data handling, enforced here
  * binds 127.0.0.1 by default and refuses a non-loopback host without
    --allow-remote;
  * POST requires application/json and a matching Origin when one is sent
    (a cross-site page cannot forge either without a preflight);
  * the raw prompt is held in browser memory and, during a run, process memory.
    It is never written to the run log or the audit file;
  * the run log records stage, counts, timings and classes only;
  * the alias pivot table stays in process memory; reveal is an explicit
    request against one run's token and never touches disk;
  * temp profile/artifacts are deleted when the run finishes.

Three modes, because a full generation takes minutes:
    dry    censor only, no model call, instant
    judge  censor + OpenJev score + route, ~25 s
    live   full artifact path (judge + generator + gate + restore + compile)

Run:
    python3 ui_server.py                 # http://127.0.0.1:8788
    python3 ui_server.py --port 9000 --open
"""
import argparse
import json
import os
import py_compile
import re
import shutil
import sys
import tempfile
import threading
import time
import uuid
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "engine"))

import alias_bridge as AB          # noqa: E402
import backends as B               # noqa: E402
import classify as C               # noqa: E402
import completeness as G           # noqa: E402
import keys as K                   # noqa: E402
from lanes import LaneDispatcher, FrontierUnconfigured, lane_for_route  # noqa: E402
from pipeline import Pipeline      # noqa: E402
from runlog import RunLog          # noqa: E402

VERSION = "1.6.5"
UI_DIR = os.path.join(HERE, "ui")
MAX_PROMPT = 20000
MAX_LIST = 50
MAX_RUNS = 20
TOKEN_RE = re.compile(r"(?<![\w:])([a-z][a-z0-9_]*):([A-Z2-7]{26})(?![\w:])")

# kinds that have a readable alias prefix. The engine's vocabulary and the
# alias bridge's vocabulary do not fully overlap (fqdn -> host, name -> person).
ALIAS_KIND = {"name": "person", "hostname": "host", "ip": "ipv4",
              "fqdn": "host", "infra_host": "host", "host_bare": "host",
              "ipv4": "ipv4"}

STAGE_ORDER = ["intake", "censor", "judge", "route", "generate", "restore", "verify", "done"]

# A retry must ask for the whole file; the failure mode is a stop at the cap.
RETRY_NOTE = (" The previous attempt was cut off mid-file. Write the COMPLETE file, "
              "including every branch and the final statement.")

CONTENT_TYPES = {".html": "text/html; charset=utf-8",
                 ".js": "application/javascript; charset=utf-8",
                 ".css": "text/css; charset=utf-8"}
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; "
       "connect-src 'self'; img-src 'self' data:; base-uri 'none'; "
       "form-action 'none'; frame-ancestors 'none'")


# --------------------------------------------------------------------- entities
def extract_entities(censored, pipe):
    """Every placeholder in the censored text, with counts and a readable alias.

    Value resolution happens against this run's TokenSpace only. The returned
    ``value`` field is for the reveal map; it is never put in an event payload.
    """
    found = {}
    for m in TOKEN_RE.finditer(censored or ""):
        kind, body = m.group(1), m.group(2)
        tok = f"{kind}:{body}"
        rec = found.setdefault(tok, {"token": tok, "kind": kind, "count": 0,
                                     "value": None, "alias": None})
        rec["count"] += 1

    for rec in found.values():
        body = rec["token"].split(":", 1)[1]
        try:
            rec["value"] = pipe.censor.space.value_for(body)
        except KeyError:
            rec["value"] = None
        akind = ALIAS_KIND.get(rec["kind"], rec["kind"])
        if rec["value"] is not None and akind in AB.KIND_PREFIX:
            try:
                rec["alias"] = pipe.aliases.issue(akind, rec["value"])
            except Exception:
                rec["alias"] = None
    return sorted(found.values(), key=lambda r: (r["kind"], r["token"]))


def public_entities(entities):
    """Strip values: this is what an event may carry."""
    return [{"token": e["token"], "kind": e["kind"], "count": e["count"],
             "alias": e["alias"], "revealable": e["value"] is not None,
             "source": ("roster" if e["kind"] in ("name", "person")
                        else "declared" if e["kind"] == "address" else "regex")}
            for e in entities]


def highlight(text, limit=4000):
    """Escape-free preview for JSON; the browser escapes. Tokens get markers."""
    s = (text or "")[:limit]
    return s


def snippet(text, token, width=48):
    """Context around a token, expanded outward to word boundaries.

    Cutting at a fixed width can start inside a neighbouring placeholder and
    read as corruption. Expanding to whitespace keeps the snippet legible.
    """
    i = (text or "").find(token)
    if i < 0:
        return ""
    a, b = max(0, i - width), min(len(text), i + len(token) + width)
    while a > 0 and not text[a - 1].isspace():
        a -= 1
    while b < len(text) and not text[b].isspace():
        b += 1
    s = text[a:b].replace("\n", " ")
    s = re.sub(r"\s+", " ", s).strip()
    return ("…" if a else "") + s + ("…" if b < len(text) else "")


# --------------------------------------------------------------------- run state
class RunState:
    def __init__(self, run_id, mode, log):
        self.run_id = run_id
        self.mode = mode
        self.log = log
        self.events = []
        self.reveal = {}
        self.cond = threading.Condition()
        self.done = False
        self.seq = 0
        self.started = time.time()
        self.outcome = None

    def emit(self, stage, event, **fields):
        with self.cond:
            self.seq += 1
            rec = {"seq": self.seq, "ts": round(time.time() - self.started, 3),
                   "elapsed_s": round(time.time() - self.started, 3),
                   "stage": stage, "event": event}
            rec.update(fields)
            self.events.append(rec)
            self.cond.notify_all()
        self._log(stage, event, fields)

    def _log(self, stage, event, fields):
        """Numbers, booleans and short enum strings only. No previews, no text."""
        if not self.log:
            return
        safe = {}
        for k, v in fields.items():
            if k.startswith("preview") or k in ("prompt", "entities", "kinds", "names"):
                continue
            if isinstance(v, bool) or isinstance(v, (int, float)):
                safe[k] = v
            elif isinstance(v, str) and len(v) <= 40:
                safe[k] = v
        try:
            self.log.event(stage, event, **safe)
        except Exception:
            pass

    def finish(self, outcome, **fields):
        self.emit("done", "run_end", outcome=outcome, **fields)
        self.outcome = outcome
        with self.cond:
            self.done = True
            self.cond.notify_all()
        if self.log:
            try:
                self.log.close()
            except Exception:
                pass


class UIApp:
    def __init__(self, host="127.0.0.1", port=8788, config_path=None,
                 judge_factory=None, dispatcher_factory=None, allow_remote=False):
        self.config_path = config_path
        self.judge_factory = judge_factory or (lambda cfg: B.build_judge(cfg["judge"]))
        self.dispatcher_factory = dispatcher_factory or (lambda cfg: LaneDispatcher(cfg))
        self.allow_remote = allow_remote
        self.runs = {}
        self.lock = threading.Lock()
        self.srv = ThreadingHTTPServer((host, int(port)), Handler)
        self.srv.daemon_threads = True
        self.srv.app = self

    @property
    def port(self):
        return self.srv.server_address[1]

    @property
    def host(self):
        return self.srv.server_address[0]

    def serve_forever(self):
        self.srv.serve_forever()

    def start_background(self):
        t = threading.Thread(target=self.serve_forever, name="ui-server", daemon=True)
        t.start()
        return t

    def shutdown(self):
        self.srv.shutdown()

    # -- runs ---------------------------------------------------------------
    def new_run(self, req):
        run_id = f"ui-{time.strftime('%Y%m%dT%H%M%S')}-{uuid.uuid4().hex[:5]}"
        log = RunLog(run_id=run_id, echo=False)
        run = RunState(run_id, req["mode"], log)
        with self.lock:
            self.runs[run_id] = run
            if len(self.runs) > MAX_RUNS:
                oldest = sorted(self.runs, key=lambda k: self.runs[k].started)[0]
                self.runs.pop(oldest, None)
        t = threading.Thread(target=self._worker, args=(run, req), name=f"run-{run_id}",
                             daemon=True)
        t.start()
        return run

    def get_run(self, run_id):
        with self.lock:
            return self.runs.get(run_id)

    def config_summary(self):
        cfg = B.load_config(self.config_path)
        cal = {}
        cal_path = os.path.join(HERE, "calibration.json")
        if os.path.exists(cal_path):
            try:
                cal = json.load(open(cal_path))
            except Exception:
                cal = {}
        return {"version": VERSION,
                "threshold": cfg.get("threshold"),
                "calibrated": bool(cal.get("calibrated")),
                "calibration_verdict": cal.get("verdict"),
                "calibration_reason": cal.get("reason"),
                "judge": cfg["judge"].get("backend"),
                "judge_url": cfg["judge"].get("url"),
                "generator": cfg["generator"].get("backend"),
                "generator_profile": cfg["generator"].get("profile"),
                "modes": ["dry", "judge", "live"],
                "bind": f"{self.host}:{self.port}"}

    # -- worker -------------------------------------------------------------
    def _worker(self, run, req):
        profile = tempfile.mkdtemp(prefix="ui_profile_")
        audit = os.path.join(profile, "audit.jsonl")
        pipe = None
        try:
            K.load_or_create(K._default_path(profile))
            cfg = B.load_config(self.config_path)
            pipe = Pipeline(profile, scope_id=run.run_id, roster=req["roster"],
                            ground_truth={"staff": []}, threshold=cfg["threshold"],
                            audit_path=audit)
            for a in req["addresses"]:
                pipe.censor.gate.mark_sensitive(a, "address")

            prompt = req["prompt"]
            mode = req["mode"]

            # -- intake
            run.emit("intake", "stage_start")
            run.emit("intake", "received", chars=len(prompt),
                     lines=prompt.count("\n") + 1,
                     roster=len(req["roster"]), declared=len(req["addresses"]),
                     mode=mode, prompt_sha=__import__("hashlib").sha256(
                         prompt.encode()).hexdigest()[:12])
            run.emit("intake", "stage_end", elapsed_s=0.0)

            # -- censor
            t0 = time.time()
            run.emit("censor", "stage_start")
            try:
                censored, rep = pipe.scrub(prompt)
            except Exception as e:
                run.emit("censor", "stage_error", error=f"{type(e).__name__}: {e}"[:200],
                         elapsed_s=round(time.time() - t0, 3))
                run.finish("CENSOR_BLOCKED", detail="the censor refused this payload")
                return
            entities = extract_entities(censored, pipe)
            run.reveal = {e["token"]: e["value"] for e in entities if e["value"] is not None}
            # rep["kinds"] maps kind -> the ACTUAL matched values. It is internal
            # diagnostics and must never cross into an event, a log or the UI.
            kinds = rep.get("kinds", {}) if isinstance(rep, dict) else {}
            kind_counts = {k: (len(v) if isinstance(v, list) else v)
                           for k, v in kinds.items()}
            names = rep.get("names", []) if isinstance(rep, dict) else []
            run.emit("censor", "stage_end", elapsed_s=round(time.time() - t0, 3),
                     chars_in=len(prompt), chars_out=len(censored),
                     kinds=json.dumps(kind_counts), names=len(names),
                     entity_count=len(entities),
                     preview_out=highlight(censored))
            run.emit("censor", "entities", entities=public_entities(entities),
                     snippets={e["token"]: snippet(censored, e["token"]) for e in entities})

            level = None
            route = None

            # -- judge
            if mode in ("judge", "live"):
                t0 = time.time()
                run.emit("judge", "stage_start")
                try:
                    judge = self.judge_factory(cfg)
                    judge_name = judge.name
                    s = _with_heartbeat(run, "judge", lambda: judge.score(censored))
                    level = s["level"]
                    run.emit("judge", "stage_end", elapsed_s=round(time.time() - t0, 3),
                             raw=s["raw"], level=s["level"], scale=s["scale"],
                             backend=judge_name, seconds=s["seconds"])
                except Exception as e:
                    run.emit("judge", "stage_error", error=f"{type(e).__name__}: {e}"[:200],
                             elapsed_s=round(time.time() - t0, 3))
                    run.finish("JUDGE_UNAVAILABLE",
                               detail="the judge did not answer; no route was chosen")
                    return
            else:
                run.emit("judge", "skipped", reason="dry mode: no judge call")

            # -- route
            if level is None:
                run.emit("route", "skipped", reason="no score in dry mode")
            else:
                try:
                    route = pipe.route(level)
                except Exception as e:
                    run.emit("route", "stage_error", error=f"{type(e).__name__}: {e}"[:160])
                    run.finish("ROUTE_UNSET", detail="no route could be decided")
                    return
                run.emit("route", "stage_end", route=route, level=level,
                         threshold=cfg["threshold"] if cfg["threshold"] is not None else None,
                         elapsed_s=0.0)
                if route == "unrouted":
                    run.emit("route", "note",
                             reason="no calibrated threshold; the pipeline refuses to pick a side")


            if mode != "live":
                run.finish("CENSORED_ONLY" if mode == "dry" else "JUDGED_ONLY",
                           entities=len(entities), route=route)
                return

            # -- generate: dispatch to the lane the ROUTE chose, never a fallback
            t0 = time.time()
            run.emit("generate", "stage_start")
            dispatcher = self.dispatcher_factory(cfg)
            lane = lane_for_route(route)
            if lane is None:
                run.emit("generate", "skipped",
                         reason="unrouted: no lane chosen, refusing to pick one")
                run.finish("ROUTE_UNSET",
                           detail="route is unrouted; live generation requires a lane",
                           route=route)
                return
            run.emit("generate", "lane", lane=lane,
                     backend=dispatcher.backend_name(lane),
                     profile=dispatcher.profile_name(lane))
            if not dispatcher.available(lane):
                reason = dispatcher.unavailable_reason(lane)
                run.emit("generate", "stage_error",
                         error=f"{lane} lane unavailable: {reason}")
                run.finish("FRONTIER_UNCONFIGURED" if lane == "frontier"
                           else "GENERATOR_WEDGED",
                           detail=reason, route=route, lane=lane)
                return
            gen_name = f"{dispatcher.backend_name(lane)}:{dispatcher.profile_name(lane)}"

            # A real completion probe on the SELECTED lane before spending
            # minutes on generation. /health alone is not proof of life.
            try:
                probe = _with_heartbeat(run, "generate",
                                        lambda: dispatcher.probe(lane, timeout=90))
            except FrontierUnconfigured as e:
                run.finish("FRONTIER_UNCONFIGURED", detail=str(e)[:160], lane=lane)
                return
            except Exception as e:
                probe = {"live": False, "error": f"{type(e).__name__}: {e}"[:160]}
            run.emit("generate", "probe", live=bool(probe.get("live")),
                     lane=lane, seconds=probe.get("seconds"),
                     content=(probe.get("content") or "")[:40],
                     tool_calls=probe.get("tool_calls"),
                     error=(probe.get("error") or "")[:160])
            if not probe.get("live"):
                run.emit("generate", "stage_error",
                         error=f"{lane} lane probe returned no content (wedged or down)")
                run.finish("GENERATOR_WEDGED",
                           detail="preflight probe failed on the selected lane; "
                                  "no artifact was requested", lane=lane)
                return

            max_tokens = (dispatcher.spec(lane) or {}).get("max_tokens") \
                or cfg.get("generator", {}).get("max_tokens")
            g = None
            gate = None
            attempts = []
            prose_text = ""
            for attempt in (1, 2):
                prompt_out = censored if attempt == 1 else censored + RETRY_NOTE
                try:
                    g = _with_heartbeat(
                        run, "generate",
                        lambda p=prompt_out, b=max_tokens: dispatcher.generate(
                            p, workdir=profile, max_tokens=b, lane=lane))
                except Exception as e:
                    err = f"{type(e).__name__}: {e}"[:200]
                    attempts.append({"attempt": attempt, "error": err})
                    run.emit("generate", "attempt", attempt=attempt, error=err,
                             elapsed_s=round(time.time() - t0, 3))
                    break
                code = g.get("code") or ""
                text = (g.get("text") or "").strip()
                if g.get("transport") == "prose" and text:
                    # An analysis answer is a deliverable, not a failed artifact.
                    prose_text = text
                    attempts.append({"attempt": attempt, "bytes": 0,
                                     "lane": lane, "complete": True, "reasons": [],
                                     "transport": "prose", "text_chars": len(text),
                                     "finish_reason": g.get("finish"),
                                     "seconds": g.get("seconds")})
                    run.emit("generate", "attempt", attempt=attempt, bytes=0,
                             lane=lane, complete=True, transport="prose",
                             text_chars=len(text), finish_reason=g.get("finish"),
                             seconds=g.get("seconds"), rc=g.get("rc"),
                             transcript=(g.get("transcript") or "")[-4000:])
                    run.emit("generate", "delivered", chars=len(text),
                             preview=highlight(text, 6000))
                    break
                gate = G.check(code, symbol=None, finish_reason=g.get("finish"),
                               completion_tokens=g.get("completion_tokens"),
                               budget_tokens=g.get("budget_tokens") or max_tokens)
                attempts.append({"attempt": attempt, "bytes": len(code),
                                 "lane": lane,
                                 "complete": gate["complete"],
                                 "reasons": gate["reasons"],
                                 "transport": g.get("transport"),
                                 "finish_reason": g.get("finish"),
                                 "seconds": g.get("seconds")})
                run.emit("generate", "attempt", attempt=attempt, bytes=len(code),
                         lane=lane, complete=gate["complete"],
                         reasons="; ".join(gate["reasons"])[:200],
                         transport=g.get("transport"), finish_reason=g.get("finish"),
                         seconds=g.get("seconds"), rc=g.get("rc"),
                         transcript=(g.get("transcript") or "")[-4000:],
                         preview=highlight(code, 3000))
                if gate["complete"]:
                    break
                if attempt == 1:
                    max_tokens = (int(max_tokens) * 2) if max_tokens else 4096
                    run.emit("generate", "retry", reason="incomplete artifact",
                             new_budget=max_tokens)
            run.emit("generate", "stage_end", elapsed_s=round(time.time() - t0, 3),
                     attempts=len(attempts), backend=gen_name, lane=lane)

            if g is None:
                run.finish("GENERATOR_WEDGED",
                           detail="generation failed; see the attempt event")
                return

            if prose_text:
                # The answer is already safe: the model only ever saw placeholders.
                # Restoring it would put real values back into the deliverable.
                run.emit("restore", "skipped",
                         reason="prose deliverable: placeholders are left intact, "
                                "the answer is already safe to ship")
                run.emit("verify", "skipped",
                         reason="prose deliverable: nothing to compile or execute")
                run.finish("DELIVERED_TEXT",
                           detail="model answered in prose; delivered the censored text",
                           lane=lane, route=route, text_chars=len(prose_text))
                return

            code = g.get("code") or ""
            if not gate or not gate["complete"]:
                run.finish("TRUNCATED" if code.strip() else "EMPTY",
                           detail="the artifact did not pass the completeness gate",
                           lane=lane)
                return

            # -- restore (browser-only preview; never logged)
            t0 = time.time()
            run.emit("restore", "stage_start")
            try:
                restored, rrep = pipe.restore(code)
            except Exception as e:
                run.emit("restore", "stage_error", error=f"{type(e).__name__}: {e}"[:200])
                run.finish("EXEC_FAIL", detail="restore failed")
                return
            run.emit("restore", "stage_end", elapsed_s=round(time.time() - t0, 3),
                     tokens=len(rrep.get("tokens", [])),
                     aliases=len(rrep.get("aliases", [])),
                     unknown=len(rrep.get("unknown_tokens", [])) +
                             len(rrep.get("unknown_aliases", [])),
                     preview_before=highlight(code, 3000),
                     preview_after=highlight(restored, 3000))

            # -- verify (compile only; execution is not exercised)
            t0 = time.time()
            run.emit("verify", "stage_start")
            art = os.path.join(profile, "artifact.py")
            compiles, compile_error = False, None
            try:
                with open(art, "w") as fh:
                    fh.write(restored)
                os.chmod(art, 0o600)
                py_compile.compile(art, doraise=True)
                compiles = True
            except Exception as e:
                compile_error = str(e)[:200]
            run.emit("verify", "stage_end", elapsed_s=round(time.time() - t0, 3),
                     compiles=compiles, compile_error=compile_error,
                     executes=None,
                     note="compiled only; execution is not exercised by the inspector")

            rec = {"code": code, "transport": g.get("transport"), "route": route,
                   "level": level, "compiles": compiles, "executes": None,
                   "complete": True, "finish_reason": g.get("finish"),
                   "gate_reasons": [], "last_statement": gate["last_statement"]}
            verdict = C.classify(rec)
            run.finish(verdict["class"], detail=verdict["detail"],
                       entities=len(entities), compiles=compiles,
                       lane=lane, route=route)

        except Exception as e:
            run.emit("done", "run_error", error=f"{type(e).__name__}: {e}"[:300])
            run.finish("EXEC_FAIL", detail="unexpected inspector error")
        finally:
            if pipe is not None:
                try:
                    pipe.close()
                except Exception:
                    pass
            shutil.rmtree(profile, ignore_errors=True)


def _with_heartbeat(run, stage, fn, interval=5.0):
    """Run a blocking call while emitting heartbeats, so slow ≠ silent."""
    stop = threading.Event()
    t0 = time.time()

    def beat():
        while not stop.wait(interval):
            run.emit(stage, "heartbeat",
                     stage_elapsed_s=round(time.time() - t0, 1))

    th = threading.Thread(target=beat, name=f"hb-{stage}", daemon=True)
    th.start()
    try:
        return fn()
    finally:
        stop.set()


# --------------------------------------------------------------------- http
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = f"DesensitizerUI/{VERSION}"

    # -- helpers
    def _common(self, code, ctype, body, cache="no-store"):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", cache)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", CSP)
        self.end_headers()
        self.wfile.write(data)

    def _json(self, code, obj):
        self._common(code, "application/json; charset=utf-8",
                     json.dumps(obj, ensure_ascii=False))

    def _err(self, code, msg):
        self._json(code, {"error": msg})

    def _origin_ok(self):
        origin = self.headers.get("Origin")
        if not origin:
            return True                      # curl / test client
        host = self.headers.get("Host", "")
        return origin in (f"http://{host}",)

    def _read_json(self):
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip()
        if ctype != "application/json":
            return None, "Content-Type must be application/json"
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return None, "bad Content-Length"
        if n <= 0 or n > 1_000_000:
            return None, "empty or oversized body"
        try:
            return json.loads(self.rfile.read(n) or b"{}"), None
        except Exception:
            return None, "body is not valid JSON"

    # -- GET
    def do_GET(self):
        u = urlparse(self.path)
        app = self.server.app
        if u.path == "/":
            return self._static("index.html")
        if u.path in ("/app.js", "/style.css"):
            return self._static(u.path.lstrip("/"))
        if u.path == "/api/health":
            return self._json(200, {"ok": True, "version": VERSION,
                                    "bind": f"{app.host}:{app.port}"})
        if u.path == "/api/config":
            return self._json(200, app.config_summary())
        if u.path == "/api/stream":
            q = parse_qs(u.query)
            run_id = (q.get("run_id") or [""])[0]
            return self._stream(run_id)
        return self._err(404, "not found")

    def _static(self, name):
        path = os.path.abspath(os.path.join(UI_DIR, name))
        if not path.startswith(os.path.abspath(UI_DIR) + os.sep) or not os.path.isfile(path):
            return self._err(404, "not found")
        ctype = CONTENT_TYPES.get(os.path.splitext(path)[1], "application/octet-stream")
        with open(path, "rb") as fh:
            self._common(200, ctype, fh.read())

    def _stream(self, run_id):
        app = self.server.app
        run = app.get_run(run_id)
        if run is None:
            return self._err(404, "unknown run")
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.send_header("Content-Security-Policy", CSP)
        self.end_headers()
        idx = 0
        try:
            while True:
                with run.cond:
                    if idx >= len(run.events) and not run.done:
                        run.cond.wait(timeout=10)
                while idx < len(run.events):
                    ev = run.events[idx]
                    idx += 1
                    payload = f"id: {ev['seq']}\ndata: {json.dumps(ev, ensure_ascii=False)}\n\n"
                    self.wfile.write(payload.encode("utf-8"))
                self.wfile.flush()
                if run.done and idx >= len(run.events):
                    break
                if idx >= len(run.events):
                    self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            self.close_connection = True

    # -- POST
    def do_POST(self):
        u = urlparse(self.path)
        if not self._origin_ok():
            return self._err(403, "cross-origin request refused")
        body, err = self._read_json()
        if err:
            return self._err(415 if "Content-Type" in err else 400, err)
        app = self.server.app

        if u.path == "/api/run":
            return self._start(app, body)
        if u.path == "/api/reveal":
            run = app.get_run((body or {}).get("run_id", ""))
            if run is None:
                return self._err(404, "unknown run")
            token = (body or {}).get("token", "")
            if token not in run.reveal or run.reveal[token] is None:
                return self._err(404, "unknown token for this run")
            return self._json(200, {"token": token, "value": run.reveal[token],
                                    "note": "cleartext, local only, not written to disk"})
        return self._err(404, "not found")

    def _start(self, app, body):
        mode = (body or {}).get("mode", "dry")
        prompt = body.get("prompt") if isinstance(body, dict) else None
        if mode not in ("dry", "judge", "live"):
            return self._err(400, "mode must be dry, judge or live")
        if not isinstance(prompt, str) or not prompt.strip():
            return self._err(400, "prompt is required")
        if len(prompt) > MAX_PROMPT:
            return self._err(400, f"prompt exceeds {MAX_PROMPT} characters")
        roster = body.get("roster") or []
        addresses = body.get("addresses") or []
        if not isinstance(roster, list) or not isinstance(addresses, list):
            return self._err(400, "roster and addresses must be lists")
        if len(roster) > MAX_LIST or len(addresses) > MAX_LIST:
            return self._err(400, f"at most {MAX_LIST} entries each")
        roster = [str(x)[:120] for x in roster if str(x).strip()]
        addresses = [str(x)[:200] for x in addresses if str(x).strip()]
        run = app.new_run({"mode": mode, "prompt": prompt,
                           "roster": roster, "addresses": addresses})
        return self._json(200, {"run_id": run.run_id, "mode": mode,
                                "stream": f"/api/stream?run_id={run.run_id}"})

    def log_message(self, fmt, *args):
        # Access logs would record prompts in a URL; there are no prompts in
        # URLs, but keep the console quiet anyway.
        pass


def main():
    ap = argparse.ArgumentParser(description="Local prompt-flow inspector")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8788)
    ap.add_argument("--config", default=os.path.join(HERE, "config.json"))
    ap.add_argument("--open", action="store_true")
    ap.add_argument("--allow-remote", action="store_true",
                    help="permit a non-loopback bind (NOT recommended)")
    a = ap.parse_args()

    loopback = a.host in ("127.0.0.1", "::1", "localhost")
    if not loopback and not a.allow_remote:
        print(f"REFUSED: host {a.host!r} is not loopback. "
              f"Pass --allow-remote only if you understand the exposure.")
        return 2

    app = UIApp(host=a.host, port=a.port, config_path=a.config,
                allow_remote=a.allow_remote)
    cfg = app.config_summary()
    print(f"Desensitizer inspector {VERSION}")
    print(f"  bind       http://{app.host}:{app.port}")
    print(f"  judge      {cfg['judge']} ({cfg['judge_url']})")
    print(f"  generator  {cfg['generator']}"
          + (f" ({cfg['generator_profile']})" if cfg.get("generator_profile") else ""))
    print(f"  threshold  {cfg['threshold'] if cfg['threshold'] is not None else 'none (unrouted)'}"
          f"  ·  calibration {cfg['calibration_verdict'] or 'absent'}")
    print("  local only: the prompt is never written to disk; reveal is explicit.")
    if a.open:
        webbrowser.open(f"http://{app.host}:{app.port}")
    try:
        app.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
