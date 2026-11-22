"""Backend adapters: exactly one judge and exactly one generator.

The topology is fixed; the models are not. A deployment may replace OpenJev with
another scorer and Agents-A1-4B with another generator, so both roles sit behind
a small contract and are selected by config, never by editing call sites.

JUDGE CONTRACT
    score(text) -> {
        raw:        float,   # what the backend literally returned
        scale:      "index0-4" | "1-10" | "0-1",
        level:      float,   # normalised onto 1..10 — THIS is what routing uses
        legend:     list | None,
        seconds:    float,
        backend:    str,
    }
    probe() -> {live: bool, ...}

    Normalising in the adapter is the point: a judge that returns an expected
    index over 5 levels and a judge that returns 1..10 directly are both usable,
    and the router never needs to know which one it has.

GENERATOR CONTRACT
    generate(prompt, workdir) -> {
        code:          str,     # the artifact text, or ""
        artifact_path: str|None,
        seconds:       float,
        transport:     str,
    }
    probe() -> {live: bool, ...}

    Two transports exist because they are not interchangeable in practice:
    an OpenAI-compatible API returns text in the response body, while the Hermes
    profile writes a file to disk. Both satisfy the contract.

Adding a backend
    1. subclass Judge or Generator
    2. honour the return keys above (tests/test_backends.py enforces this)
    3. register it in BACKENDS
    4. point config.json at it
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

DEFAULT_CRITERIA = [
    "1 - single-line boilerplate or lookup",
    "3 - one straightforward function",
    "5 - several interacting pieces",
    "7 - careful algorithm or state machine",
    "10 - deep systems reasoning with many invariants",
]


# --------------------------------------------------------------------- judge
class Judge:
    """Base class. Subclasses implement score() and probe()."""

    name = "judge"

    def score(self, text):
        raise NotImplementedError

    def probe(self):
        raise NotImplementedError

    @staticmethod
    def normalise(raw, legend=None):
        """Map a backend score onto 1..10 for routing.

        legend, when present, is the backend's own level labels (e.g.
        [1,3,5,7,10]). raw is treated as an expected INDEX into it and
        interpolated. Without a legend, raw is assumed to be on 1..10 already.
        """
        if raw is None:
            return None
        if not legend:
            return float(raw)
        lo = int(raw)
        frac = raw - lo
        if lo >= len(legend) - 1:
            return float(legend[-1])
        if lo < 0:
            return float(legend[0])
        return round(legend[lo] + frac * (legend[lo + 1] - legend[lo]), 3)


class JevJudge(Judge):
    """OpenJev: POST /v1/inference with a score question.

    Returns an expected index over the `legend` it reports. Measured
    inference_seconds for 5 candidates on CPU: ~19-25s.
    """

    name = "openjev"

    def __init__(self, url="http://127.0.0.1:8791", criteria=None, timeout=300):
        self.url = url.rstrip("/")
        self.criteria = criteria or DEFAULT_CRITERIA
        self.timeout = timeout

    def _ask(self, payload, timeout=None):
        req = urllib.request.Request(f"{self.url}/v1/inference",
                                     data=json.dumps(payload).encode(),
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout or self.timeout) as r:
            return json.loads(r.read())

    def score(self, text):
        payload = {"state": {"text": text},
                   "questions": {"difficulty": {
                       "type": "score",
                       "instructions": "Rate how hard this task is for a 4B local model.",
                       "criteria": self.criteria}}}
        t0 = time.time()
        d = self._ask(payload)
        a = d["answers"]["difficulty"]
        raw = float(a["score"])
        legend = _legend_values(a.get("legend"))
        return {"raw": raw, "scale": "index0-4" if legend else "1-10",
                "level": self.normalise(raw, legend), "legend": legend,
                "seconds": round(time.time() - t0, 2), "backend": self.name}

    def probe(self):
        t0 = time.time()
        try:
            s = self.score("Say hello.")
            return {"live": s["raw"] is not None, "seconds": round(time.time() - t0, 2),
                    "raw": s["raw"], "level": s["level"]}
        except Exception as e:
            return {"live": False, "seconds": round(time.time() - t0, 2),
                    "error": f"{type(e).__name__}: {e}"[:160]}


def _legend_values(legend):
    """Extract numeric labels from {'0': '1 - trivial', ...} or [1,3,5,7,10]."""
    if not legend:
        return None
    if isinstance(legend, list):
        return legend
    out = []
    for k in sorted(legend, key=lambda x: int(x)):
        m = re.search(r"-?\d+(?:\.\d+)?", str(legend[k]))
        out.append(float(m.group(0)) if m else float(k))
    return out



_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_RULE = re.compile(r"(?m)^\s*[\u2500\u2501\u2550-]{6,}\s*$")
_BANNER = ("Welcome to", "ghcr.io/", "Boot Status", "ujust", "fastfetch",
           "brew help", "No Flatpak", "The Gear Lever", "Bazzite", "BTRFS",
           "It is always better", "Protect your video games", "https://",
           "Command ", "Documentation ", "Report an issue", "Discord",
           "Bluesky")


def _assistant_text(out):
    """The model's answer text from a `hermes chat -q` transcript.

    Strips ANSI, the resume footer, rule lines and the shell banner. This is a
    display/delivery fallback only: it never claims to be code.
    """
    s = _ANSI.sub("", out or "")
    s = s.split("Resume this session with:")[0]
    # Drop the CLI's query echo and marker; the answer follows the last marker.
    if "☤ Hermes" in s:
        s = s.split("☤ Hermes")[-1]
    s = _RULE.sub("", s)
    keep = []
    for line in s.splitlines():
        t = line.strip()
        if not t:
            keep.append("")
            continue
        if any(t.startswith(b) for b in _BANNER):
            continue
        if t[0] in "\u2502\u2503\u250f\u2517\u2500\u2022\uf0d9\uf11b":
            continue
        keep.append(line.rstrip())
    return re.sub(r"\n{3,}", "\n\n", "\n".join(keep)).strip()


# ----------------------------------------------------------------- generator
class Generator:
    """Base class. Subclasses implement generate() and probe().

    ``health()`` is deliberately NOT proof of life: a llama-server can answer
    /health with 200 while every completion times out. It exists only to tell
    "down" (socket refused) apart from "wedged" (socket bound, no answer).
    """

    name = "generator"
    url = None

    def generate(self, prompt, workdir=None, max_tokens=None):
        raise NotImplementedError

    def probe(self, timeout=None):
        raise NotImplementedError

    def health(self, timeout=5):
        if not self.url:
            return {"ok": None, "detail": "backend has no url"}
        try:
            with urllib.request.urlopen(f"{self.url}/health", timeout=timeout) as r:
                body = r.read(400).decode("utf-8", "replace")
                return {"ok": r.status == 200, "status": r.status, "body": body[:120]}
        except Exception as e:
            return {"ok": False, "error": f"{type(e).__name__}: {e}"[:160]}


class ProfileGenerator(Generator):
    """Drive a Hermes profile. The artifact lands in the profile's scratch dir.

    This is the transport that works for Agents-A1-4B. The raw API on :8083
    returns zero content for coding prompts because the server runs with
    --reasoning-budget -1 (measured: 6000 tokens, 0 content chars, 20,098
    reasoning chars). A per-request reasoning_budget is ignored by this build.
    """

    name = "hermes-profile"

    def __init__(self, profile="testingagentsa14b", url="http://127.0.0.1:8083", timeout=900):
        self.profile = profile
        self.url = url.rstrip("/")
        self.timeout = timeout

    def generate(self, prompt, workdir=None, max_tokens=None):
        cwd = workdir or tempfile.mkdtemp(prefix="gen_")
        os.makedirs(cwd, exist_ok=True)
        t0 = time.time()
        r = subprocess.run(["hermes", "-p", self.profile, "chat", "-q", prompt],
                           capture_output=True, text=True, timeout=self.timeout, cwd=cwd)
        out = (r.stdout or "") + (r.stderr or "")

        # Announcements seen in practice: "File created at:<path>" (colon, no
        # space) and "✍️ Write <path>". Accept any .py path that exists and is
        # newer than this call, so a stale scratch file is never returned.
        path, code = None, ""
        for cand in reversed(re.findall(r"(/\S+?\.py)", out)):
            cand = cand.rstrip(".,)")
            if os.path.exists(cand) and os.path.getmtime(cand) >= t0 - 2:
                path = cand
                with open(cand) as fh:
                    code = fh.read()
                break
        if not code and os.path.exists(os.path.join(cwd, "answer.py")):
            path = os.path.join(cwd, "answer.py")
            with open(path) as fh:
                code = fh.read()

        # Some turns answer inline instead of writing a file.
        transport = "file" if code else "none"
        text = ""
        if not code:
            body = out.split("☤ Hermes")[-1] if "☤ Hermes" in out else out
            body = re.split(r"─{5,}", body)[0].strip()
            if re.search(r"^\s*(?:import|from|def|class)\s", body, re.M):
                code, path, transport = body, None, "inline"
            else:
                # An analysis prompt legitimately answers in prose. Capture it
                # as a deliverable instead of throwing it away as "none".
                text = _assistant_text(out)
                transport = "prose" if text else "none"

        return {"code": code, "artifact_path": path, "text": text,
                "seconds": round(time.time() - t0, 1), "transport": transport,
                "transcript": _ANSI.sub("", out)[-8000:], "rc": r.returncode,
                "finish": None, "budget_tokens": max_tokens}

    def probe(self, timeout=180):
        body = {"model": "agents-a1-4b",
                "messages": [{"role": "user", "content": "Reply with the single word: ALIVE"}],
                "max_tokens": 400, "temperature": 0}
        t0 = time.time()
        try:
            req = urllib.request.Request(f"{self.url}/v1/chat/completions",
                                         data=json.dumps(body).encode(),
                                         headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                d = json.loads(r.read())
            c = d["choices"][0]
            txt = (c["message"].get("content") or "").strip()
            return {"live": bool(txt), "seconds": round(time.time() - t0, 1),
                    "content": txt[:40],
                    "completion_tokens": d.get("usage", {}).get("completion_tokens")}
        except Exception as e:
            return {"live": False, "seconds": round(time.time() - t0, 1),
                    "error": f"{type(e).__name__}: {e}"[:160]}


class ApiGenerator(Generator):
    """OpenAI-compatible chat endpoint. Returns the body text.

    Kept because it is the natural backend for any model that answers directly
    instead of writing files. Not usable with the current 4B config; usable with
    any model that emits content within its token budget.
    """

    name = "openai-api"

    def __init__(self, url="http://127.0.0.1:8083", model="agents-a1-4b",
                 max_tokens=2200, timeout=900, temperature=0):
        self.url = url.rstrip("/")
        self.model = model
        self.max_tokens = max_tokens
        self.timeout = timeout
        self.temperature = temperature

    def _chat(self, prompt, max_tokens=None, timeout=None):
        """One raw completion. Returns the parsed choice plus usage."""
        budget = max_tokens or self.max_tokens
        body = {"model": self.model,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": budget, "temperature": self.temperature}
        req = urllib.request.Request(f"{self.url}/v1/chat/completions",
                                     data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout or self.timeout) as r:
            d = json.loads(r.read())
        c = d["choices"][0]
        usage = d.get("usage") or {}
        return c, usage, budget

    def generate(self, prompt, workdir=None, max_tokens=None):
        t0 = time.time()
        c, usage, budget = self._chat(prompt, max_tokens=max_tokens)
        text = c["message"].get("content") or ""
        return {"code": text, "artifact_path": None,
                "seconds": round(time.time() - t0, 1),
                "transport": "api", "finish": c.get("finish_reason"),
                "completion_tokens": usage.get("completion_tokens"),
                "budget_tokens": budget,
                "reasoning_chars": len(c["message"].get("reasoning_content") or "")}

    def probe(self, timeout=None):
        t0 = time.time()
        try:
            c, usage, budget = self._chat("Reply with the single word: ALIVE",
                                          max_tokens=16, timeout=timeout)
            txt = (c["message"].get("content") or "").strip()
            return {"live": bool(txt), "seconds": round(time.time() - t0, 1),
                    "content": txt[:40], "finish": c.get("finish_reason"),
                    "reasoning_chars": len(c["message"].get("reasoning_content") or ""),
                    "completion_tokens": usage.get("completion_tokens")}
        except Exception as e:
            return {"live": False, "seconds": round(time.time() - t0, 1),
                    "error": f"{type(e).__name__}: {e}"[:160]}


class SubagentGenerator(ProfileGenerator):
    """A delegated Hermes subagent, one profile per lane.

    Same transport as ProfileGenerator (the profile writes the artifact), but
    ``probe()`` tests the PROFILE, not a separate raw API. Probing :8083 for a
    frontier profile would report the local model's health and call it live —
    the exact false-positive this class exists to avoid.
    """

    name = "hermes-subagent"

    def probe(self, timeout=120):
        cwd = tempfile.mkdtemp(prefix="probe_")
        t0 = time.time()
        try:
            r = subprocess.run(
                ["hermes", "-p", self.profile, "chat", "-q",
                 "Reply with the single word: ALIVE"],
                capture_output=True, text=True, timeout=timeout, cwd=cwd)
            out = (r.stdout or "") + (r.stderr or "")
            live = r.returncode == 0 and "ALIVE" in out
            m = re.search(r"\(1 user, (\d+) tool calls\)", out)
            return {"live": live, "seconds": round(time.time() - t0, 1),
                    "content": "ALIVE" if live else out[-80:],
                    "rc": r.returncode,
                    "tool_calls": int(m.group(1)) if m else None}
        except Exception as e:
            return {"live": False, "seconds": round(time.time() - t0, 1),
                    "error": f"{type(e).__name__}: {e}"[:160]}
        finally:
            shutil.rmtree(cwd, ignore_errors=True)


# ------------------------------------------------------------------ registry
JUDGES = {"openjev": JevJudge}
GENERATORS = {"hermes-profile": ProfileGenerator, "openai-api": ApiGenerator,
              "hermes-subagent": SubagentGenerator}


def build_judge(cfg):
    """Exactly one judge. Refuses to build zero."""
    cfg = cfg or {}
    kind = cfg.get("backend", "openjev")
    cls = JUDGES.get(kind)
    if cls is None:
        raise ValueError(f"unknown judge backend {kind!r}; known: {sorted(JUDGES)}")
    kw = {k: v for k, v in cfg.items()
          if k in ("url", "timeout", "criteria")}
    return cls(**kw)


def build_generator(cfg):
    """Exactly one generator. Refuses to build zero."""
    cfg = cfg or {}
    kind = cfg.get("backend", "hermes-profile")
    cls = GENERATORS.get(kind)
    if cls is None:
        raise ValueError(f"unknown generator backend {kind!r}; known: {sorted(GENERATORS)}")
    kw = {k: v for k, v in cfg.items()
          if k in ("url", "model", "profile", "timeout", "max_tokens", "temperature")}
    return cls(**kw)


def load_config(path=None):
    """Config with defaults. One judge, one generator — never a list.

    ``threshold`` stays None unless it comes from an explicit config value or a
    calibration file that proves its separation. None means route() returns
    "unrouted"; that is the honest default, not a missing setting.
    """
    cfg = {"threshold": None,
           "judge": {"backend": "openjev", "url": "http://127.0.0.1:8791"},
           "generator": {"backend": "hermes-profile", "profile": "testingagentsa14b"},
           # Two lanes, one delegated subagent each. The router picks the lane;
           # a missing frontier lane is an error, never a fallback to local.
           "lanes": {"local": {"backend": "hermes-subagent", "profile": "desens-local"},
                     "frontier": {"backend": "hermes-subagent", "profile": "desens-frontier"}}}
    if path and os.path.exists(path):
        with open(path) as fh:
            user = json.load(fh)
        for k, v in user.items():
            if k in ("judge", "generator") and isinstance(v, dict):
                cfg[k].update(v)
            elif k == "lanes" and isinstance(v, dict):
                for lane, spec in v.items():
                    cfg["lanes"].setdefault(lane, {}).update(spec or {})
            else:
                cfg[k] = v
    if cfg.get("threshold") is None:
        cfg["threshold"] = _calibrated_threshold(cfg.get("calibration_path"))
    return cfg


def _calibrated_threshold(path=None):
    """Read calibration.json; honour a threshold only on demonstrated evidence."""
    candidates = [path] if path else []
    candidates.append(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                   "calibration.json"))
    for p in candidates:
        if not p or not os.path.exists(p):
            continue
        try:
            with open(p) as fh:
                d = json.load(fh)
        except Exception:
            continue
        if not d.get("calibrated"):
            continue
        try:
            thr = float(d["threshold"])
        except (KeyError, TypeError, ValueError):
            continue
        ratio = d.get("separation_over_noise")
        if ratio is None:
            try:
                ok = float(d["separation"]) >= float(d.get("min_separation", 1.0))
            except (KeyError, TypeError, ValueError):
                ok = False
            if ok:
                return thr
            continue
        try:
            if float(ratio) >= float(d.get("min_ratio", 3.0)):
                return thr
        except (TypeError, ValueError):
            continue
    return None


# ------------------------------------------------------------------ liveness
# Recovery for a wedged server. SIGTERM first, confirm by pid, then SIGKILL:
# a compute loop that ignores SIGTERM will otherwise survive the restart and
# two servers end up on one port.
RECOVERY = ("pgrep -f 'llama-server.*port 8083' | xargs -r kill; sleep 5; "
            "pgrep -f 'llama-server.*port 8083' | xargs -r kill -9; "
            "~/Documents/Agents/hermes/tuning/supervisor.sh restart")


def wedge_verdict(gen, attempts=2, probe_timeout=None, health_timeout=5):
    """Decide live / wedged / down from a REAL completion probe.

    /health is read but never trusted on its own: the measured failure was a
    server answering health with 200 while every completion hung. Two
    consecutive empty probes with health ok is a wedge; a refused socket is
    down. Both refuse to run; only one of them is a model-server bug.
    """
    health = gen.health(timeout=health_timeout)
    probes = []
    for _ in range(max(1, int(attempts))):
        try:
            p = gen.probe(timeout=probe_timeout) if probe_timeout is not None else gen.probe()
        except TypeError:                      # probe() without a timeout kwarg
            p = gen.probe()
        except Exception as e:                 # a probe that raises is not live
            p = {"live": False, "error": f"{type(e).__name__}: {e}"[:160]}
        probes.append(p)
        if p.get("live"):
            return {"verdict": "live", "health": health, "probes": probes,
                    "attempts": len(probes)}

    if health.get("ok") is True:
        verdict = "wedged"
    else:
        verdict = "down"
    return {"verdict": verdict, "health": health, "probes": probes,
            "attempts": len(probes), "recovery": RECOVERY}


def preflight(judge, gen, attempts=2, probe_timeout=None):
    """Refuse to run against a dead judge or a generator that cannot complete.

    Returns {"ok": bool, "class": name|None, "judge": {...}, "generator": {...}}.
    A caller that ignores ``ok`` is reporting rates against a wall.
    """
    jp = judge.probe()
    out = {"ok": False, "class": None, "judge": jp, "generator": None}
    if not jp.get("live"):
        out["class"] = "JUDGE_UNAVAILABLE"
        return out

    w = wedge_verdict(gen, attempts=attempts, probe_timeout=probe_timeout)
    out["generator"] = w
    if w["verdict"] != "live":
        out["class"] = "GENERATOR_WEDGED"
        out["detail"] = ("health 200 but no completion (wedged)" if w["verdict"] == "wedged"
                         else "generator socket refused (down)")
        return out
    out["ok"] = True
    return out
