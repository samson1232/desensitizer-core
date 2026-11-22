"""Append-only JSONL run log — one file per run, one record per stage.

The problem this solves: a three-task live run takes 4-6 minutes and prints
nothing between model calls, so a normal wait is indistinguishable from a hang.
Every run now narrates itself:

    run = RunLog()                     # runs/run-<id>.jsonl
    with run.stage("judge"):
        run.progress(bytes=1234)       # optional in-flight byte counter
        ...

Guarantees enforced here, not by convention:

1. A heartbeat is emitted at least every ``heartbeat_s`` (default 5 s, budget
   is 10 s) while any stage is in flight, carrying elapsed time and bytes
   received so far. A killed run's last record therefore names the stage it
   died in.
2. No cleartext can be written. Values are numbers, booleans, None or short
   strings; strings pass through a redactor that removes PII shapes and
   capitalised-name runs, and a deny list rejects whole-document keys
   (``source``, ``code``, ``transcript``, ``tasking``, ...) outright. A caller
   that tries to log an artifact gets a ValueError, not a leak.
3. ``classify.py`` can read the log: every record carries ``run_id``, ``stage``
   and ``event``, and terminal records use event="done" or "classified".

Nothing here imports the censor: the log must not depend on a key, and it must
be safe even when the censor is unavailable.
"""
import json
import os
import re
import threading
import time
import uuid

# Whole-document keys are refused: these hold cleartext by design somewhere
# upstream, and a log is not the place to re-introduce it.
_DENY_KEYS = {
    "source", "code", "artifact", "artifacts", "transcript", "tasking",
    "pivot", "pivot_table", "cleartext", "restored", "prompt", "text",
    "content", "answer", "raw_text", "body", "stdout", "stderr",
}

_KEY_RE = re.compile(r"^[a-z][a-z0-9_]{0,39}$")

# PII shapes. Deliberately conservative: a false redaction costs a log field,
# a missed one costs a leak.
_PII = [
    ("email", re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")),
    ("card", re.compile(r"\b(?:\d[ -]?){13,16}\b")),
    ("iban", re.compile(r"\b[A-Z]{2}\d{2}[A-Z]{4}\d{10,30}\b")),
    ("phone", re.compile(r"(?:\+\d[\d ()-]{8,}\d)|(?:\b0\d{3,5}[ -]?\d{6}\b)")),
    ("ipv4", re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")),
    ("uuid", re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                        r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")),
    ("postcode", re.compile(r"\b[A-Z]{1,2}\d[A-Z\d]?\s*\d[A-Z]{2}\b")),
    ("money", re.compile(r"£\s?\d[\d,]*(?:\.\d+)?")),
    ("host", re.compile(r"\b[\w-]+(?:\.(?:com|net|org|io|co|uk|local|lan|"
                        r"internal|corp|example|dev))\b", re.I)),
    ("digits", re.compile(r"\b\d{8,}\b")),
    ("hex", re.compile(r"\b[0-9a-f]{16,}\b", re.I)),
]
# Two capitalised words in a row, whitespace or comma separated. This is the
# "Alice Smith" shape; prose rarely has it and runlog should never carry prose.
_NAME = re.compile(r"\b[A-Z][a-z]{1,20}(?:\s+|\s*,\s*)[A-Z][a-z]{1,20}\b")

_MAX_STR = 160


def redact(value):
    """Return a log-safe string. Raises for non-scalar junk, never for text."""
    if value is None or isinstance(value, (bool, int, float)):
        if isinstance(value, float) and (value != value or value in
                                         (float("inf"), float("-inf"))):
            return str(value)
        return value
    if not isinstance(value, str):
        raise TypeError(f"runlog value must be scalar or str, not {type(value).__name__}")
    s = value.replace("\n", " ").replace("\r", " ")
    for _kind, rx in _PII:
        s = rx.sub("[redacted]", s)
    s = _NAME.sub("[redacted]", s)
    if len(s) > _MAX_STR:
        s = s[: _MAX_STR - 3] + "..."
    return s


class RunLog:
    """One JSONL file per run. Thread-safe within the process."""

    def __init__(self, path=None, run_id=None, heartbeat_s=5.0, echo=False):
        self.run_id = run_id or f"{time.strftime('%Y%m%dT%H%M%S')}-{uuid.uuid4().hex[:6]}"
        self.heartbeat_s = float(heartbeat_s)
        self.echo = echo
        self._lock = threading.Lock()
        self._t0 = time.time()
        self._stage = None
        self._stage_t0 = None
        self._bytes = 0
        self._hb_stop = None
        self._hb_thread = None

        if path is None:
            base = os.environ.get("DESENS_RUNLOG_DIR") or os.path.join(
                os.path.dirname(os.path.abspath(__file__)), "runs")
            os.makedirs(base, exist_ok=True)
            path = os.path.join(base, f"run-{self.run_id}.jsonl")
        elif os.path.isdir(path):
            os.makedirs(path, exist_ok=True)
            path = os.path.join(path, f"run-{self.run_id}.jsonl")
        else:
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self.path = path

    # ------------------------------------------------------------------ write
    def _write(self, stage, event, **fields):
        rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S") + f".{int(time.time()*1000)%1000:03d}",
               "run_id": self.run_id,
               "stage": stage,
               "event": event,
               "elapsed_s": round(time.time() - self._t0, 3)}
        for k, v in fields.items():
            if k in _DENY_KEYS:
                raise ValueError(f"runlog refuses cleartext key {k!r}")
            if not _KEY_RE.match(k):
                raise ValueError(f"bad runlog field name {k!r}")
            rec[k] = redact(v)
        line = json.dumps(rec, ensure_ascii=False)
        with self._lock:
            with open(self.path, "a") as fh:
                fh.write(line + "\n")
        if self.echo:
            print(f"  [{stage}] {event} {rec.get('elapsed_s')}s", flush=True)
        return rec

    def event(self, stage, event, **fields):
        return self._write(stage, event, **fields)

    def progress(self, nbytes=0, **fields):
        """Count bytes received for the stage currently in flight."""
        with self._lock:
            self._bytes += int(nbytes or 0)
        return self._write(self._stage or "unknown", "progress",
                           bytes_so_far=self._bytes, **fields)

    def classified(self, label, **evidence):
        """Terminal record. classify.py reads this as the run's outcome."""
        return self._write(self._stage or "done", "classified", label=label, **evidence)

    # ------------------------------------------------------------------ stages
    def stage(self, name):
        return _Stage(self, name)

    def _begin(self, name):
        self._stage, self._stage_t0, self._bytes = name, time.time(), 0
        self._write(name, "stage_start")
        if self._hb_thread is None:
            self._hb_stop = threading.Event()
            self._hb_thread = threading.Thread(target=self._heartbeat_loop,
                                               name="runlog-heartbeat", daemon=True)
            self._hb_thread.start()

    def _heartbeat_loop(self):
        while not self._hb_stop.wait(self.heartbeat_s):
            stage = self._stage
            if stage is None:
                continue
            elapsed = round(time.time() - (self._stage_t0 or time.time()), 1)
            with self._lock:
                n = self._bytes
            self._write(stage, "heartbeat", stage_elapsed_s=elapsed, bytes=n)

    def _end(self, name, error=None):
        elapsed = round(time.time() - (self._stage_t0 or time.time()), 1)
        with self._lock:
            n = self._bytes
        if error:
            self._write(name, "stage_error", stage_elapsed_s=elapsed,
                        bytes=n, error=str(error)[:200])
        else:
            self._write(name, "stage_end", stage_elapsed_s=elapsed, bytes=n)
        self._stage, self._stage_t0, self._bytes = None, None, 0

    def close(self):
        if self._hb_stop is not None:
            self._hb_stop.set()
            self._hb_stop = None
        self._stage = None

    # ------------------------------------------------------------------ reader
    def records(self):
        if not os.path.exists(self.path):
            return []
        out = []
        with open(self.path) as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        out.append(json.loads(line))
                    except json.JSONDecodeError:
                        out.append({"event": "unparsable", "raw_len": len(line)})
        return out

    def summary(self):
        recs = self.records()
        return {"run_id": self.run_id, "path": self.path, "records": len(recs),
                "heartbeats": sum(1 for r in recs if r.get("event") == "heartbeat"),
                "stages": sorted({r.get("stage") for r in recs if r.get("stage")})}


class _Stage:
    def __init__(self, log, name):
        self.log, self.name = log, name

    def __enter__(self):
        self.log._begin(self.name)
        return self.log

    def __exit__(self, exc_type, exc, tb):
        self.log._end(self.name, error=exc)
        return False
