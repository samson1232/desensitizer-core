"""Map any run (or one case of a run) onto exactly one failure class.

The point is that no outcome is unnamed. Before this module a truncated
artifact, a wedged generator and a missing route all arrived as the same thing:
a line of console output that looked like success.

    from classify import classify
    r = classify({"level": 3.4, "route": "local", "code": "...",
                  "compiles": True, "executes": True, "complete": True})
    r["class"]   # "OK"

Each class carries the evidence that produced it. Absent evidence renders as
"not recorded" in ``detail`` — never as a plausible number.

Precedence (first match wins) is deliberate:
  * censoring outranks everything: a leak stops the run before quality matters;
  * an unavailable judge outranks generation: without a score there is no route;
  * a wedge outranks an empty artifact: "empty" from a wedged server is not a
    model failure;
  * TRUNCATED outranks COMPILE_ERROR because a truncated file can compile, and
    reporting COMPILE_ERROR would send the reader hunting for syntax that is fine.
"""
CLASSES = [
    "OK",
    "TRUNCATED",
    "EMPTY",
    "COMPILE_ERROR",
    "EXEC_FAIL",
    "CENSOR_BLOCKED",
    "JUDGE_UNAVAILABLE",
    "GENERATOR_WEDGED",
    "NO_ARTIFACT",
    "ROUTE_UNSET",
]

NOT_RECORDED = "not recorded"


def _first(rec, *keys):
    for k in keys:
        if k in rec and rec[k] is not None:
            return rec[k]
    return None


def _looks_like_timeout(text):
    t = str(text or "").lower()
    return any(w in t for w in ("timed out", "timeout", "timedout", "read timeout"))


def classify(rec):
    """Return {"class": <one of CLASSES>, "evidence": {...}, "detail": str}.

    ``rec`` is a per-case record as written by live_integration (or any dict
    with the same keys). Missing keys are tolerated: an absent fact is recorded
    as absent, not guessed.
    """
    rec = rec or {}
    code = rec.get("code")
    if code is None:
        code = rec.get("restored") or ""
    nbytes = len(code) if isinstance(code, str) else 0

    evidence = {
        "finish_reason": _first(rec, "finish_reason", "finish"),
        "bytes": nbytes,
        "last_statement": rec.get("last_statement"),
        "transport": rec.get("transport"),
        "exit_code": _first(rec, "exit_code", "rc"),
        "gate_reasons": rec.get("gate_reasons"),
        "judge_level": rec.get("level"),
        "route": rec.get("route"),
        "seconds": _first(rec, "gen_seconds", "seconds"),
    }

    def done(label, why):
        ev = {k: (NOT_RECORDED if v is None else v) for k, v in evidence.items()}
        return {"class": label, "evidence": ev, "detail": why}

    # 1. censoring is unconditional
    if rec.get("censor_blocked") or rec.get("censor_ok") is False:
        blocked = rec.get("leaks") or rec.get("censor_reason") or NOT_RECORDED
        return done("CENSOR_BLOCKED", f"censor refused the payload: {blocked}")

    # 2. a judge that did not answer
    if rec.get("judge_error") or (rec.get("needs_judge", True) and rec.get("level") is None):
        return done("JUDGE_UNAVAILABLE",
                    f"judge produced no score: {rec.get('judge_error') or NOT_RECORDED}")

    # 3. a generator that accepts connections but never answers
    if rec.get("wedge") is True or str(rec.get("verdict", "")).lower() == "wedged":
        return done("GENERATOR_WEDGED",
                    "health answered but completion probe failed repeatedly")
    if rec.get("gen_error") and _looks_like_timeout(rec["gen_error"]):
        return done("GENERATOR_WEDGED", f"generation timed out: {rec['gen_error']}")

    # 4. a decision the pipeline needed and did not have
    if rec.get("needs_route", True) and rec.get("route") is None:
        return done("ROUTE_UNSET", "no route declared; case was never dispatched")

    # 5. nothing came back at all
    transport = rec.get("transport")
    if not nbytes:
        if transport in (None, "none"):
            return done("NO_ARTIFACT", "generator produced no file and no code")
        return done("EMPTY", f"transport {transport!r} returned zero content bytes")

    # 6. truncation — checked BEFORE compile: a truncated file can compile
    if rec.get("complete") is False or evidence["finish_reason"] == "length":
        reasons = rec.get("gate_reasons") or []
        why = ("finish_reason=length" if evidence["finish_reason"] == "length"
               else "; ".join(reasons) or "completeness gate rejected the artifact")
        return done("TRUNCATED", why)

    # 7. syntax, then behaviour
    if rec.get("compiles") is False:
        return done("COMPILE_ERROR", rec.get("compile_error") or "py_compile failed")
    if rec.get("executes") is False:
        return done("EXEC_FAIL", rec.get("exec_detail") or "artifact assertion failed")

    return done("OK", "complete, compiled and executed")


def histogram(labels):
    """Counts for a list of class labels, all ten present (zeros included)."""
    h = {c: 0 for c in CLASSES}
    for lab in labels:
        h[lab] = h.get(lab, 0) + 1
    return h


def classify_log(records):
    """Read a runlog record list and return the terminal class, if any."""
    for r in reversed(records or []):
        if r.get("event") == "classified" and r.get("label") in CLASSES:
            return r["label"]
    return None
