"""Enterprise PII pipeline — single entry point.

Two scrubbing layers, deliberately different, because they have different
threat models and pretending otherwise is how systems leak:

  LAYER 1  scrub()    outbound text (prompts, files, egress)
           HMAC tokens, fail-closed, canary-tested detectors.
           Token = <kind>:<26 x base32>. Unlinkable without the key, stable
           within a session so the far side can still group by token.

  LAYER 2  alias()    artifacts that must come back
           Sequential, human-readable aliases (person_ID_1). A reviewer can
           read the aliased artifact; restore() is a strict dict lookup.

  restore()           reverses BOTH schemes in one pass, exactly.
  route()             difficulty -> local|frontier. A pure function of
                      (score, threshold). The model never chooses its route.
  audit()             append-only JSONL. Counts and aliases only — never a
                      real value. The audit log is safe to ship.

Invariants the tests enforce:
  1. Nothing outbound survives scrubbing (no real value in the output).
  2. restore(scrub(x)) == x and restore(alias(x)) == x, byte for byte.
  3. Unknown tokens/aliases are left untouched and reported, never guessed.
  4. Every alias is scoped; one scope cannot resolve another's.
  5. route() is total and deterministic; no model input.
  6. A dead detector fails closed (CensorPass self-test).
"""
import json
import math
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "engine"))

import censor_pass as CP          # noqa: E402
import alias_bridge as AB         # noqa: E402

DEFAULT_THRESHOLD = None   # unrouted until a calibration proves separation > 3x noise

# <kind>:<26 chars of base32> as emitted by ScrubGate
_TOKEN_RE = re.compile(r"(?<![\w:])([a-z][a-z0-9_]*):([A-Z2-7]{26})(?![\w:])")


class PipelineBlocked(Exception):
    """The pipeline refused to continue. Fail closed; never deliver."""

    def __init__(self, stage, reason):
        super().__init__(f"{stage}: {reason}")
        self.stage = stage
        self.reason = reason


class Pipeline:
    """One task, one scope, one audit trail."""

    def __init__(self, profile_dir, scope_id=None, roster=None, ground_truth=None,
                 threshold=None, audit_path=None, world_dir=None):
        self.scope_id = scope_id or f"task-{int(time.time()*1000)}"
        self.threshold = DEFAULT_THRESHOLD if threshold is None else float(threshold)
        self.audit_path = audit_path

        gt, names = (ground_truth, roster)
        if world_dir:
            gt, names = CP.load_world(world_dir)

        # Layer 1: outbound scrubber. Raises on a dead detector.
        self.censor = CP.CensorPass(profile_dir, roster_names=names, ground_truth=gt)
        # Layer 2: artifact aliasing, scoped to this task.
        self.aliases = AB.AliasScope(self.scope_id)

        # Addresses and other free text cannot be found by regex; the caller
        # declares them. This is the documented contract, not a hack.
        for s in (gt or {}).get("staff", []):
            if s.get("addr"):
                self.censor.gate.mark_sensitive(s["addr"], "address")

    # ---------------------------------------------------------------- layer 1
    def scrub(self, text):
        """Censor outbound text. Returns (censored, report).

        Raises PipelineBlocked if the pass refuses the payload.
        """
        try:
            out, rep = self.censor.censor_prompt(text)
        except CP.CensorFailure as e:
            self.audit(event="scrub_blocked", reason=str(e)[:200])
            raise PipelineBlocked("scrub", str(e))
        self.audit(event="scrub", kinds=_kinds(rep))
        return out, rep

    # ---------------------------------------------------------------- layer 2
    def alias(self, text, hosts=None):
        """Alias an artifact so it can be restored later. Returns (text, report)."""
        if hosts:
            out, rep = self.aliases.censor_with_seeds(text, hosts)
        else:
            out, rep = self.aliases.censor(text)
        self.audit(event="alias", count=rep["count"],
                   aliases=[r["alias"] for r in rep["replaced"]])
        return out, rep

    # ---------------------------------------------------------------- restore
    def restore(self, text):
        """Reverse both schemes, single pass, strict. Returns (text, report).

        Unknown tokens and aliases are left as-is and listed. Nothing is guessed.
        """
        restored_tokens, unknown_tokens = [], []

        def _tok(m):
            kind, t = m.group(1), m.group(2)
            try:
                v = self.censor.space.value_for(t)
            except KeyError:
                unknown_tokens.append(f"{kind}:{t}")
                return m.group(0)
            restored_tokens.append(f"{kind}:{t}")
            return v

        out = _TOKEN_RE.sub(_tok, text)
        out, alias_report = self.aliases.restore(out)

        report = {"tokens": restored_tokens,
                  "unknown_tokens": unknown_tokens,
                  "aliases": alias_report["restored"],
                  "unknown_aliases": alias_report["unknown"]}
        self.audit(event="restore", tokens=len(restored_tokens),
                   aliases=len(alias_report["restored"]),
                   unknown=len(unknown_tokens) + len(alias_report["unknown"]))
        return out, report

    # ---------------------------------------------------------------- routing
    def route(self, score):
        """Pure function. The model never chooses its own route.

        Returns "unrouted" when no threshold has been justified by calibration.
        That is an honest answer, not a failure: a threshold whose noise equals
        its signal looks like a decision and is not one.
        """
        if score is None:
            raise PipelineBlocked("route", "no difficulty score; refusing to guess")
        try:
            v = float(score)
        except (TypeError, ValueError):
            raise PipelineBlocked("route", f"non-numeric score {score!r}")
        if not math.isfinite(v):
            raise PipelineBlocked("route", f"non-finite score {score!r}")
        if self.threshold is None:
            return "unrouted"
        return "frontier" if v >= self.threshold else "local"

    def decide(self, text, score):
        """Full decision for one unit of work, with the censored tasking."""
        censored, rep = self.scrub(text)
        return {"scope_id": self.scope_id,
                "route": self.route(score),
                "score": score,
                "threshold": self.threshold,
                "tasking": censored,          # safe to send
                "kinds": _kinds(rep)}

    # ----------------------------------------------------------------- audit
    def audit(self, **record):
        """Append one JSONL record. Aliases and counts only — never a value."""
        if not self.audit_path:
            return
        rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
               "scope_id": self.scope_id}
        rec.update(record)
        with open(self.audit_path, "a") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")

    # ------------------------------------------------------------- lifecycle
    def pivot_table(self):
        """The sensitive store. Never persist, never send to a model."""
        return self.aliases.export()

    def close(self):
        """Destroy the in-memory maps. Call when the task is done."""
        self.aliases = AB.AliasScope(self.scope_id)
        self.censor.space._t2v.clear()
        self.censor.space._v2t.clear()
        self.audit(event="closed")


def _kinds(rep):
    """Normalise a CensorPass report into {kind: count} without any values."""
    counts = {}
    for item in getattr(rep, "hits", []) or []:
        k = item[0] if isinstance(item, (tuple, list)) else str(item)
        counts[k] = counts.get(k, 0) + 1
    for item in getattr(rep, "literals", []) or []:
        k = item[0] if isinstance(item, (tuple, list)) else str(item)
        counts[k] = counts.get(k, 0) + 1
    return counts


def load_threshold(path=None):
    """Threshold from a calibration file, or None (unrouted).

    A number is honoured only when the file proves it: ``calibrated: true`` and
    ``separation_over_noise >= 3.0``. The previous 4.2 default is deliberately
    NOT a fallback — it was never compared against run-to-run noise.
    """
    if not path:
        return None
    try:
        with open(path) as fh:
            d = json.load(fh)
    except Exception:
        return None
    if not d.get("calibrated"):
        return None
    try:
        thr = float(d["threshold"])
    except (KeyError, TypeError, ValueError):
        return None
    ratio = d.get("separation_over_noise")
    if ratio is None:
        # Deterministic judge: the ratio is undefined, so the calibration fell
        # back to its declared minimum separation. Honour it only if that
        # number is present and clears the floor.
        try:
            sep = float(d["separation"])
            floor = float(d.get("min_separation", 1.0))
        except (KeyError, TypeError, ValueError):
            return None
        return thr if sep >= floor else None
    try:
        ratio = float(ratio)
    except (TypeError, ValueError):
        return None
    return thr if ratio >= 3.0 else None
