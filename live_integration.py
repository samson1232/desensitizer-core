"""Live integration: one judge + one generator, both swappable, behind the pipeline.

The topology is fixed — exactly one judge and exactly one LLM — but the models
are not. Both roles come from backends.py and are selected by config.json, so a
replacement model needs no code change here.

What this run now guarantees, beyond the original end-to-end proof:

  * preflight uses a REAL completion probe; a wedged server refuses the run
    before any rate is reported (F3);
  * every run writes an append-only JSONL log with heartbeats every 5 s, so the
    run cannot be described as "hung" without the log naming the stage (F2);
  * every case is classified to exactly one named class (F1, F5);
  * an artifact is accepted only if it ends at a statement boundary and defines
    the requested symbol — compiling is not completeness (F1);
  * a truncation is retried ONCE with a larger budget and both attempts are
    recorded; a second truncation is reported, never looped.

Run:
    python3 live_integration.py
    python3 live_integration.py --config other.json --tasks trivial,hard
"""
import argparse
import json
import os
import resource
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "engine"))

import backends as B                # noqa: E402
import classify as C                # noqa: E402
import completeness as G            # noqa: E402
import keys as K                    # noqa: E402
from pipeline import Pipeline       # noqa: E402
from runlog import RunLog           # noqa: E402

TASKS = {
    "trivial": {
        "symbol": "reverse",
        "prompt": ("Write a Python file answer.py containing a function `reverse(s)` that "
                   "returns the string reversed. Do not explain. Just write the file."),
        "check": "reverse('abc') == 'cba' and reverse('') == ''",
    },
    "medium": {
        "symbol": "word_freq",
        "prompt": ("Write a Python file answer.py containing a function `word_freq(text)` "
                   "returning a dict of word to count, lowercased with punctuation "
                   "stripped. Do not explain. Just write the file."),
        "check": "word_freq('Hello, hello world!') == {'hello': 2, 'world': 1}",
    },
    "hard": {
        "symbol": "toposort",
        "prompt": ("Write a Python file answer.py containing a function `toposort(graph)` "
                   "where graph maps a node to the list of dependencies that must come first. "
                   "Return a deterministic order, include isolated nodes, raise ValueError on "
                   "any cycle including self-loops. Do not explain. Just write the file."),
        "check": "toposort({'a':['b'],'b':[]}) == ['b','a']",
    },
}

# Planted PII: the request a real user would send, which must not leave the host.
PLANT = ("Context: raising this for Alice Smith (alice.smith@corp.co.uk) at 14 Mill Lane, "
         "Cardiff, host web01.internal, card 4111 1111 1111 1111. ")
REAL = ["Alice Smith", "alice.smith@corp.co.uk", "14 Mill Lane, Cardiff",
        "web01.internal", "4111 1111 1111 1111"]

# A retry must ask for the whole file; the failure mode is a stop at the cap.
RETRY_NOTE = (" The previous attempt was cut off mid-file. Write the COMPLETE file, "
              "including every branch and the final statement.")


def run_code_check(path, expr):
    """Execute the artifact and evaluate one assertion in its namespace.

    Compiling is necessary, not sufficient: a truncated generation can compile
    and still be wrong. The child is bounded on wall clock and address space so
    a runaway artifact fails the case instead of killing the harness.
    """
    test = os.path.join(os.path.dirname(path), "check_" + os.path.basename(path))
    with open(test, "w") as fh:
        fh.write("import importlib.util\n"
                 f"spec=importlib.util.spec_from_file_location('m', {path!r})\n"
                 "m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)\n"
                 f"ok=eval({expr!r}, vars(m))\n"
                 "assert ok, 'assertion returned False'\n"
                 "print('OK')\n")

    def _limit():
        try:
            resource.setrlimit(resource.RLIMIT_AS, (4 * 1024 ** 3,) * 2)
        except Exception:
            pass

    try:
        r = subprocess.run([sys.executable, test], capture_output=True, text=True,
                           timeout=120, preexec_fn=_limit)
        return r.returncode == 0, (r.stdout + r.stderr).strip()[:160]
    except subprocess.TimeoutExpired:
        return False, "exec timed out after 120s"


def _restore_safe(p, code):
    try:
        restored, rep = p.restore(code)
        return restored, rep
    except Exception as e:
        return code, {"tokens": [], "unknown_tokens": [], "aliases": [],
                      "unknown_aliases": [], "error": f"{type(e).__name__}: {e}"}


def run(names, cfg, log=None):
    profile = tempfile.mkdtemp(prefix="live_profile_")
    K.load_or_create(K._default_path(profile))
    audit = os.path.join(profile, "audit.jsonl")

    run_id = log.run_id if log else None
    judge = B.build_judge(cfg["judge"])
    gen = B.build_generator(cfg["generator"])
    p = Pipeline(profile, scope_id=f"live-{run_id or '001'}",
                 roster=["Alice Smith"], ground_truth={"staff": []},
                 threshold=cfg["threshold"], audit_path=audit)
    # A free-text address cannot be found by regex; SKILL.md says the caller
    # declares it. Without this line the address leaks and the run reports
    # censored 0/3 — correctly.
    p.censor.gate.mark_sensitive("14 Mill Lane, Cardiff", "address")

    out = {"run_id": run_id, "config": cfg, "judge": judge.name,
           "generator": gen.name, "probes": {}, "tasks": [],
           "log": log.path if log else None}

    # ------------------------------------------------------------- preflight
    with log.stage("preflight") if log else _null():
        pf = B.preflight(judge, gen)
        out["preflight"] = pf
        if log:
            log.event("preflight", "probe",
                      judge_live=bool(pf["judge"].get("live")),
                      judge_raw=pf["judge"].get("raw"),
                      judge_seconds=pf["judge"].get("seconds"),
                      generator_verdict=(pf.get("generator") or {}).get("verdict"),
                      health_ok=((pf.get("generator") or {}).get("health") or {}).get("ok"))
    print(f"=== backends: judge={judge.name} generator={gen.name} ===")
    jp = pf["judge"]
    print(f"  judge      live={jp.get('live')} raw={jp.get('raw')} "
          f"level={jp.get('level')} {jp.get('seconds')}s")
    gv = pf.get("generator") or {}
    print(f"  generator  verdict={gv.get('verdict')} "
          f"probes={[(p_.get('live'), p_.get('seconds')) for p_ in gv.get('probes', [])]}")

    if not pf["ok"]:
        print(f"  REFUSED: {pf['class']} — {pf.get('detail', '')}. "
              "No rates will be reported against this backend.")
        if gv.get("recovery"):
            print(f"  recovery: {gv['recovery']}")
            if log:
                log.event("preflight", "recovery_hint", command=gv["recovery"])
        if log:
            log.classified(pf["class"], why=pf.get("detail"))
            log.close()
        out["refused"] = pf["class"]
        return out, 2

    # ---------------------------------------------------------------- per task
    print("\n=== per task ===")
    for name in names:
        spec = TASKS[name]
        rec = {"case": name}

        # -- censor
        with log.stage("censor") if log else _null():
            try:
                censored, _ = p.scrub(PLANT + spec["prompt"])
                leaks = [v for v in REAL if v in censored]
                rec["censored_ok"] = not leaks
                rec["leaks"] = leaks
                rec["censored_chars"] = len(censored)
                if log:
                    log.event("censor", "scrubbed", chars_in=len(PLANT + spec["prompt"]),
                              chars_out=len(censored), leaks=len(leaks))
            except Exception as e:
                rec["censored_ok"] = False
                rec["censor_blocked"] = True
                rec["censor_reason"] = f"{type(e).__name__}: {e}"[:160]
                if log:
                    log.event("censor", "blocked", error=rec["censor_reason"])
                out["tasks"].append(_finish(rec, log, out))
                continue

        # -- judge
        with log.stage("judge") if log else _null():
            try:
                s = judge.score(censored)
                rec.update({"raw": s["raw"], "level": s["level"], "scale": s["scale"],
                            "judge_seconds": s["seconds"]})
                if log:
                    log.event("judge", "scored", raw=s["raw"], level=s["level"],
                              scale=s["scale"], seconds=s["seconds"])
            except Exception as e:
                rec["judge_error"] = f"{type(e).__name__}: {e}"[:160]
                if log:
                    log.event("judge", "error", error=rec["judge_error"])
                out["tasks"].append(_finish(rec, log, out))
                continue

        # -- route (may legitimately be "unrouted")
        with log.stage("route") if log else _null():
            try:
                rec["route"] = p.route(s["level"])
            except Exception as e:
                rec["route"] = None
                rec["route_error"] = f"{type(e).__name__}: {e}"[:120]
            if log:
                log.event("route", "decided", route=rec["route"],
                          threshold=cfg["threshold"])

        # -- generate, gate, retry once on truncation
        with log.stage("generate") if log else _null():
            attempts = []
            max_tokens = cfg.get("generator", {}).get("max_tokens")
            g = None
            for attempt in (1, 2):
                prompt = censored if attempt == 1 else censored + RETRY_NOTE
                try:
                    g = gen.generate(prompt, workdir=profile, max_tokens=max_tokens)
                except Exception as e:
                    attempts.append({"attempt": attempt, "error": f"{type(e).__name__}: {e}"[:160],
                                     "budget_tokens": max_tokens})
                    if log:
                        log.event("generate", "error", attempt=attempt,
                                  error=attempts[-1]["error"], budget_tokens=max_tokens)
                    break
                code = g.get("code") or ""
                if log:
                    log.progress(nbytes=len(code), attempt=attempt,
                                 transport=g.get("transport"))
                verdict = G.check(code, symbol=spec["symbol"],
                                  finish_reason=g.get("finish"),
                                  completion_tokens=g.get("completion_tokens"),
                                  budget_tokens=g.get("budget_tokens") or max_tokens)
                attempts.append({"attempt": attempt, "bytes": len(code),
                                 "finish_reason": g.get("finish"),
                                 "gate_reasons": verdict["reasons"],
                                 "last_statement": verdict["last_statement"],
                                 "seconds": g.get("seconds"),
                                 "transport": g.get("transport"),
                                 "budget_tokens": g.get("budget_tokens") or max_tokens})
                if log:
                    log.event("generate", "attempt", attempt=attempt, bytes=len(code),
                              finish_reason=g.get("finish"),
                              complete=verdict["complete"],
                              reasons="; ".join(verdict["reasons"])[:160])
                if verdict["complete"]:
                    break
                if attempt == 1:
                    # exactly one retry, with a doubled budget where the
                    # transport has a token lever; the profile transport does
                    # not, and the retry note is what changes the request.
                    max_tokens = (int(max_tokens) * 2) if max_tokens else 4096
                    if log:
                        log.event("generate", "retry", reason="truncated",
                                  new_budget=max_tokens)
            rec["attempts"] = attempts
            if g:
                rec.update({"code": g.get("code") or "", "transport": g.get("transport"),
                            "artifact_path": g.get("artifact_path"),
                            "gen_seconds": g.get("seconds"),
                            "finish_reason": g.get("finish")})
            elif attempts and attempts[0].get("error"):
                rec["gen_error"] = attempts[0]["error"]
            rec["gate"] = G.check(rec.get("code") or "", symbol=spec["symbol"],
                                  finish_reason=rec.get("finish_reason"))
            rec["complete"] = rec["gate"]["complete"]
            rec["gate_reasons"] = rec["gate"]["reasons"]
            rec["last_statement"] = rec["gate"]["last_statement"]

        # -- restore + write + compile + execute (only meaningful if complete)
        if rec.get("complete"):
            with log.stage("restore") if log else _null():
                restored, rrep = _restore_safe(p, rec["code"])
                rec["unknown"] = (len(rrep.get("unknown_tokens", [])) +
                                  len(rrep.get("unknown_aliases", [])))
                rec["restore_error"] = rrep.get("error")
                if log:
                    log.event("restore", "restored", tokens=len(rrep.get("tokens", [])),
                              aliases=len(rrep.get("aliases", [])),
                              unknown=rec["unknown"])

            with log.stage("verify") if log else _null():
                art = os.path.join(profile, f"{name}.py")
                with open(art, "w") as fh:
                    fh.write(restored)
                rec["artifact_bytes"] = len(restored)
                try:
                    import py_compile
                    py_compile.compile(art, doraise=True)
                    rec["compiles"] = True
                except Exception as e:
                    rec["compiles"] = False
                    rec["compile_error"] = str(e)[:120]
                ok, detail = run_code_check(art, spec["check"])
                rec["executes"] = ok
                rec["exec_detail"] = detail
                rec["exit_code"] = 0 if ok else 1
                if log:
                    log.event("verify", "checked", compiles=rec["compiles"],
                              executes=ok, bytes=len(restored),
                              detail=detail[:120])
        else:
            rec["compiles"] = False
            rec["executes"] = False

        out["tasks"].append(_finish(rec, log, out))
        print(f"  {name:<8} class={rec['class']:<16} "
              f"censored={'ok' if rec['censored_ok'] else rec['leaks']} "
              f"level={_fmt(rec.get('level'))} route={rec.get('route')} "
              f"bytes={rec.get('artifact_bytes', len(rec.get('code') or ''))} "
              f"compiles={rec.get('compiles')} executes={rec.get('executes')}")

    p.close()
    out["summary"] = _summary(out["tasks"])
    if log:
        with log.stage("done"):
            log.event("done", "run_end", ok=out["summary"]["ok"],
                      classes=json.dumps(out["summary"]["histogram"]))
        log.close()

    with open(os.path.join(HERE, "live_integration.json"), "w") as fh:
        json.dump(out, fh, indent=2)
    _append_results(out)
    return out, 0 if out["summary"]["ok"] else 1


def _fmt(v):
    return f"{v:.3f}" if isinstance(v, (int, float)) else "—"


class _null:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _finish(rec, log, out):
    """Classify one case, log the terminal record, return the rec."""
    verdict = C.classify(rec)
    rec["class"] = verdict["class"]
    rec["evidence"] = verdict["evidence"]
    rec["detail"] = verdict["detail"]
    if log:
        log.classified(verdict["class"], case=rec.get("case"),
                       why=verdict["detail"][:160],
                       finish_reason=rec.get("finish_reason"),
                       bytes=verdict["evidence"].get("bytes"),
                       last_statement=verdict["evidence"].get("last_statement"),
                       gate=json.dumps(rec.get("gate_reasons") or [])[:160])
    return rec


def _summary(tasks):
    labels = [t["class"] for t in tasks]
    hist = C.histogram(labels)
    ok = bool(tasks) and all(t["class"] in C.CLASSES for t in tasks) \
        and any(t["class"] == "OK" for t in tasks)
    return {"n": len(tasks), "histogram": hist,
            "route": {r: sum(1 for t in tasks if t.get("route") == r)
                      for r in ("local", "frontier", "unrouted")},
            "ok": ok}


def _append_results(out):
    """One JSONL line per run — the evidence for '20 consecutive runs'."""
    import time as _t
    path = os.path.join(HERE, "runs", "live_results.jsonl")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    row = {"ts": _t.strftime("%Y-%m-%dT%H:%M:%S"), "run_id": out.get("run_id"),
           "refused": out.get("refused"),
           "classes": [t["class"] for t in out["tasks"]],
           "routes": [t.get("route") for t in out["tasks"]],
           "summary": out.get("summary")}
    with open(path, "a") as fh:
        fh.write(json.dumps(row) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tasks", default="trivial,medium,hard")
    ap.add_argument("--config", default=os.path.join(HERE, "config.json"))
    ap.add_argument("--threshold", type=float, default=None)
    ap.add_argument("--run-id", default=None)
    a = ap.parse_args()

    cfg = B.load_config(a.config)
    if a.threshold is not None:
        cfg["threshold"] = a.threshold
    names = [t.strip() for t in a.tasks.split(",") if t.strip()]
    unknown = [n for n in names if n not in TASKS]
    if unknown:
        print(f"REFUSED: unknown task(s) {unknown}; known: {sorted(TASKS)}")
        return 2

    log = RunLog(run_id=a.run_id, echo=True)
    out, rc = run(names, cfg, log=log)
    ts = out["tasks"]
    print("\n=== summary ===")
    print(f"  run_id           {out['run_id']}")
    print(f"  log              {out['log']}")
    print(f"  judge            {out['judge']}")
    print(f"  generator        {out['generator']}")
    print(f"  threshold        {cfg['threshold'] if cfg['threshold'] is not None else 'none (unrouted)'}")
    if ts:
        print(f"  tasks            {len(ts)}")
        print(f"  censored clean   {sum(1 for t in ts if t['censored_ok'])}/{len(ts)}")
        print(f"  compiled         {sum(1 for t in ts if t.get('compiles'))}/{len(ts)}")
        print(f"  executed         {sum(1 for t in ts if t.get('executes'))}/{len(ts)}")
        h = out["summary"]["histogram"]
        print("  classes          " + "  ".join(f"{k}={v}" for k, v in h.items() if v))
        r = out["summary"]["route"]
        print(f"  route            local={r['local']} frontier={r['frontier']} "
              f"unrouted={r['unrouted']}")
        lv = [t["level"] for t in ts if isinstance(t.get("level"), (int, float))]
        if lv:
            print(f"  level range      {min(lv):.3f}..{max(lv):.3f}")
        unclassified = [t["case"] for t in ts if t["class"] not in C.CLASSES]
        print(f"  unclassified     {len(unclassified)}")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
