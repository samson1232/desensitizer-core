"""Router calibration: measure whether judge separation beats judge noise.

A threshold is a decision only if the signal moves more than the noise. The
prior 4.2 was carried on faith: measured levels 3.24-3.88 with a run-to-run
swing (~0.2) the same size as the whole trivial->hard spread (0.637).

This harness runs a 12-task corpus (4 genuinely trivial, 4 medium, 4 genuinely
hard) three times each, and writes:

    calibration.json   machine-readable; load_threshold() reads it
    calibration.md     the table a human reads

Rule: threshold is set ONLY if separation >= 3 * pooled within-group SD.
Otherwise ``threshold`` is null and the pipeline routes "unrouted". A router
that never fires and a router that fires at random are both worse than one that
says it cannot tell.

    python3 calibration.py                 # 36 judge calls, ~12-15 min
    python3 calibration.py --runs 3 --json
"""
import argparse
import json
import math
import os
import statistics
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "engine"))

import backends as B  # noqa: E402
import keys as K  # noqa: E402
from pipeline import Pipeline  # noqa: E402

# The router scores CENSORED tasking. A calibration corpus without the PII that
# production carries measures a different distribution: the same toposort task
# scored 4.591 bare and 3.975 with the planted context. Calibration therefore
# runs through the same scrubber, with the same plant, by default.
PLANT = ("Context: raising this for Alice Smith (alice.smith@corp.co.uk) at 14 Mill Lane, "
         "Cardiff, host web01.internal, card 4111 1111 1111 1111. ")

# 12 tasks spanning the range the router must separate. Texts are the tasking a
# caller would send; no PII, so nothing needs censoring for calibration.
TASKS = [
    # ---- genuinely trivial: one line, one lookup, boilerplate
    ("easy-01", "easy", "Write a Python function `add(a, b)` that returns the sum of two numbers."),
    ("easy-02", "easy", "Write a Python function `reverse(s)` that returns the string reversed."),
    ("easy-03", "easy", "Write a Python function `is_even(n)` that returns True when n is even."),
    ("easy-04", "easy", "Write a Python file containing the constant PI and a function `circle_area(r)`."),
    # ---- medium: one real function, modest state
    ("med-01", "medium", "Write `word_freq(text)` returning a dict of lowercased words to counts, "
                         "punctuation stripped."),
    ("med-02", "medium", "Write `parse_ini(text)` that parses sections and key=value pairs into a "
                         "nested dict, ignoring comments."),
    ("med-03", "medium", "Write `merge_intervals(pairs)` that merges overlapping integer intervals "
                         "and returns them sorted."),
    ("med-04", "medium", "Write a `BankAccount` class with deposit, withdraw and balance, raising "
                         "ValueError on overdraft."),
    # ---- hard: careful algorithm, many invariants
    ("hard-01", "hard", "Write `toposort(graph)` where graph maps a node to its dependencies. Return "
                        "a deterministic order including isolated nodes, and raise ValueError on any "
                        "cycle including self-loops."),
    ("hard-02", "hard", "Write `dijkstra(graph, start)` for a weighted graph with non-negative edges. "
                        "Return shortest distances to every reachable node, and raise ValueError on a "
                        "negative edge."),
    ("hard-03", "hard", "Write a thread-safe bounded blocking queue class with put/get, timeout "
                        "support, and correct shutdown semantics under concurrent producers and "
                        "consumers."),
    ("hard-04", "hard", "Write `tokenize_expr(s)` for arithmetic with + - * / parentheses and unary "
                        "minus, producing an AST that respects precedence and rejects malformed input "
                        "with a precise error position."),
]

MIN_RATIO = 3.0
# A deterministic judge gives SD 0, which makes the ratio undefined (not
# infinite evidence). In that case the group gap must still clear a practical
# floor: under one level on a 1..10 scale is not a routing signal.
MIN_SEPARATION = 1.0


def _sd(xs):
    return statistics.stdev(xs) if len(xs) > 1 else 0.0


def compute(results, runs_per_task):
    """results: {task_name: [levels]}. Returns the calibration dict."""
    rows = []
    for name, group, _text in TASKS:
        levels = results.get(name, [])
        rows.append({"name": name, "group": group, "runs": levels,
                     "n": len(levels),
                     "mean": round(statistics.mean(levels), 3) if levels else None,
                     "sd": round(_sd(levels), 3) if len(levels) > 1 else None})

    easy = [r["mean"] for r in rows if r["group"] == "easy" and r["mean"] is not None]
    hard = [r["mean"] for r in rows if r["group"] == "hard" and r["mean"] is not None]
    sds = [r["sd"] for r in rows if r["sd"] is not None]

    if not easy or not hard or not sds:
        return {"measured": _now(), "runs_per_task": runs_per_task, "tasks": rows,
                "calibrated": False, "threshold": None, "verdict": "INSUFFICIENT",
                "reason": "not every group produced scores"}

    mean_easy = statistics.mean(easy)
    mean_hard = statistics.mean(hard)
    separation = mean_hard - mean_easy
    # Pooled within-task SD: the noise the router has to see over.
    noise = math.sqrt(sum(s * s for s in sds) / len(sds))

    if noise > 0:
        ratio = separation / noise
        calibrated = ratio >= MIN_RATIO and separation > 0
        reason = ("separation >= 3x noise; threshold is the group midpoint"
                  if calibrated else
                  f"separation/noise {ratio:.2f} < {MIN_RATIO}; router must report unrouted")
    else:
        # Deterministic judge on identical input: the ratio is undefined. Fall
        # back to a declared practical floor instead of dividing by zero and
        # calling the result infinite evidence.
        ratio = None
        calibrated = separation >= MIN_SEPARATION
        reason = (f"within-task SD 0 (deterministic for identical input); "
                  f"separation {separation:.3f} >= practical floor {MIN_SEPARATION}"
                  if calibrated else
                  f"within-task SD 0 and separation {separation:.3f} < "
                  f"practical floor {MIN_SEPARATION}; router must report unrouted")

    threshold = round((mean_easy + mean_hard) / 2.0, 3) if calibrated else None

    return {
        "measured": _now(),
        "runs_per_task": runs_per_task,
        "tasks": rows,
        "groups": {"easy": {"n": len(easy), "mean": round(mean_easy, 3),
                            "sd": round(_sd(easy), 3)},
                   "hard": {"n": len(hard), "mean": round(mean_hard, 3),
                            "sd": round(_sd(hard), 3)}},
        "separation": round(separation, 3),
        "noise_sd": round(noise, 3),
        "separation_over_noise": round(ratio, 3) if ratio is not None else None,
        "min_ratio": MIN_RATIO,
        "min_separation": MIN_SEPARATION,
        "calibrated": calibrated,
        "threshold": threshold,
        "verdict": "CALIBRATED" if calibrated else "UNROUTED",
        "reason": reason,
    }


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def markdown(cal):
    lines = ["# Router calibration", "",
             f"Measured: {cal.get('measured')}  ·  runs per task: {cal.get('runs_per_task')}"
             f"  ·  corpus: {cal.get('mode', 'not recorded')}",
             f"Verdict: **{cal.get('verdict')}** — {cal.get('reason')}", "",
             "| task | group | run 1 | run 2 | run 3 | mean | SD |",
             "|---|---|---|---|---|---|---|"]
    for r in cal.get("tasks", []):
        runs = r.get("runs") or []
        cells = [f"{v:.3f}" if isinstance(v, (int, float)) else "—" for v in runs]
        cells += ["—"] * (3 - len(cells))
        lines.append(f"| {r['name']} | {r['group']} | " + " | ".join(cells[:3]) +
                     f" | {r['mean'] if r['mean'] is not None else '—'} "
                     f"| {r['sd'] if r['sd'] is not None else '—'} |")
    g = cal.get("groups") or {}
    lines += ["",
              f"Easy group mean: {g.get('easy', {}).get('mean', '—')}  ·  "
              f"Hard group mean: {g.get('hard', {}).get('mean', '—')}",
              f"Separation: {cal.get('separation', '—')}  ·  "
              f"pooled within-task SD: {cal.get('noise_sd', '—')}  ·  "
              f"ratio: {cal.get('separation_over_noise', '—')}",
              "",
              (f"Threshold: **{cal.get('threshold')}** (midpoint, justified)" if cal.get("threshold")
               else "Threshold: **none** — router returns `unrouted` and the pipeline says so."),
              "",
              "A passing argument is separation >= 3x noise. Below that the numbers are"
              " reported and no side is picked."]
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--config", default=os.path.join(HERE, "config.json"))
    ap.add_argument("--out", default=os.path.join(HERE, "calibration.json"))
    ap.add_argument("--md", default=os.path.join(HERE, "calibration.md"))
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--only", default="", help="comma-separated task names (debug)")
    ap.add_argument("--no-censor", action="store_true",
                    help="score bare tasking (NOT production-shaped; for comparison only)")
    a = ap.parse_args()

    cfg = B.load_config(a.config)
    judge = B.build_judge(cfg["judge"])
    only = {s.strip() for s in a.only.split(",") if s.strip()}
    tasks = [t for t in TASKS if not only or t[0] in only]

    prof = tempfile.mkdtemp(prefix="cal_profile_")
    K.load_or_create(K._default_path(prof))
    pipe = Pipeline(prof, scope_id="calibration", roster=["Alice Smith"],
                    ground_truth={"staff": []})
    pipe.censor.gate.mark_sensitive("14 Mill Lane, Cardiff", "address")

    jp = judge.probe()
    if not jp.get("live"):
        print(f"REFUSED: judge not answering ({jp.get('error', 'no score')}). "
              "Calibration against a dead judge is meaningless.")
        return 2

    results = {}
    started = time.time()
    for i, (name, group, text) in enumerate(tasks, 1):
        tasking = text if a.no_censor else PLANT + text
        if not a.no_censor:
            tasking, _ = pipe.scrub(tasking)
        levels = []
        for k in range(a.runs):
            try:
                s = judge.score(tasking)
                levels.append(round(s["level"], 3))
                print(f"  [{i:>2}/{len(tasks)}] {name} run {k+1}/{a.runs}: "
                      f"raw={s['raw']:.3f} level={s['level']:.3f} ({s['seconds']}s)",
                      flush=True)
            except Exception as e:
                print(f"  [{i:>2}/{len(tasks)}] {name} run {k+1}/{a.runs}: "
                      f"ERROR {type(e).__name__}: {e}", flush=True)
        results[name] = levels

    cal = compute(results, a.runs)
    cal["elapsed_s"] = round(time.time() - started, 1)
    cal["judge"] = judge.name
    cal["mode"] = "bare (comparison only)" if a.no_censor else "censored, planted PII"

    with open(a.out, "w") as fh:
        json.dump(cal, fh, indent=2)
    with open(a.md, "w") as fh:
        fh.write(markdown(cal))

    if a.json:
        print(json.dumps(cal, indent=2))
    else:
        print()
        print(markdown(cal))
        print(f"wrote {a.out} and {a.md} in {cal['elapsed_s']}s")
    return 0 if cal.get("verdict") != "INSUFFICIENT" else 1


if __name__ == "__main__":
    raise SystemExit(main())
