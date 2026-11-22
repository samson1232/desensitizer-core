"""Router controls: the router is valid or honest, never merely decisive.

Two things are proved here:
  1. the mechanism: explicit threshold routes, missing threshold returns
     "unrouted", corrupt scores block instead of defaulting to local;
  2. the rule: calibration.compute() only certifies a threshold when
     separation >= 3x noise — tested on synthetic numbers with a known answer,
     so the rule is checked without 36 live judge calls.
"""
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "engine"))

import calibration as CAL            # noqa: E402
import keys as K                    # noqa: E402
from pipeline import Pipeline, PipelineBlocked, load_threshold  # noqa: E402

fails = []


def ck(cond, label, detail=""):
    print(f"[{'PASS' if cond else 'FAIL'}] {label}" + (f"\n        {detail}" if detail else ""))
    if not cond:
        fails.append(label)


TMP = tempfile.mkdtemp(prefix="router_test_")
K.load_or_create(K._default_path(TMP))
ROSTER = ["Alice Smith"]
GT = {"staff": []}

print("=== 1. no calibrated threshold -> unrouted, not a guess ===")
p_none = Pipeline(TMP, scope_id="r-none", roster=ROSTER, ground_truth=GT)
ck(p_none.route(9.9) == "unrouted", "high score is unrouted, not frontier")
ck(p_none.route(1.0) == "unrouted", "low score is unrouted, not local")

print("\n=== 2. an explicit threshold still routes (mechanism intact) ===")
p = Pipeline(TMP, scope_id="r-42", roster=ROSTER, ground_truth=GT, threshold=4.2)
ck(p.route(9.0) == "frontier", "9.0 -> frontier")
ck(p.route(1.0) == "local", "1.0 -> local")
ck(p.route(4.2) == "frontier", "boundary is >=")
ck(p.route(4.19) == "local", "just below -> local")

print("\n=== 3. corrupt scores block; they never fall to local ===")
for label, bad in [("None", None), ("NaN", float("nan")),
                   ("inf", float("inf")), ("string", "high")]:
    try:
        p.route(bad)
        ck(False, f"{label} blocked")
    except PipelineBlocked:
        ck(True, f"{label} blocked")
try:
    p_none.route(None)
    ck(False, "None blocked even with no threshold")
except PipelineBlocked:
    ck(True, "None blocked even with no threshold")

print("\n=== 4. load_threshold refuses to carry a number on faith ===")
def write(d):
    path = os.path.join(TMP, f"cal-{len(os.listdir(TMP))}.json")
    with open(path, "w") as fh:
        json.dump(d, fh)
    return path

ck(load_threshold(None) is None, "no file -> None")
ck(load_threshold(write({"threshold": 4.2, "calibrated": False,
                         "separation_over_noise": 9.0})) is None,
   "uncalibrated number ignored")
ck(load_threshold(write({"threshold": 4.2, "calibrated": True,
                         "separation_over_noise": 2.9})) is None,
   "ratio below 3 ignored")
ck(load_threshold(write({"threshold": 5.5, "calibrated": True,
                         "separation_over_noise": 3.0})) == 5.5,
   "ratio 3.0 honoured")
ck(load_threshold(write({"threshold": 5.5, "calibrated": True})) is None,
   "missing ratio ignored")
ck(load_threshold(write({})) is None, "empty file -> None")
ck(load_threshold(write({"calibrated": True, "threshold": 4.3,
                         "separation_over_noise": None, "separation": 1.258,
                         "min_separation": 1.0})) == 4.3,
   "deterministic-judge calibration honoured on its declared floor")
ck(load_threshold(write({"calibrated": True, "threshold": 4.3,
                         "separation_over_noise": None, "separation": 0.5,
                         "min_separation": 1.0})) is None,
   "zero-noise but sub-floor separation refused")

import backends as B  # noqa: E402
ck(B._calibrated_threshold(write({"calibrated": True, "threshold": 4.3,
                                  "separation_over_noise": 6.2})) == 4.3,
   "config loader honours a proven calibration")
ck(B._calibrated_threshold(write({"threshold": 4.2})) != 4.2,
   "config loader ignores an unproven threshold (may fall back to package file)")

print("\n=== 5. the calibration rule itself: separation >= 3x noise ===")
def synthetic(easy_vals, hard_vals):
    """Give every task a tiny deterministic spread around its group mean."""
    res = {}
    for name, group, _t in CAL.TASKS:
        base = easy_vals if group == "easy" else (hard_vals if group == "hard" else
                                                  (easy_vals + hard_vals) / 2)
        res[name] = [base - 0.05, base, base + 0.05]
    return CAL.compute(res, 3)

wide = synthetic(3.0, 8.0)            # separation 5.0, noise ~0.05
ck(wide["calibrated"] is True, "wide separation calibrates", str(wide["separation_over_noise"]))
ck(wide["threshold"] is not None, "threshold set", str(wide["threshold"]))
ck(abs(wide["threshold"] - 5.5) < 0.02, "threshold is the group midpoint",
   str(wide["threshold"]))
ck(wide["verdict"] == "CALIBRATED", "verdict CALIBRATED")

noisy = synthetic(3.4, 3.8)           # separation 0.4, noise tiny -> still calibrates
ck(noisy["calibrated"] is True, "small but clean separation still calibrates",
   str(noisy["separation_over_noise"]))

# Now add genuine run-to-run noise to the measured levels, matching the
# measured failure: spread comparable to the separation.
import random
random.seed(7)
res = {}
for name, group, _t in CAL.TASKS:
    base = 3.4 if group == "easy" else (3.6 if group == "medium" else 3.8)
    res[name] = [round(base + random.uniform(-0.35, 0.35), 3) for _ in range(3)]
flat = CAL.compute(res, 3)
ck(flat["calibrated"] is False, "noise comparable to separation -> NOT calibrated",
   f"ratio={flat['separation_over_noise']} sep={flat['separation']} noise={flat['noise_sd']}")
ck(flat["threshold"] is None, "threshold withheld")
ck(flat["verdict"] == "UNROUTED", "verdict UNROUTED")

print("\n=== 5b. deterministic judge: ratio is undefined, floor decides ===")
det = {}
for name, group, _t in CAL.TASKS:
    base = 3.5 if group == "easy" else (4.1 if group == "medium" else 4.8)
    det[name] = [base, base, base]
dcal = CAL.compute(det, 3)
ck(dcal["noise_sd"] == 0.0, "zero within-task SD recorded as 0.0")
ck(dcal["separation_over_noise"] is None, "ratio is None, not 'inf'")
ck(dcal["calibrated"] is True, "separation 1.3 clears the 1.0 floor")
ck(dcal["threshold"] == 4.15, "threshold is still the group midpoint", str(dcal["threshold"]))
dcal2 = CAL.compute({n: ([3.5, 3.5, 3.5] if g == "easy" else
                          [4.0, 4.0, 4.0] if g == "hard" else [3.75] * 3)
                     for n, g, _t in CAL.TASKS}, 3)
ck(dcal2["calibrated"] is False, "zero-noise but 0.5 separation -> UNROUTED",
   str(dcal2["reason"]))

print("\n=== 6. the calibration table has 12 tasks x 3 runs ===")
ck(len(wide["tasks"]) == 12, "12 tasks", str(len(wide["tasks"])))
ck(all(len(t["runs"]) == 3 for t in wide["tasks"]), "3 runs per task")
groups = {t["group"] for t in wide["tasks"]}
ck(groups == {"easy", "medium", "hard"}, "all three groups present", str(groups))
md = CAL.markdown(wide)
ck(md.count("|") > 40 and "Threshold" in md, "markdown table renders", f"{len(md)} chars")

print()
if fails:
    print(f"FAILED ({len(fails)}):")
    for f in fails:
        print("  -", f)
    sys.exit(1)
print("ROUTER: unrouted by default, threshold only on evidence")
