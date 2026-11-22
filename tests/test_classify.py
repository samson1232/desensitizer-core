"""One synthetic control per failure class.

A classifier never shown to emit TRUNCATED is not a classifier. Each control
below is the minimal record that must produce exactly that label, plus a few
precedence checks where two defects are present at once.
"""
import os
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

import classify as C

fails = []


def check(cond, label, detail=""):
    print(f"[{'PASS' if cond else 'FAIL'}] {label}" + (f"\n        {detail}" if detail else ""))
    if not cond:
        fails.append(label)


def label(rec):
    return C.classify(rec)["class"]


GOOD = {"code": "def f():\n    return 1\n", "transport": "file", "route": "local",
        "level": 3.0, "compiles": True, "executes": True, "complete": True,
        "finish_reason": "stop", "exit_code": 0}

CONTROLS = [
    ("OK", dict(GOOD)),
    ("TRUNCATED", dict(GOOD, code="def f():\n    for dep", complete=False,
                       gate_reasons=["does not parse (SyntaxError line 2)"] )),
    ("EMPTY", dict(GOOD, code="", transport="api")),
    ("COMPILE_ERROR", dict(GOOD, compiles=False, compile_error="SyntaxError: bad")),
    ("EXEC_FAIL", dict(GOOD, executes=False, exec_detail="assertion returned False")),
    ("CENSOR_BLOCKED", dict(GOOD, censor_ok=False, leaks=["Alice Smith"])),
    ("JUDGE_UNAVAILABLE", dict(GOOD, level=None, judge_error="ConnectionRefusedError")),
    ("GENERATOR_WEDGED", dict(GOOD, wedge=True)),
    ("NO_ARTIFACT", dict(GOOD, code="", transport="none", artifact_path=None)),
    ("ROUTE_UNSET", dict(GOOD, route=None)),
]

print("=== 1. every class has a control that produces it ===")
seen = set()
for want, rec in CONTROLS:
    got = label(rec)
    seen.add(got)
    check(got == want, f"{want} control -> {got}", "" if got == want else f"want {want}")
check(seen == set(C.CLASSES), "all ten classes exercised",
      f"missing: {sorted(set(C.CLASSES) - seen)}")

print("\n=== 2. precedence: truncation outranks compile ===")
# The measured bug: a file cut mid-statement that still compiles. If the
# classifier reports COMPILE_ERROR here it sends the reader hunting syntax.
rec = dict(GOOD, complete=False, compiles=False, finish_reason="length")
check(label(rec) == "TRUNCATED", "complete=False + compiles=False -> TRUNCATED")

print("\n=== 3. finish_reason=length is truncation on its own ===")
check(label(dict(GOOD, finish_reason="length")) == "TRUNCATED",
      "finish_reason=length -> TRUNCATED even if complete is absent")
check(label(dict(GOOD, finish_reason="length", code="", transport="api")) == "EMPTY",
      "length with zero content -> EMPTY (F5 shape), not TRUNCATED")

print("\n=== 4. evidence is carried, and absence is not invented ===")
v = C.classify(dict(GOOD, complete=False, finish_reason="length", code="x = 1\n",
                    last_statement="x = 1"))
check(v["evidence"]["finish_reason"] == "length", "finish_reason in evidence")
check(v["evidence"]["bytes"] == 6, "byte count in evidence", str(v["evidence"]["bytes"]))
check(v["evidence"]["last_statement"] == "x = 1", "last statement in evidence")
v2 = C.classify({"code": "x=1\n", "compiles": True, "executes": True, "complete": True,
                 "route": "local", "level": 2})
check(v2["evidence"]["exit_code"] == C.NOT_RECORDED,
      "absent exit code renders as 'not recorded'", str(v2["evidence"]["exit_code"]))

print("\n=== 5. a wedged generator outranks an empty artifact ===")
check(label(dict(GOOD, code="", transport="api", wedge=True)) == "GENERATOR_WEDGED",
      "wedge + empty content -> GENERATOR_WEDGED")
check(label(dict(GOOD, gen_error="Read timed out")) == "GENERATOR_WEDGED",
      "timeout error -> GENERATOR_WEDGED")

print("\n=== 6. histogram always has all ten keys ===")
h = C.histogram(["OK", "OK", "TRUNCATED"])
check(h["OK"] == 2 and h["TRUNCATED"] == 1, "counts correct")
check(len(h) == 10 and h["EXEC_FAIL"] == 0, "zeros present, not omitted", str(h))

print("\n=== 7. classify_log reads the terminal record ===")
check(C.classify_log([{"event": "classified", "label": "EMPTY"}]) == "EMPTY",
      "terminal label read")
check(C.classify_log([]) is None, "no terminal record -> None")

print()
if fails:
    print(f"FAILED ({len(fails)}):")
    for f in fails:
        print("  -", f)
    sys.exit(1)
print(f"CLASSIFY: {len(C.CLASSES)} classes, {len(CONTROLS)} controls, precedence held")
