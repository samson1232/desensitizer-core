"""Controls for the completeness gate.

Two controls matter most:
  * the truncated artifact MUST be rejected (and must still compile — that is
    the whole failure);
  * a correct artifact MUST NOT be rejected (or the gate is just a failure
    generator and gets ripped out).

The first test proves the failure is real before the gate is used on it.
"""
import os
import py_compile
import sys
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

import completeness as G
from completeness import ends_at_boundary, symbol_present

fails = []


def ck(cond, label, detail=""):
    print(f"[{'PASS' if cond else 'FAIL'}] {label}" + (f"\n        {detail}" if detail else ""))
    if not cond:
        fails.append(label)


TRUNCATED = "def toposort(graph):\n    order = []\n    for node in graph:\n        for dep"

# This one compiles: the cut lands after a complete statement but the function
# is still not finished. The gate must catch it by request evidence
# (finish_reason) — text alone cannot always tell.
TRUNCATED_COMPILES = ("def toposort(graph):\n"
                      "    order = []\n"
                      "    seen = set()\n"
                      "    for node in graph:\n"
                      "        visit(node)\n")

GOOD = ("def toposort(graph):\n"
        "    order, state = [], {}\n"
        "    def visit(n):\n"
        "        if state.get(n) == 1:\n"
        "            raise ValueError('cycle')\n"
        "        if state.get(n) == 2:\n"
        "            return\n"
        "        state[n] = 1\n"
        "        for dep in graph.get(n, []):\n"
        "            visit(dep)\n"
        "        state[n] = 2\n"
        "        order.append(n)\n"
        "    for n in sorted(graph):\n"
        "        visit(n)\n"
        "    return order\n")


print("=== 0. the failure is real: the truncated file fails or compiles ===")
tmp = tempfile.mkdtemp(prefix="gate_")
p = os.path.join(tmp, "t.py")
open(p, "w").write(TRUNCATED)
compiles = True
try:
    py_compile.compile(p, doraise=True)
except Exception:
    compiles = False
ck(compiles is False, "mid-statement cut does not compile (baseline)",
   "if this changed, the control below still applies")
p2 = os.path.join(tmp, "t2.py")
open(p2, "w").write(TRUNCATED_COMPILES)
try:
    py_compile.compile(p2, doraise=True)
    compiles2 = True
except Exception:
    compiles2 = False
ck(compiles2 is True, "complete-statement cut COMPILES — compiling is not completeness")

print("\n=== 1. truncated artifact is rejected ===")
v = G.check(TRUNCATED, symbol="toposort", finish_reason="stop")
ck(v["complete"] is False, "mid-statement artifact rejected", str(v["reasons"]))
ck(any("parse" in r or "dangling" in r for r in v["reasons"]),
   "reason names the structural defect", str(v["reasons"]))
ck(v["last_statement"] == "for dep", "last statement recorded", v["last_statement"])

print("\n=== 2. finish_reason=length is decisive even when the text parses ===")
v = G.check(TRUNCATED_COMPILES, symbol="toposort", finish_reason="length")
ck(v["complete"] is False, "compiling file rejected on finish_reason", str(v["reasons"]))
v = G.check(TRUNCATED_COMPILES, symbol="toposort", finish_reason="stop")
ck(v["complete"] is True, "same text with a clean finish passes", str(v["reasons"]))

print("\n=== 3. token-budget saturation is truncation evidence ===")
v = G.check(GOOD, symbol="toposort", completion_tokens=2199, budget_tokens=2200)
ck(v["complete"] is False, "99.9% of budget -> rejected", str(v["reasons"]))
v = G.check(GOOD, symbol="toposort", completion_tokens=400, budget_tokens=2200)
ck(v["complete"] is True, "18% of budget -> accepted")

print("\n=== 4. requested symbol must exist ===")
v = G.check(GOOD, symbol="dijkstra")
ck(v["complete"] is False and any("symbol" in r for r in v["reasons"]),
   "missing symbol rejected", str(v["reasons"]))
ck(symbol_present(GOOD, "toposort") is True, "def found")
ck(symbol_present("toposort = 1\n", "toposort") is True, "assignment found")
ck(symbol_present("def toposort_x():\n    pass\n", "toposort") is False,
   "prefix name is not the symbol")

print("\n=== 5. false-positive control: good artifacts pass ===")
CASES = {
    "closing bracket": "def f():\n    return [1, 2,\n            3]\n",
    "return expression": "def f(x):\n    return x + 1\n",
    "bare pass": "def f():\n    pass\n",
    "docstring end": 'def f():\n    """doc."""\n',
    "bare return": "def f():\n    return\n",
    "class": "class A:\n    def m(self):\n        return 1\n",
    "import last": "def f():\n    return 1\nimport os\n",
    "multi-line call": "def f():\n    return max(\n        1,\n        2,\n    )\n",
}
bad = []
for label, src in CASES.items():
    verdict = G.check(src, finish_reason="stop")
    if not verdict["complete"]:
        bad.append((label, verdict["reasons"]))
ck(not bad, f"{len(CASES)} passing shapes accepted", str(bad))

print("\n=== 6. structural boundary checks in isolation ===")
for label, src, want in [
    ("dangling keyword", "def f():\n    for dep", False),
    ("dangling operator", "x = 1 +", False),
    ("open bracket", "x = [1, 2", False),
    ("full line", "x = 1", True),
    ("trailing comment after good code", "x = 1\n# done", True),
    ("empty", "   \n", False),
]:
    got, why = ends_at_boundary(src)
    ck(got == want, f"{label}: {why}", "" if got == want else f"want {want} got {got}")

print("\n=== 7. empty source is rejected, not treated as complete ===")
v = G.check("", symbol="f")
ck(v["complete"] is False and "empty" in " ".join(v["reasons"]).lower(),
   "empty source rejected", str(v["reasons"]))

print()
if fails:
    print(f"FAILED ({len(fails)}):")
    for f in fails:
        print("  -", f)
    sys.exit(1)
print("COMPLETENESS: truncation rejected, good artifacts accepted")
