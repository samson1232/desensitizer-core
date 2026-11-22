"""Contract tests for the backend adapters.

The topology is fixed at one judge + one generator; the models are swappable.
These tests prove that a replacement only has to honour the contract, and that
normalisation makes a 0..4-index judge and a 1..10 judge interchangeable at the
router. No network, no models.
"""
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "engine"))

import backends as B
import keys as K
from pipeline import Pipeline

fails = []
def check(cond, label, detail=""):
    print(f"[{'PASS' if cond else 'FAIL'}] {label}" + (f"\n        {detail}" if detail else ""))
    if not cond:
        fails.append(label)

# ---- 1. normalisation is the thing that makes swapping safe --------------
print("=== 1. judge normalisation ===")
J = B.Judge
cases = [
    (0.0, [1, 3, 5, 7, 10], 1.0, "index 0 -> first label"),
    (2.0, [1, 3, 5, 7, 10], 5.0, "index 2 -> middle label"),
    (2.5, [1, 3, 5, 7, 10], 6.0, "index 2.5 -> halfway to next"),
    (4.0, [1, 3, 5, 7, 10], 10.0, "top index clamps to last"),
    (9.9, [1, 3, 5, 7, 10], 10.0, "out-of-range clamps, never extrapolates"),
    (6.5, None, 6.5, "no legend -> raw is already 1..10"),
]
for raw, legend, want, why in cases:
    got = J.normalise(raw, legend)
    check(abs(got - want) < 1e-9, why, f"raw={raw} legend={legend} -> {got}")

# ---- 2. a replacement judge only needs the contract ---------------------
print("\n=== 2. swapped judge, unmodified pipeline ===")


class FakeIndexJudge(B.Judge):
    """Returns a 0..4 expected index, like OpenJev."""
    name = "fake-index"
    def score(self, text):
        long = len(text) > 60
        raw = 3.2 if long else 1.1
        return {"raw": raw, "scale": "index0-4",
                "level": self.normalise(raw, [1, 3, 5, 7, 10]),
                "legend": [1, 3, 5, 7, 10], "seconds": 0.0, "backend": self.name}
    def probe(self):
        return {"live": True, "seconds": 0.0, "raw": 1.1, "level": 1.0}


class FakeTenPointJudge(B.Judge):
    """A different model that scores 1..10 directly."""
    name = "fake-ten"
    def score(self, text):
        return {"raw": 8.0, "scale": "1-10", "level": 8.0,
                "legend": None, "seconds": 0.0, "backend": self.name}
    def probe(self):
        return {"live": True, "seconds": 0.0, "raw": 8.0, "level": 8.0}


class FakeGenerator(B.Generator):
    name = "fake-gen"
    def generate(self, prompt, workdir=None):
        return {"code": "def reverse(s):\n    return s[::-1]\n",
                "artifact_path": None, "seconds": 0.1, "transport": "inline"}
    def probe(self):
        return {"live": True, "seconds": 0.0}


for judge, expect_route in ((FakeIndexJudge(), "frontier"), (FakeTenPointJudge(), "frontier")):
    s = judge.score("x" * 100)
    check(set(("raw", "scale", "level", "legend", "seconds", "backend")) <= set(s),
          f"{judge.name} honours the contract keys",
          f"level={s['level']} scale={s['scale']}")
    check(1 <= s["level"] <= 10,
          f"{judge.name} level is on 1..10", f"{s['level']}")

# ---- 3. routing is identical through either judge -----------------------
print("\n=== 3. same router, two different judges ===")
d = tempfile.mkdtemp(prefix="be_")
K.load_or_create(K._default_path(d))
p = Pipeline(d, scope_id="be", roster=["Alice Smith"], ground_truth={"staff": []},
             threshold=4.2)
long_text = "Write a toposort with cycle detection over a dependency graph " * 3
for judge in (FakeIndexJudge(), FakeTenPointJudge()):
    s = judge.score(long_text)
    check(p.route(s["level"]) == "frontier",
          f"{judge.name} routes frontier via level, not raw",
          f"raw={s['raw']} level={s['level']} route={p.route(s['level'])}")

# a judge that lies below threshold must route local
class LowJudge(FakeIndexJudge):
    def score(self, text):
        return {"raw": 0.5, "scale": "index0-4", "level": self.normalise(0.5, [1, 3, 5, 7, 10]),
                "legend": [1, 3, 5, 7, 10], "seconds": 0.0, "backend": "low"}
check(p.route(LowJudge().score("x")["level"]) == "local", "low judge routes local")

# ---- 4. registry refuses a missing or unknown backend -------------------
print("\n=== 4. exactly one judge, exactly one generator ===")
j = B.build_judge({"backend": "openjev", "url": "http://127.0.0.1:8791"})
check(isinstance(j, B.JevJudge), "build_judge returns the configured judge")
g = B.build_generator({"backend": "hermes-profile", "profile": "testingagentsa14b"})
check(isinstance(g, B.ProfileGenerator), "build_generator returns the configured generator")
g2 = B.build_generator({"backend": "openai-api", "model": "other-model"})
check(isinstance(g2, B.ApiGenerator), "generator can be swapped by config alone")
for bad, fn in (("nope", B.build_judge), ("nope", B.build_generator)):
    try:
        fn({"backend": bad})
        check(False, f"{fn.__name__} rejects unknown backend")
    except ValueError as e:
        check("unknown" in str(e), f"{fn.__name__} rejects unknown backend", str(e)[:60])

# ---- 5. config carries one of each, never a list -----------------------
print("\n=== 5. config shape ===")
cfg = B.load_config(None)
check(isinstance(cfg["judge"], dict) and isinstance(cfg["generator"], dict),
      "defaults have one judge and one generator")
check(not isinstance(cfg["judge"], list) and not isinstance(cfg["generator"], list),
      "neither role is a list")
tmp_cfg = os.path.join(d, "config.json")
with open(tmp_cfg, "w") as fh:
    import json
    json.dump({"threshold": 5.0, "judge": {"backend": "openjev", "timeout": 60}}, fh)
merged = B.load_config(tmp_cfg)
check(merged["threshold"] == 5.0, "threshold overridden")
check(merged["judge"]["timeout"] == 60, "judge option overridden")
check(merged["judge"]["url"] == "http://127.0.0.1:8791", "unspecified defaults survive merge")
check(merged["generator"]["backend"] == "hermes-profile", "generator default survives merge")

# ---- 6. end-to-end with fakes: censor -> route -> generate -> restore --
print("\n=== 6. full loop with swapped backends, no network ===")
judge, gen = FakeIndexJudge(), FakeGenerator()
task = ("Context: Alice Smith (alice.smith@corp.co.uk) at 14 Mill Lane, Cardiff. "
        "Write a Python file answer.py with reverse(s).")
p.censor.gate.mark_sensitive("14 Mill Lane, Cardiff", "address")
censored, _ = p.scrub(task)
check("Alice Smith" not in censored and "alice.smith@corp.co.uk" not in censored,
      "cleartext removed before generation", censored[:80])
route = p.route(judge.score(censored)["level"])
out = gen.generate(censored)["code"]
restored, rep = p.restore(out)
check("def reverse" in restored, "generated artifact survives restore", restored[:50])
check(rep["unknown_tokens"] == [] and rep["unknown_aliases"] == [],
      "restore reported no unknown identifiers")
check(route in ("local", "frontier"), "route is one of the two allowed values", route)

import shutil
shutil.rmtree(d, ignore_errors=True)
print()
if fails:
    print(f"FAILED ({len(fails)}):")
    for f in fails:
        print("  -", f)
    sys.exit(1)
print("BACKENDS: contract holds for swapped judges and generators")
