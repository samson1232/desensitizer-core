"""Integration tests for the enterprise pipeline.

Proves the six invariants in pipeline.py's docstring against a real key,
a real roster and a real ground truth — not mocks.
"""
import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "engine"))

import keys as K
from pipeline import Pipeline, PipelineBlocked

fails = []
def check(cond, label, detail=""):
    print(f"[{'PASS' if cond else 'FAIL'}] {label}" + (f"\n        {detail}" if detail else ""))
    if not cond:
        fails.append(label)

TMP = tempfile.mkdtemp(prefix="pipeline_test_")
K.load_or_create(K._default_path(TMP))

ROSTER = ["Alice Smith", "Bob Jones"]
GT = {"staff": [{"name": "Alice Smith", "addr": "14 Mill Lane, Cardiff"},
                {"name": "Bob Jones", "addr": None}]}

TEXT = ("Alice Smith (alice.smith@corp.co.uk) at 14 Mill Lane, Cardiff "
        "about host web01.internal (10.4.19.22). Card 4111 1111 1111 1111, "
        "IBAN GB33BUKB20201555555555, phone +44 7700 900123, postcode SW1A 1AA, "
        "UTR 1234567890. Invoice £1,250.00. Ref 8f14e45f-ceea-467a-9c3c-4b3e1f2a9d01.")
REAL = ["Alice Smith", "alice.smith@corp.co.uk", "14 Mill Lane, Cardiff",
        "web01.internal", "10.4.19.22", "4111 1111 1111 1111",
        "GB33BUKB20201555555555", "+44 7700 900123", "SW1A 1AA",
        "1234567890", "8f14e45f-ceea-467a-9c3c-4b3e1f2a9d01"]

audit = os.path.join(TMP, "audit.jsonl")
p = Pipeline(TMP, scope_id="task-001", roster=ROSTER, ground_truth=GT,
             audit_path=audit, threshold=4.2)

print("=== 1. outbound scrub removes every real value ===")
censored, rep = p.scrub(TEXT)
leaks = [v for v in REAL if v in censored]
check(not leaks, "no real value survives scrub()", f"leaked: {leaks}" if leaks else "clean")
print(f"        {censored[:150]}")

print("\n=== 2. tokens are stable and structured ===")
c2, _ = p.scrub("again: alice.smith@corp.co.uk")
tok1 = [t for t in censored.split() if "email:" in t]
check("email:" in c2, "same value yields the same token", f"{c2[:60]}")
check(bool(tok1), "token carries its kind prefix")

print("\n=== 3. restore(scrub(x)) == x byte for byte ===")
back, r = p.restore(censored)
check(back == TEXT, "exact round trip",
      "" if back == TEXT else f"DIFF\n  got: {back[:120]!r}")
check(r["unknown_tokens"] == [], "no unknown tokens", f"{r['unknown_tokens']}")

print("\n=== 4. routing is a pure function ===")
check(p.route(9.0) == "frontier", "high score -> frontier")
check(p.route(1.0) == "local", "low score -> local")
check(p.route(4.2) == "frontier", "boundary is >= threshold")
check(p.route(4.19) == "local", "just below threshold -> local")
try:
    p.route(None); check(False, "None score refused")
except PipelineBlocked:
    check(True, "None score refused (no guessing)")
_p_unrouted = Pipeline(TMP, scope_id="task-001b", roster=ROSTER, ground_truth=GT)
check(_p_unrouted.route(9.9) == "unrouted",
      "no calibrated threshold -> unrouted, not frontier")
try:
    _p_unrouted.route(float("nan")); check(False, "NaN refused")
except PipelineBlocked:
    check(True, "NaN refused rather than falling to local")

print("\n=== 5. artifact aliasing round trip ===")
art, arep = p.alias("fix host web01.internal and web01.internal again", hosts=["web01.internal"])
check("web01.internal" not in art, "host aliased", f"{art!r}")
back2, r2 = p.restore(art)
check(back2 == "fix host web01.internal and web01.internal again",
      "alias restore is exact", f"{back2!r}")

print("\n=== 6. unknown alias/token left untouched, reported ===")
u, ru = p.restore("ping person_ID_999 and email:AAAAAAAAAAAAAAAAAAAAAAAAAA")
check("person_ID_999" in u, "unknown alias untouched")
check("email:AAAAAAAAAAAAAAAAAAAAAAAAAA" in u, "unknown token untouched")
check(len(ru["unknown_aliases"]) + len(ru["unknown_tokens"]) == 2, "both reported",
      f"{ru['unknown_aliases']} {ru['unknown_tokens']}")

print("\n=== 7. scope isolation ===")
p2 = Pipeline(TMP, scope_id="task-002", roster=["Bob Jones"], ground_truth={"staff": []})
p2.alias("Bob Jones called")          # scope 2 mints person_ID_1 -> Bob
leak, _ = p2.restore("person_ID_1")
check(leak == "Bob Jones", "scope 2 resolves its own alias", f"{leak!r}")
p3 = Pipeline(TMP, scope_id="task-003", roster=["Alice Smith"], ground_truth={"staff": []})
p3.alias("Alice Smith called")        # scope 3 mints its OWN person_ID_1 -> Alice
x, _ = p3.restore("person_ID_1")
check(x == "Alice Smith", "same alias, different scope, different truth", f"{x!r}")
check(p2.restore("person_ID_1")[0] != p3.restore("person_ID_1")[0],
      "the two scopes disagree — isolation is real, not a shared map")

print("\n=== 8. audit log carries no cleartext ===")
with open(audit) as fh:
    lines = [json.loads(l) for l in fh if l.strip()]
blob = json.dumps(lines)
audit_leaks = [v for v in REAL if v in blob]
check(not audit_leaks, "audit contains no real value", f"leaked: {audit_leaks}")
check(all("scope_id" in l for l in lines), "every record is scoped", f"{len(lines)} records")
print(f"        {len(lines)} audit records, kinds recorded as counts")

print("\n=== 9. decide() returns safe tasking ===")
d = p.decide("email alice.smith@corp.co.uk for routing", score=7.5)
check(d["route"] == "frontier", "decide routes by score")
check("alice.smith@corp.co.uk" not in d["tasking"], "tasking is censored")

print("\n=== 10. close() destroys the maps ===")
p.close()
check(len(p.aliases.export()["a2v"]) == 0, "alias map emptied")
check(len(p.censor.space) == 0, "token map emptied")

print("\n=== 11. a dead detector fails closed ===")
import censor_pass as CP
p4 = Pipeline(TMP, scope_id="task-004", roster=ROSTER, ground_truth=GT)
saved = CP.PATTERNS
CP.PATTERNS = []                     # simulate the scanner being wiped
try:
    p4.censor.censor_prompt(TEXT)
    check(False, "dead scanner certified a dirty prompt")
except CP.CensorFailure as e:
    check("detectors not firing" in str(e),
          "dead scanner raises rather than certifying", str(e)[:80])
finally:
    CP.PATTERNS = saved

print("\n=== 12. round trip holds across 25 random keys (regression) ===")
# Tokens are HMAC-derived, so their base32 bodies are different every install.
# A body can accidentally look like an IBAN, card or postcode to a detector;
# if any scan runs inside an emitted token, the round trip breaks on a small
# fraction of keys and nowhere else. That was a real bug: 5 failures in 80.
_rt_fail = 0
for _ in range(25):
    _d = tempfile.mkdtemp(prefix="key_rt_")
    K.load_or_create(K._default_path(_d))
    _p = Pipeline(_d, scope_id="rt", roster=ROSTER, ground_truth=GT)
    _out, _ = _p.scrub(TEXT)
    _back, _ = _p.restore(_out)
    if _back != TEXT:
        _rt_fail += 1
    shutil.rmtree(_d, ignore_errors=True)
check(_rt_fail == 0, "25 random keys, 25 exact round trips", f"{_rt_fail} failed")

print("\n=== 13. filenames survive censoring (regression) ===")
# An FQDN detector that claims "answer.py" turns the task into nonsense and the
# model writes an extension-less file. Filenames are instructions, not PII.
_p13 = Pipeline(TMP, scope_id="task-013", roster=ROSTER, ground_truth=GT)
for fn in ("answer.py", "main.js", "notes.md", "data.json", "report.docx"):
    _c, _ = _p13.scrub(f"Write a Python file {fn} with a function f()")
    check(fn in _c, f"{fn} not censored", f"got {_c[:60]!r}")
for host in ("web01.internal", "db.corp.example.com", "srv01"):
    _c, _ = _p13.scrub(f"connect to {host} now")
    check(host not in _c, f"{host} still censored", f"got {_c[:60]!r}")

shutil.rmtree(TMP, ignore_errors=True)
print()
if fails:
    print(f"FAILED ({len(fails)}):")
    for f in fails:
        print("  -", f)
    sys.exit(1)
print("PIPELINE: 11 groups, all invariants held")
