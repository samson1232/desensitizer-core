"""Hostname management tests for alias_bridge_v2."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from alias_bridge import AliasScope

fails = []
def check(cond, label, detail=""):
    print(f"[{'PASS' if cond else 'FAIL'}] {label}" + (f"\n        {detail}" if detail else ""))
    if not cond:
        fails.append(label)

HOSTS = ["web01.internal", "db-prod-02.corp.example.com", "srv01", "ftcam01",
         "s600", "mail.corp.example.com.", "api.staging.acme.co.uk"]

s = AliasScope("host-test")
print("=== A. each shape is censored and restores ===")
for h in HOSTS:
    text = f"connect to {h} now"
    censored, rep = s.censor(text)
    back, _ = s.restore(censored)
    kinds = [r["value_kind"] for r in rep["replaced"]]
    check(h not in censored and back == text,
          f"{h:<30} censored",
          f"{censored!r} kinds={kinds}")

print("\n=== B. ports stay outside the alias ===")
c, _ = s.censor("api.staging.acme.co.uk:8443")
check(c.endswith(":8443"), "port preserved", f"{c!r}")
b, _ = s.restore(c)
check(b == "api.staging.acme.co.uk:8443", "port restores with host", f"{b!r}")

print("\n=== C. digitless names need seeding ===")
c2, r2 = s.censor("the sigmac box is down")
check(c2 == "the sigmac box is down", "unseeded digitless name passes through (expected)",
      f"{c2!r} — cannot be detected from shape")
c3, r3 = s.censor_with_seeds("the sigmac box is down", ["sigmac"])
check("sigmac" not in c3, "seeded name is censored", f"{c3!r}")
b3, _ = s.restore(c3)
check(b3 == "the sigmac box is down", "seeded name restores", f"{b3!r}")

print("\n=== D. same host, two mentions -> one alias ===")
c4, _ = s.censor("srv01 then srv01 again")
ids = [t for t in c4.split() if t.startswith("hostname_")]
check(len(ids) == 2 and ids[0] == ids[1], "repeated host reuses its alias", f"{c4!r}")

print("\n=== E. no false positives on prose ===")
prose = ["The quick brown fox jumps over the lazy dog.",
         "We shipped version 2 of the client on Tuesday.",
         "Room 101 was ready before the QA pass.",
         "Please review the attached report."]
hits = 0
for p in prose:
    c5, r5 = s.censor(p)
    if c5 != p:
        hits += 1
        print(f"        MUTATED: {p!r} -> {c5!r}")
check(hits == 0, "ordinary prose untouched", f"{hits}/{len(prose)} mutated")

print("\n=== F. host and email for the same domain ===")
s2 = AliasScope("cross")
c6, _ = s2.censor("user@mail.corp.example.com and mail.corp.example.com")
print(f"        {c6!r}")
vals = set(s2.export()["a2v"].values())
check("mail.corp.example.com" in vals, "domain appears as a value",
      "reachable via pivot table even when spanned by an email")

print("\nregistry:")
for a, v in sorted(s.export()["a2v"].items()):
    print(f"  {a:<14} {v}")
if fails:
    print(f"\nFAILED ({len(fails)}): {fails}")
    sys.exit(1)
print("\nHOSTNAME MANAGEMENT OK")
