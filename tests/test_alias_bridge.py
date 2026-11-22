"""Tests for alias_bridge_v2: can it scrub into an alias, and restore exactly?

Runs the SAME intake as test_agentless_decensor.py so v1 and v2 are directly
comparable, then adds the scrub direction v1 lacked.

The decisive property: censor() must remove every real value from the text and
replace it with an alias, and restore() must put them back byte for byte.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from alias_bridge import AliasScope, AliasError, _ALIAS_RE

fails = []
def check(cond, label, detail=""):
    print(f"[{'PASS' if cond else 'FAIL'}] {label}" + (f"\n        {detail}" if detail else ""))
    if not cond:
        fails.append(label)

RAW = ("Alice Smith (alice.smith@corp.co.uk) called about host web01.internal "
       "(10.4.19.22). Card 4111 1111 1111 1111, IBAN GB33BUKB20201555555555, "
       "phone +44 7700 900123, postcode SW1A 1AA, UTR 1234567890. "
       "Invoice £1,250.00 outstanding. Ref 8f14e45f-ceea-467a-9c3c-4b3e1f2a9d01.")

VALUES = ["Alice Smith", "alice.smith@corp.co.uk", "web01.internal", "10.4.19.22",
          "4111 1111 1111 1111", "GB33BUKB20201555555555", "+44 7700 900123",
          "SW1A 1AA", "1234567890", "£1,250.00", "8f14e45f-ceea-467a-9c3c-4b3e1f2a9d01"]

# ---- 1. censor() actually scrubs -----------------------------------------
s = AliasScope("task-42")
censored, rep = s.censor(RAW)

check(censored != RAW, "censor() changes the text",
      f"{len(RAW)} chars in, {len(censored)} out")
leaks = [v for v in VALUES if v in censored]
check(not leaks, "no detector-known value survives censoring",
      f"leaked: {leaks}" if leaks else f"all {len(VALUES)} removed")
check(rep["count"] > 0, "report says what it replaced", f"count={rep['count']}")
print(f"        censored: {censored[:150]}\n")

# ---- 2. Round-trip -------------------------------------------------------
back, rep2 = s.restore(censored)
check(back == RAW, "restore(censor(text)) == text, byte for byte",
      "" if back == RAW else f"DIFF got {back[:100]!r}")
check(rep2["unknown"] == [], "no unknown aliases on restore", f"{rep2['unknown']}")

# ---- 3. Idempotence ------------------------------------------------------
twice, _ = s.censor(censored)
check(twice == censored, "censoring twice == censoring once",
      f"second pass changed it: {twice[:80]!r}" if twice != censored else "")

# ---- 4. Same value -> same alias ----------------------------------------
a1 = s.issue("email", "alice.smith@corp.co.uk")
c2, _ = s.censor("again: alice.smith@corp.co.uk")
check(a1 in c2, "a repeated value reuses its alias, not a new one",
      f"{a1} present in second censor: {a1 in c2}")

# ---- 5. Longest-span wins (card not chopped by phone/utr) ---------------
sc = AliasScope("card-test")
cc, _ = sc.censor("Card 4111 1111 1111 1111 on file")
check("card_1" in cc and "4111" not in cc,
      "card number aliased whole, not shredded",
      f"{cc}")

# ---- 6. Unknown alias refused, never guessed ----------------------------
u, ru = s.restore("ping person_ID_999 now")
check(u == "ping person_ID_999 now", "unknown alias untouched", f"{ru}")

# ---- 7. A fresh scope cannot leak the first -----------------------------
s2 = AliasScope("other-task")
leak, rl = s2.restore("email_1")
check(leak == "email_1", "scope B cannot resolve scope A's alias",
      f"resolved to {leak!r}" if leak != "email_1" else "refused")

# ---- 8. Empty / plain text is a no-op, not an error ---------------------
e, _ = s.censor("")
check(e == "", "empty string censors to empty")
p, _ = s.censor("nothing sensitive here")
check(p == "nothing sensitive here", "plain text passes through unchanged", f"{p!r}")

# ---- 9. Non-str refused --------------------------------------------------
try:
    s.censor(None); check(False, "censor(None) refused")
except AliasError:
    check(True, "censor(None) refused")

# ---- 10. export() carries the pivot table --------------------------------
ex = s.export()
check(ex["scope_id"] == "task-42" and len(ex["a2v"]) > 0,
      "export() exposes the pivot table with its scope",
      f"{len(ex['a2v'])} aliases")

print()
print(f"aliases minted   : {len(s._a2v)}")
print(f"censored length  : {len(censored)} chars (from {len(RAW)})")
print(f"round-trip       : {'exact' if back == RAW else 'BROKEN'}")
print(f"values surviving : {len([v for v in VALUES if v in censored])}")
if fails:
    print(f"\nFAILED ({len(fails)}): {fails}")
    sys.exit(1)
print("\nv2 SCRUBS INTO ALIASES AND RESTORES EXACTLY — no LLM in either direction.")
