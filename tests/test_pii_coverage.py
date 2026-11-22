"""Coverage controls for the identifiers the first pass missed.

Each case below failed on a real incident ticket: names, postal address,
employee id, last-4 SSN, usernames, API secrets, SSH fingerprints, and a DB
credential whose password survived a partial match. The UUID case is different:
it was DETECTED but fragmented into `550e8400-<host token><phone token>`, which
is worse than a miss because the output looks censored.

Two controls per idea: the identifier must disappear, and the surrounding
technical prose must survive. Over-censoring is its own failure.
"""
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "engine"))

import censor_pass as CP          # noqa: E402
import keys as K                  # noqa: E402
from pipeline import Pipeline     # noqa: E402

fails = []


def ck(cond, label, detail=""):
    print(f"[{'PASS' if cond else 'FAIL'}] {label}" + (f"\n        {detail}" if detail else ""))
    if not cond:
        fails.append(label)


FAKE_STRIPE = "sk_" + "test_" + "51P9xK2L9vQ8mN3zR7wT4yB6c"
FAKE_AWS = "AKIA" + "IOSFODNN7EXAMPLE"

TICKET = f"""Ticket INC-884920
Reporter: Sarah Jenkins (sarah.jenkins@corp.example)
Direct Line: +44 7700 900123 | Employee ID: EMP-90482
Home Address (Remote Worker): 742 Evergreen Terrace, Apt 4B, San Francisco, CA 94107
Gov ID Verified (Last 4 SSN): 6789
Escalated to on-call SRE Marcus Vance.
Accepted publickey for mvance from 10.240.18.94
DB_URI=postgresql://mvance:ssw0rd123!@10.240.18.94:5432/prod_ledger
STRIPE_SECRET_KEY={FAKE_STRIPE}
AWS_ACCESS_KEY_ID={FAKE_AWS}
Hardware UUID: 550e8400-e29b-41d4-a716-446655440000
Fingerprint: SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8
"""

SECRETS = [
    ("reporter name", "Sarah Jenkins"),
    ("reporter email", "sarah.jenkins@corp.example"),
    ("employee id", "EMP-90482"),
    ("last-4 ssn", "6789"),
    ("street address", "742 Evergreen Terrace"),
    ("city / zip", "San Francisco, CA 94107"),
    ("sre name", "Marcus Vance"),
    ("username", "mvance"),
    ("db password", "ssw0rd123!"),
    ("stripe key", FAKE_STRIPE),
    ("aws key", FAKE_AWS),
    ("uuid", "550e8400-e29b-41d4-a716-446655440000"),
    ("ssh fingerprint", "nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8"),
]

KINDS = ["person", "email", "employee_id", "ssn_last4", "address", "username",
         "url_credential", "api_secret", "aws_key", "uuid", "ssh_fingerprint"]

TMP = tempfile.mkdtemp(prefix="pii_cov_")
K.load_or_create(K._default_path(TMP))
p = Pipeline(TMP, scope_id="cov", roster=[], ground_truth={"staff": []})

print("=== 1. every missed value disappears ===")
censored, rep = p.scrub(TICKET)
for label, value in SECRETS:
    ck(value not in censored, f"{label} removed", "" if value not in censored
       else f"still in: {censored[:160]}")

print("\n=== 2. the right kinds fired ===")
kinds = rep.get("kinds", {})
for kind in KINDS:
    ck(kind in kinds, f"{kind} detected", str(sorted(kinds)))

print("\n=== 3. no fragmentation: one whole token per structured span ===")
ck(censored.count("uuid:") == 1, "exactly one UUID token", f"{censored.count('uuid:')}")
ck("550e8400-" not in censored, "no UUID prefix survives")
ck("url_credential:" in censored, "whole URI is one token")
ck(":5432/prod_ledger" not in censored, "URI tail (port/db) is inside the token")
ck(censored.count("person:") == 2, "two context-bound names, two tokens",
   f"{censored.count('person:')}")

print("\n=== 4. technical prose survives ===")
BENIGN = ["INC-884920", "Senior Site Reliability Engineer", "for the team",
          "last update", "ED25519", "Ubuntu 24.04", "kernel 6.8.0-45-generic",
          "billing-api.service"]
prose = ("Ticket INC-884920. The Senior Site Reliability Engineer asked for the team to "
         "check the last update. ED25519 keys, Ubuntu 24.04, kernel 6.8.0-45-generic. "
         "Restart billing-api.service.")
out2, _ = p.scrub(prose)
for b in BENIGN:
    ck(b in out2, f"{b!r} preserved", "" if b in out2 else out2[:160])

print("\n=== 4b. Singapore address shapes ===")
SG = [
    "Blk 35 Mandalay Road, #01-01, Singapore 308215",
    "11 Orchard Turn, Orchard Parksuites #01-13, Singapore 238800",
    "738 North Bridge Road, Singapore 198706",
    "Blk 101 Yishun Avenue 5, #05-12, Singapore 760101",
    "1 HarbourFront Walk, #01-52 VivoCity, Singapore 098585",
    "44 Changi Road, Singapore 419702",
]
for i, addr in enumerate(SG, 1):
    src = f"Ship to: {addr}. Thanks."
    out3, rep3 = p.scrub(src)
    back3, _ = p.restore(out3)
    ck(addr not in out3, f"SG address {i} removed",
       "" if addr not in out3 else out3[:140])
    ck("address_sg" in rep3.get("kinds", {}), f"SG address {i} kind",
       str(sorted(rep3.get("kinds", {}))))
    ck(back3 == src, f"SG address {i} round trip")

print("\n=== 4c. hostnames and IPv6 ===")
HD = ("Technician logs show her laptop (Hostname: DESKTOP-9941A, IP: 10.240.18.92, "
      "IPv6: 2001:0db8:85a3:0000:0000:8a2e:0370:7334, alt fe80::1) was on guest Wi-Fi. "
      "At 08:14:51 the port changed; ISO time 2026-11-22T08:15:03Z must survive.")
out4, rep4 = p.scrub(HD)
back4, _ = p.restore(out4)
ck("DESKTOP-9941A" not in out4, "uppercase hostname removed")
ck("2001:0db8:85a3:0000:0000:8a2e:0370:7334" not in out4, "full IPv6 removed")
ck("fe80::1" not in out4, "compressed IPv6 removed")
ck("host_labeled" in rep4.get("kinds", {}) or "host_upper" in rep4.get("kinds", {}),
   "hostname kind fired", str(sorted(rep4.get("kinds", {}))))
ck("ipv6" in rep4.get("kinds", {}), "ipv6 kind fired")
ck("08:14:51" in out4, "clock time preserved", out4[:120])
ck("2026-11-22T08:15:03Z" in out4, "ISO timestamp preserved")
ck(back4 == HD, "hostname/IPv6 note round trip")

print("\n=== 5. round trip is exact ===")
back, _ = p.restore(censored)
ck(back == TICKET, "restore(scrub(ticket)) == ticket",
   "" if back == TICKET else "DIFF")

print("\n=== 6. every new kind has a live canary ===")
diag = p.censor.self_test()
dead = [k for k, ok in diag.items() if not ok]
ck(not dead, f"all {len(diag)} canaries fire", str(dead))

print("\n=== 7. the controls can fail ===")
saved = CP.PATTERNS
CP.PATTERNS = []
try:
    p.censor.censor_prompt(TICKET)
    ck(False, "disarmed scanner certified a dirty ticket")
except CP.CensorFailure as e:
    ck("detectors not firing" in str(e), "disarmed scanner refuses", str(e)[:80])
finally:
    CP.PATTERNS = saved

shutil.rmtree(TMP, ignore_errors=True)
print()
if fails:
    print(f"FAILED ({len(fails)}):")
    for f in fails:
        print("  -", f)
    sys.exit(1)
print(f"PII COVERAGE: {len(KINDS)} kinds, {len(SECRETS)} secrets, prose preserved")
