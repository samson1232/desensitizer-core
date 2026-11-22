"""Detector-noise controls: identifiers are censored, ordinary words are not.

The measured failure this guards: a live prompt containing "card ending-4",
"ssw0rd", "ED25519", "sha256", "us-west-2" and an incident id had all of them
replaced as bare hostnames. The tasking became unreadable and the model produced
no artifact. Over-censoring is a reliability failure, not a safe default.

The two controls must disagree: benign tokens survive, real hosts do not.
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


BENIGN = ["ending-4", "ssw0rd", "ED25519", "sha256", "us-west-2", "INC-90482",
          "2026-11-22", "utf8", "base64"]
HOSTS = ["web01", "srv01", "prod-pay-db-01", "ftcam01"]
TEXT = ("Customer reported the card ending-4: 4829. Password was ssw0rd and the "
        "key algorithm ED25519. Verify the sha256 digest, region us-west-2, ticket "
        "INC-90482, opened 2026-11-22. Encoding utf8, transfer base64. "
        "Hosts: web01, srv01, prod-pay-db-01 and ftcam01 all lost power.")

TMP = tempfile.mkdtemp(prefix="noise_test_")
K.load_or_create(K._default_path(TMP))

print("=== 1. benign technical tokens are NOT censored ===")
p = Pipeline(TMP, scope_id="noise", roster=[], ground_truth={"staff": []})
censored, rep = p.scrub(TEXT)
for word in BENIGN:
    ck(word in censored, f"{word!r} survives", "" if word in censored else censored[:200])

print("\n=== 2. real hosts ARE censored ===")
for host in HOSTS:
    ck(host not in censored, f"{host!r} removed", "" if host not in censored else "still present")
ck("host_bare:" in censored, "host placeholders emitted")

print("\n=== 3. round trip is still exact ===")
back, _ = p.restore(censored)
ck(back == TEXT, "restore(scrub(x)) == x", "" if back == TEXT else "DIFF")

print("\n=== 4. the pattern itself: control fails if reverted ===")
host_rx = dict(CP.PATTERNS)["host_bare"]
for word in ("last-4", "ssw0rd", "ED25519", "sha256", "us-west-2", "INC-90482"):
    ck(host_rx.search(word) is None, f"pattern rejects {word!r}",
       str(host_rx.search(word).group(0) if host_rx.search(word) else ""))
for host in HOSTS:
    ck(host_rx.search(host) is not None, f"pattern still claims {host!r}")

print("\n=== 5. one-digit names are ambiguous and must be seeded ===")
ck(host_rx.search("db2") is None, "db2 not guessed")
p.censor.gate.mark_sensitive("db2", "host")
seeded, _ = p.scrub("connect to db2 now")
ck("db2" not in seeded, "declared db2 is censored", seeded[:80])

print("\n=== 6. no false positive on ordinary prose ===")
prose = ("The last update was made by the team in the west region on a quiet "
         "afternoon, and nothing about this sentence should be replaced.")
p2 = Pipeline(TMP, scope_id="prose", roster=[], ground_truth={"staff": []})
out, _ = p2.scrub(prose)
ck(out == prose, "plain prose is untouched", out[:120])

shutil.rmtree(TMP, ignore_errors=True)
print()
if fails:
    print(f"FAILED ({len(fails)}):")
    for f in fails:
        print("  -", f)
    sys.exit(1)
print("DETECTOR NOISE: hosts censored, technical words preserved")
