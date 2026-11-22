"""Controls for runlog.py — the log must exist, heartbeat, survive a kill, and
never contain cleartext.

A log with no heartbeat control is just a file that exists. The kill test runs a
real child process, SIGKILLs it mid-stage, and reads the last record: that is the
only way to prove the claim "a killed run's last record names the stage and the
elapsed time".
"""
import json
import os
import signal
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

from runlog import RunLog, redact

fails = []


def check(cond, label, detail=""):
    print(f"[{'PASS' if cond else 'FAIL'}] {label}" + (f"\n        {detail}" if detail else ""))
    if not cond:
        fails.append(label)


TMP = tempfile.mkdtemp(prefix="runlog_test_")
PLANT = ["Alice Smith", "alice.smith@corp.co.uk", "14 Mill Lane, Cardiff",
         "web01.internal", "4111 1111 1111 1111"]

print("=== 1. stages and events are recorded with the required fields ===")
log = RunLog(path=os.path.join(TMP, "a.jsonl"), run_id="r1", heartbeat_s=0.2)
with log.stage("preflight"):
    log.event("preflight", "probe", judge_live=True)
with log.stage("generate"):
    log.progress(nbytes=1234)
log.close()
recs = log.records()
check(len(recs) >= 4, f"records written ({len(recs)})")
check(all({"ts", "run_id", "stage", "event", "elapsed_s"} <= set(r) for r in recs),
      "every record has ts/run_id/stage/event/elapsed_s")
check(any(r.get("stage") == "generate" and r.get("bytes") == 1234 for r in recs),
      "progress carries bytes")
check({r.get("stage") for r in recs} >= {"preflight", "generate"}, "stages named")

print("\n=== 2. heartbeat fires while a stage is in flight ===")
_default_log = RunLog(path=os.path.join(TMP, "d.jsonl"), run_id="r-default")
check(_default_log.heartbeat_s <= 10.0,
      "the DEFAULT heartbeat interval is <= 10 s",
      f"heartbeat_s={_default_log.heartbeat_s}")
_default_log.close()

log2 = RunLog(path=os.path.join(TMP, "b.jsonl"), run_id="r2", heartbeat_s=0.25)
with log2.stage("judge"):
    time.sleep(1.2)
log2.close()
hbs = [r for r in log2.records() if r.get("event") == "heartbeat"]
check(len(hbs) >= 3, f">=3 heartbeats over 1.2 s at 0.25 s ({len(hbs)})",
      f"intervals={log2.heartbeat_s}")
check(all("bytes" in h for h in hbs), "each heartbeat carries bytes so far")
check(all(h.get("stage") == "judge" for h in hbs), "heartbeat names the live stage")

print("\n=== 3. a killed run's last record names the stage and elapsed time ===")
child = os.path.join(TMP, "child.py")
with open(child, "w") as fh:
    fh.write(
        "import sys, time\n"
        f"sys.path.insert(0, {HERE!r})\n"
        "from runlog import RunLog\n"
        f"log = RunLog(path={os.path.join(TMP, 'kill.jsonl')!r}, run_id='kill', heartbeat_s=0.2)\n"
        "with log.stage('generate'):\n"
        "    print('ready', flush=True)\n"
        "    time.sleep(30)\n")
proc = subprocess.Popen([sys.executable, child], stdout=subprocess.PIPE, text=True)
proc.stdout.readline()                      # child is inside the stage
time.sleep(0.9)
os.kill(proc.pid, signal.SIGKILL)
proc.wait(timeout=10)
klog = RunLog(path=os.path.join(TMP, "kill.jsonl"), run_id="kill")
krecs = klog.records()
last = krecs[-1] if krecs else {}
check(last.get("stage") == "generate", "last record names the stage", str(last))
check(isinstance(last.get("elapsed_s"), (int, float)) and last["elapsed_s"] > 0,
      "last record carries elapsed time", str(last.get("elapsed_s")))
check(any(r.get("event") == "heartbeat" for r in krecs),
      "killed run left heartbeats behind")

print("\n=== 4. no cleartext, and whole-document keys are refused ===")
log3 = RunLog(path=os.path.join(TMP, "c.jsonl"), run_id="r3", heartbeat_s=5)
log3.event("censor", "detail", note="Alice Smith at 14 Mill Lane, Cardiff, "
                                    "card 4111 1111 1111 1111, mail alice.smith@corp.co.uk, "
                                    "host web01.internal")
log3.event("verify", "statement", last_statement="return x")
log3.close()
blob = open(os.path.join(TMP, "c.jsonl")).read()
leaks = [v for v in PLANT if v in blob]
check(not leaks, "no planted value survives redaction", f"leaked: {leaks}")
check("return x" in blob, "ordinary short evidence survives", "return x")

refused = 0
for key in ("source", "code", "transcript", "tasking", "prompt", "answer"):
    try:
        log3.event("x", "y", **{key: "anything"})
    except ValueError:
        refused += 1
check(refused == 6, "six whole-document keys refused", f"{refused}/6")

print("\n=== 5. redact() keeps numbers and rejects non-scalars ===")
check(redact(3.5) == 3.5, "float passes through")
check(redact(True) is True, "bool passes through")
try:
    redact(["a"]); check(False, "list rejected")
except TypeError:
    check(True, "list rejected (no accidental dumps)")

print("\n=== 6. summary is readable without parsing the log by hand ===")
s = log2.summary()
check(s["records"] >= 3 and s["heartbeats"] >= 3, "summary counts records and heartbeats", str(s))

print()
if fails:
    print(f"FAILED ({len(fails)}):")
    for f in fails:
        print("  -", f)
    sys.exit(1)
print("RUNLOG: stages, heartbeats, kill-survival, no cleartext")
