"""Single-command verification. Offline by default.

    python3 verify.py            # 338 offline checks, no models
    python3 verify.py --live     # adds one real judge+generator run (~5 min)
    python3 verify.py --json     # machine-readable summary

Exit 0 only if every suite passed. A green exit from a broken checker is the
exact failure this project was built to prevent, so each suite carries its own
known-failing controls; verify.py does not re-assert them, it reports them.
"""
import argparse
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SUITES = ["test_pipeline.py", "test_backends.py", "test_alias_bridge.py",
          "test_hostnames.py", "test_runlog.py", "test_classify.py",
          "test_completeness.py", "test_liveness.py", "test_router.py",
          "test_ui.py", "test_detector_noise.py", "test_pii_coverage.py"]


def run_suite(path):
    r = subprocess.run([sys.executable, path], capture_output=True, text=True,
                       timeout=1200, cwd=HERE)
    out = (r.stdout or "") + (r.stderr or "")
    return {"suite": os.path.basename(path), "rc": r.returncode,
            "pass": out.count("[PASS]"), "fail": out.count("[FAIL]"),
            "tail": out.strip().splitlines()[-1] if out.strip() else ""}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--live", action="store_true")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    results = []
    for s in SUITES:
        p = os.path.join(HERE, "tests", s)
        if not os.path.exists(p):
            results.append({"suite": s, "rc": 2, "pass": 0, "fail": 0,
                            "tail": "MISSING"})
            continue
        results.append(run_suite(p))

    total_p = sum(r["pass"] for r in results)
    total_f = sum(r["fail"] for r in results)
    ok = all(r["rc"] == 0 and r["fail"] == 0 for r in results)

    live = None
    if a.live and ok:
        r = subprocess.run([sys.executable, os.path.join(HERE, "live_integration.py")],
                           capture_output=True, text=True, timeout=3600, cwd=HERE)
        out = (r.stdout or "") + (r.stderr or "")
        live = {"rc": r.returncode, "tail": out.strip().splitlines()[-6:]}
        ok = ok and r.returncode == 0

    if a.json:
        print(json.dumps({"offline": results, "live": live,
                          "pass": total_p, "fail": total_f, "ok": ok}, indent=2))
    else:
        for r in results:
            print(f"  [{'PASS' if r['rc'] == 0 and r['fail'] == 0 else 'FAIL'}] "
                  f"{r['suite']:<24} {r['pass']:>3} pass, {r['fail']} fail")
        if live is not None:
            print(f"  [{'PASS' if live['rc'] == 0 else 'FAIL'}] live_integration.py")
            for line in live["tail"]:
                print("       " + line)
        print(f"\n  offline: {total_p} pass, {total_f} fail")
        print("  VERIFY OK" if ok else "  VERIFY FAILED — do not trust any rate above")

    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
