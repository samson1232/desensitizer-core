"""Install desensitizer_core into a Hermes profile. Idempotent.

Does exactly four things and prints what it did:
  1. copies the package into <profile>/pii/ (skips if already current)
  2. creates <profile>/desens_key.bin if absent (never overwrites, never copies)
  3. writes config.json if absent
  4. runs the test suites and refuses to report success unless all pass

Usage:
    python3 install.py --profile ~/.hermes/profiles/myagent
    python3 install.py --profile ... --dry-run
"""
import argparse
import json
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SKIP = {"__pycache__", ".git", "install.py", "MANIFEST.json", "runs"}

DEFAULT_CONFIG = {
    "threshold": None,
    "audit_path": None,
    "fail_closed": True,
    "calibration_path": "calibration.json",
    "note": ("threshold stays null until calibration.py proves separation >= 3x "
             "run-to-run noise. Null means route() returns 'unrouted' and the "
             "pipeline says so instead of picking a side."),
}


def copy_package(dst, dry):
    copied = []
    for name in sorted(os.listdir(HERE)):
        if name in SKIP:
            continue
        src = os.path.join(HERE, name)
        if os.path.isdir(src) and name == "__pycache__":
            continue
        target = os.path.join(dst, name)
        if os.path.exists(target) and os.path.getmtime(target) >= os.path.getmtime(src):
            continue
        if not dry:
            if os.path.isdir(src):
                shutil.copytree(src, target, dirs_exist_ok=True,
                                ignore=shutil.ignore_patterns("__pycache__"))
            else:
                shutil.copy2(src, target)
        copied.append(name)
    return copied


def make_key(profile, dry):
    sys.path.insert(0, os.path.join(HERE, "engine"))
    import keys as K
    path = K._default_path(profile)
    if os.path.exists(path):
        return f"exists ({os.path.getsize(path)} bytes) — left untouched"
    if dry:
        return f"would create {path}"
    K.load_or_create(path)
    os.chmod(path, 0o600)
    return f"created {path} (32 bytes, 0600)"


def write_config(dst, dry):
    path = os.path.join(dst, "config.json")
    if os.path.exists(path):
        return "exists — left untouched"
    if dry:
        return f"would write {path}"
    with open(path, "w") as fh:
        json.dump(DEFAULT_CONFIG, fh, indent=2)
    return f"wrote {path}"


def run_tests(dst):
    results = []
    py = sys.executable
    for t in ("test_pipeline.py", "test_backends.py", "test_alias_bridge.py",
              "test_hostnames.py", "test_runlog.py", "test_classify.py",
              "test_completeness.py", "test_liveness.py", "test_router.py",
              "test_ui.py", "test_detector_noise.py", "test_pii_coverage.py"):
        p = os.path.join(dst, "tests", t)
        if not os.path.exists(p):
            results.append((t, None, "MISSING"))
            continue
        r = subprocess.run([py, p], capture_output=True, text=True, timeout=600)
        fails = r.stdout.count("[FAIL]")
        passes = r.stdout.count("[PASS]")
        results.append((t, r.returncode, f"{passes} pass, {fails} fail"))
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", required=True)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    profile = os.path.expanduser(args.profile)
    if not os.path.isdir(profile):
        print(f"REFUSED: profile directory does not exist: {profile}")
        print("Create the profile first; this installer will not invent one.")
        return 2

    dst = os.path.join(profile, "pii")
    print(f"installing into {dst}")
    if not args.dry_run:
        os.makedirs(dst, exist_ok=True)

    copied = copy_package(dst, args.dry_run)
    print(f"  1. copied {len(copied)} entries"
          + (f": {', '.join(copied[:6])}{'...' if len(copied) > 6 else ''}"
             if copied else " (nothing newer)"))

    print(f"  2. key: {make_key(profile, args.dry_run)}")
    print(f"  3. config: {write_config(dst, args.dry_run)}")

    if args.dry_run:
        print("  dry run: tests not executed")
        return 0

    print("  4. running the suites")
    results = run_tests(dst)
    ok = True
    for name, rc, detail in results:
        good = rc == 0 and detail != "MISSING" and "0 fail" in detail
        ok = ok and good
        print(f"     [{'PASS' if good else 'FAIL'}] {name:<24} {detail}")

    if not ok:
        print("\nINSTALL INCOMPLETE: a control failed. Do not use this profile "
              "for outbound work until it is green.")
        return 1
    print("\nINSTALL OK. Wire the three call sites listed in SKILL.md step 4.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
