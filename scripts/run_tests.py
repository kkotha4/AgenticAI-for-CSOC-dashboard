"""Run the test suites by level.

    python scripts/run_tests.py unit | component | e2e | all

unit       one function at a time, no servers (fast, runs on every change)
component  real server, worker and broker processes on temporary data, with fake models
e2e        the whole journey in a real browser
No level makes real model calls or touches local data. Exits non-zero if anything fails.
"""
import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LEVELS = {
    "unit": [[sys.executable, "-m", "pytest", "tests/unit", "-q"]],
    "component": [[sys.executable, f"tests/{name}.py"] for name in (
        "test_triage_tools", "fake_claude_live_loop", "fake_gemini_live_loop", "gemini_timeout", "test_claude_code_provider",
        "test_auth", "test_mfa", "test_observability", "test_dashboard_data", "test_dynamic_alerts", "test_multi_agent", "test_reliability", "test_production")],
    "e2e": [[sys.executable, "tests/test_ui_browser.py"]],
}


def main():
    wanted = sys.argv[1] if len(sys.argv) > 1 else "all"
    if wanted != "all" and wanted not in LEVELS:
        sys.exit(__doc__)
    results = []
    for level in (LEVELS if wanted == "all" else [wanted]):
        for command in LEVELS[level]:
            name = command[-1] if level != "unit" else "tests/unit"
            started = time.time()
            try:
                done = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=600)
                ok, output = done.returncode == 0, done.stdout + done.stderr
            except subprocess.TimeoutExpired as e:
                ok, output = False, f"Timed out after {e.timeout}s"
            results.append((level, name, ok, time.time() - started))
            print(f"{'PASS' if ok else 'FAIL'}  {level:<10} {name:<40} {time.time() - started:6.1f}s", flush=True)
            if not ok:
                print(output[-4000:], flush=True)
    failed = [r for r in results if not r[2]]
    print(f"\n{len(results) - len(failed)} of {len(results)} suites passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
