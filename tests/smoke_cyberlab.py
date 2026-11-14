"""Smoke test for the supported v2 cyberlab CLI, without starting targets.

    python tests/smoke_cyberlab.py
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
V2 = ROOT / "v2"


def run(*args: str, home: str) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ, CYBERLAB_HOME=home, PYTHONPATH=str(V2))
    return subprocess.run(
        [sys.executable, "-m", "cyberlab", *args],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="cyberlab-smoke-") as home:
        checks = [
            (("--version",), "cyberlab 2."),
            (("list",), "web-sqli"),
            (("learn", "web-sqli"), "How to defend"),
        ]
        for args, expected in checks:
            result = run(*args, home=home)
            if result.returncode or expected not in result.stdout:
                print(f"FAIL  {' '.join(args)}")
                print(result.stdout)
                print(result.stderr, file=sys.stderr)
                return 1
            print(f"PASS  {' '.join(args)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
