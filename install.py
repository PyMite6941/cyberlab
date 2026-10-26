#!/usr/bin/env python3
"""cyberterminal offline install script.

Creates a venv (via uv), installs dependencies, and supports an offline wheel
cache so the environment can be rebuilt with no network access.

Interactive setup asks:
  - whether to install tutorial docs
  - which tools to set up (burp, wireshark, both)
  - whether to download tutorials

Usage:
    # Interactive setup (prompts for docs, tools, tutorials)
    python install.py

    # While online: create venv + install deps + populate offline wheel cache
    python install.py --cache-wheels

    # Later, fully offline: recreate venv from the cached wheels only
    python install.py --offline

    # Non-interactive (uses defaults: yes to everything)
    python install.py --non-interactive
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VENV_DIR = ROOT / ".venv"
WHEELS_DIR = ROOT / "wheels"
REQUIREMENTS = ROOT / "requirements.txt"
TUTORIALS_DATA = ROOT / "src" / "cyberlab" / "tutorials" / "data.json"


def log(msg: str) -> None:
    print(f"[cyberterminal install] {msg}")


def run(cmd: list[str], **kwargs) -> int:
    log("$ " + " ".join(cmd))
    return subprocess.call(cmd, **kwargs)


def find_uv() -> str:
    uv = shutil.which("uv")
    if uv:
        return uv
    # Fall back to common user install location on Windows
    cand = Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "uv" / "uv.exe"
    if cand.exists():
        return str(cand)
    raise SystemExit("uv not found on PATH. Install uv first: https://github.com/astral-sh/uv")


def find_python() -> str:
    for name in ("python3", "python"):
        p = shutil.which(name)
        if p:
            return p
    raise SystemExit("python not found on PATH")


def venv_python(venv: Path) -> str:
    if os.name == "nt":
        return str(venv / "Scripts" / "python.exe")
    return str(venv / "bin" / "python")


def prompt_yes_no(question: str, default: bool = True) -> bool:
    """Ask a yes/no question. Returns True/False."""
    suffix = " [Y/n] " if default else " [y/N] "
    while True:
        try:
            ans = input(question + suffix).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return default
        if ans in ("", "y", "yes"):
            return True
        if ans in ("n", "no"):
            return False
        print("  Please answer y or n.")


def prompt_tools() -> str:
    """Ask which tools to install. Returns 'burp', 'wireshark', or 'both'."""
    print()
    print("Which tools would you like to set up for use?")
    print("  1. burp      (simulated intercepting proxy)")
    print("  2. wireshark (simulated packet capture)")
    print("  3. both")
    while True:
        try:
            ans = input("Select 1/2/3 [3]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return "both"
        if ans in ("", "3", "both"):
            return "both"
        if ans in ("1", "burp"):
            return "burp"
        if ans in ("2", "wireshark"):
            return "wireshark"
        print("  Please select 1, 2, or 3.")


def create_venv(uv: str) -> None:
    if VENV_DIR.exists():
        log(f"venv already exists at {VENV_DIR}")
        return
    log(f"Creating venv at {VENV_DIR}")
    rc = run([uv, "venv", str(VENV_DIR)])
    if rc != 0:
        raise SystemExit(f"uv venv failed with exit code {rc}")


def pip_install_offline(uv: str, venv_py: str, wheels_dir: Path) -> int:
    """Install from the local wheels directory only (--no-index).

    uv resolves and installs directly; it does not need pip inside the venv.
    """
    if not wheels_dir.exists() or not any(wheels_dir.iterdir()):
        log("No wheels found in wheels/; cannot install offline.")
        return 1
    log("Installing from offline wheel cache (--no-index --find-links wheels/)")
    return run([
        uv, "pip", "install", "--python", venv_py,
        "--no-index", "--find-links", str(wheels_dir),
        "-r", str(REQUIREMENTS),
    ])


def pip_install_online(uv: str, venv_py: str) -> int:
    log("Installing dependencies from PyPI")
    rc = run([uv, "pip", "install", "--python", venv_py, "--upgrade", "pip"])
    if rc != 0:
        return rc
    return run([uv, "pip", "install", "--python", venv_py, "-r", str(REQUIREMENTS)])


def cache_wheels(uv: str, venv_py: str) -> int:
    """Download requirement wheels into wheels/ for later offline installs.

    Uses the venv's pip (uv installs pip into the venv) so this works with any
    uv version. Runs in parallel by default (pip downloads multiple wheels
    concurrently).
    """
    WHEELS_DIR.mkdir(exist_ok=True)
    log("Caching wheels into wheels/ (requires network, parallel downloads)")
    # Ensure pip is available inside the venv
    run([uv, "pip", "install", "--python", venv_py, "--upgrade", "pip"])
    return run([
        venv_py, "-m", "pip", "download",
        "-d", str(WHEELS_DIR),
        "-r", str(REQUIREMENTS),
    ])


def setup_docs(desired: bool) -> None:
    """Install tutorial docs (data.json + index.html) if desired."""
    if not desired:
        log("Skipping tutorial docs install.")
        return
    log("Installing tutorial docs...")
    if not TUTORIALS_DATA.exists():
        log(f"ERROR: tutorial data not found at {TUTORIALS_DATA}")
        return
    html = TUTORIALS_DATA.parent / "index.html"
    if not html.exists():
        log(f"ERROR: tutorial webpage not found at {html}")
        return
    log(f"Tutorial docs ready: {TUTORIALS_DATA}")
    log(f"Tutorial webpage ready: {html}")


def download_tutorials(desired: bool) -> None:
    """Confirm tutorials are bundled for offline use."""
    if not desired:
        log("Skipping tutorial download.")
        return
    log("Preparing tutorials for offline use...")
    if TUTORIALS_DATA.exists():
        with open(TUTORIALS_DATA, encoding="utf-8") as f:
            data = json.load(f)
        n = len(data.get("tutorials", []))
        log(f"Tutorials bundled: {n} tutorial(s) available offline.")
    else:
        log("WARNING: no tutorial data found to bundle.")


def verify(uv: str, venv_py: str) -> int:
    log("Verifying install: `cyberterminal` imports correctly")
    # Install the package itself in editable mode so `cyberterminal` entry point works
    run([uv, "pip", "install", "--python", venv_py, "-e", str(ROOT)])
    return run([
        venv_py, "-c",
        "from cyberlab.terminal import CyberTerminal, main; print('cyberterminal OK')",
    ])


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Install cyberterminal offline-capable environment.")
    parser.add_argument("--cache-wheels", action="store_true",
                        help="Download dependency wheels into wheels/ for offline use.")
    parser.add_argument("--offline", action="store_true",
                        help="Install from wheels/ only, no network.")
    parser.add_argument("--recreate", action="store_true",
                        help="Delete existing .venv before creating a new one.")
    parser.add_argument("--non-interactive", action="store_true",
                        help="Run without prompts (uses defaults: yes to everything).")
    args = parser.parse_args(argv)

    uv = find_uv()
    python = find_python()
    log(f"Using uv: {uv}")
    log(f"Using python: {python}")

    # ---- Interactive setup ----
    if args.non_interactive:
        install_docs = True
        tools = "both"
        download_tuts = True
        log("Non-interactive mode: defaults (docs=yes, tools=both, tutorials=yes)")
    else:
        print()
        print("=== cyberterminal setup ===")
        install_docs = prompt_yes_no("Install tutorial docs?", default=True)
        tools = prompt_tools()
        download_tuts = prompt_yes_no("Download tutorials for offline use?", default=True)
        print()

    if args.recreate and VENV_DIR.exists():
        log("Removing existing .venv")
        shutil.rmtree(VENV_DIR)

    create_venv(uv)
    vp = venv_python(VENV_DIR)

    if args.offline:
        rc = pip_install_offline(uv, vp, WHEELS_DIR)
        if rc != 0:
            return rc
    else:
        rc = pip_install_online(uv, vp)
        if rc != 0:
            return rc

    if args.cache_wheels:
        rc = cache_wheels(uv, vp)
        if rc != 0:
            return rc

    # Docs / tutorials setup
    setup_docs(install_docs)
    download_tutorials(download_tuts)

    log(f"Tools selected: {tools}")
    return verify(uv, vp)


if __name__ == "__main__":
    sys.exit(main())
