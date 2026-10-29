#!/usr/bin/env python3
"""cyberterminal offline install script.

Creates a venv (via uv), installs Python dependencies, detects/installs real
cybersecurity tools (wireshark, nmap, sqlmap, hydra, nikto, burpsuite)
cross-platform, and clones useful GitHub repos into src/tools/.

Usage:
    python install.py                          # interactive setup
    python install.py --cache-wheels           # cache wheels for offline
    python install.py --offline                # install from cache only
    python install.py --recreate               # delete + recreate .venv
    python install.py --non-interactive        # defaults, no prompts
    python install.py --install-tools          # also install real system tools
    python install.py --clone-repos            # clone GitHub repos to src/tools/
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
TUTORIALS_DATA = ROOT / "src" / "tutorials" / "data.json"
TOOLS_DIR = ROOT / "src" / "tools"


def log(msg: str) -> None:
    print(f"[cyberterminal install] {msg}")


def run(cmd: list[str], **kwargs) -> int:
    log("$ " + " ".join(cmd))
    return subprocess.call(cmd, **kwargs)


def run_capture(cmd: list[str]) -> tuple[int, str, str]:
    """Run a command, return (returncode, stdout, stderr)."""
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr


def find_uv() -> str:
    uv = shutil.which("uv")
    if uv:
        return uv
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


def detect_os() -> str:
    if os.name == "nt":
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    return "linux"


def prompt_yes_no(question: str, default: bool = True) -> bool:
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


# ---------------------------------------------------------------------------
# Real tool detection / installation
# ---------------------------------------------------------------------------

# Each tool: exe paths per OS, package manager names, github repo for cloning
TOOL_DEFS = {
    "wireshark": {
        "exe_windows": [
            "C:/Program Files/Wireshark/Wireshark.exe",
            "C:/Program Files (x86)/Wireshark/Wireshark.exe",
        ],
        "exe_macos": "/Applications/Wireshark.app/Contents/MacOS/Wireshark",
        "exe_linux": "/usr/bin/wireshark",
        "winget": "WiresharkFoundation.Wireshark",
        "brew": "wireshark",
        "apt": "wireshark",
        "choco": "wireshark",
        "repo": None,
    },
    "nmap": {
        "exe_windows": [
            "C:/Program Files (x86)/Nmap/nmap.exe",
            "C:/Program Files/Nmap/nmap.exe",
        ],
        "exe_macos": "/opt/local/bin/nmap",
        "exe_linux": "/usr/bin/nmap",
        "winget": "Insecure.Nmap",
        "brew": "nmap",
        "apt": "nmap",
        "choco": "nmap",
        "repo": None,
    },
    "sqlmap": {
        "exe_windows": ["sqlmap.py"],  # run via python
        "exe_macos": "/usr/local/bin/sqlmap",
        "exe_linux": "/usr/bin/sqlmap",
        "winget": None,
        "brew": "sqlmap",
        "apt": "sqlmap",
        "choco": None,
        "repo": "https://github.com/sqlmapproject/sqlmap.git",
    },
    "hydra": {
        "exe_windows": ["hydra.exe"],
        "exe_macos": "/opt/local/bin/hydra",
        "exe_linux": "/usr/bin/hydra",
        "winget": None,
        "brew": "hydra",
        "apt": "hydra",
        "choco": None,
        "repo": "https://github.com/vanhauser-thc/thc-hydra.git",
    },
    "nikto": {
        "exe_windows": ["nikto.pl"],  # run via perl
        "exe_macos": "/usr/local/bin/nikto",
        "exe_linux": "/usr/bin/nikto",
        "winget": None,
        "brew": "nikto",
        "apt": "nikto",
        "choco": None,
        "repo": "https://github.com/sullo/nikto.git",
    },
    "burpsuite": {
        "exe_windows": [
            "C:/Program Files/Burp Suite Community/burpsuite.exe",
            "C:/Program Files/PortSwigger/burpsuite.exe",
        ],
        "exe_macos": "/Applications/Burp Suite Community Edition.app",
        "exe_linux": "/usr/bin/burpsuite",
        "winget": "PortSwigger.BurpSuiteCommunity",
        "brew": None,
        "apt": "burpsuite",
        "choco": "burpsuite",
        "repo": None,
    },
}


def find_tool_exe(tool: str) -> str | None:
    """Return the path to a real tool executable if installed, else None."""
    d = TOOL_DEFS.get(tool)
    if not d:
        return None
    os_name = detect_os()
    key = f"exe_{os_name}"
    paths = d.get(key, [])
    if isinstance(paths, str):
        paths = [paths]
    for p in paths:
        if Path(p).exists():
            return p
    # Also check PATH
    found = shutil.which(tool)
    if found:
        return found
    # Special: sqlmap.py / nikto.pl may be in src/tools/<tool>/
    cloned = TOOLS_DIR / tool / paths[0] if paths else None
    if cloned and cloned.exists():
        return str(cloned)
    return None


def has_package_manager(pm: str) -> bool:
    return shutil.which(pm) is not None


def install_tool(tool: str, os_name: str) -> bool:
    """Try to install a real tool via available package manager. Returns True if likely installed."""
    d = TOOL_DEFS.get(tool)
    if not d:
        log(f"  no install definition for {tool}")
        return False

    # Try winget (Windows)
    if os_name == "windows" and d.get("winget") and has_package_manager("winget"):
        log(f"  installing {tool} via winget ({d['winget']}) ...")
        rc = run(["winget", "install", "--id", d["winget"], "--accept-package-agreements", "--accept-source-agreements"])
        if rc == 0:
            return True
        log(f"  winget install failed for {tool} (rc={rc})")

    # Try chocolatey (Windows)
    if os_name == "windows" and d.get("choco") and has_package_manager("choco"):
        log(f"  installing {tool} via chocolatey ({d['choco']}) ...")
        rc = run(["choco", "install", d["choco"], "-y"])
        if rc == 0:
            return True
        log(f"  choco install failed for {tool} (rc={rc})")

    # Try brew (macOS / Linux)
    if d.get("brew") and has_package_manager("brew"):
        log(f"  installing {tool} via brew ({d['brew']}) ...")
        rc = run(["brew", "install", d["brew"]])
        if rc == 0:
            return True
        log(f"  brew install failed for {tool} (rc={rc})")

    # Try apt (Linux)
    if os_name == "linux" and d.get("apt") and has_package_manager("apt"):
        log(f"  installing {tool} via apt ({d['apt']}) ...")
        rc = run(["sudo", "apt-get", "install", "-y", d["apt"]])
        if rc == 0:
            return True
        log(f"  apt install failed for {tool} (rc={rc})")

    log(f"  could not auto-install {tool}; please install manually")
    return False


def clone_repo(repo_url: str, dest: Path) -> bool:
    """Clone a GitHub repo into dest. Returns True on success."""
    if dest.exists():
        log(f"  {dest.name} already cloned, skipping")
        return True
    log(f"  cloning {repo_url} -> {dest}")
    rc = run(["git", "clone", "--depth", "1", repo_url, str(dest)])
    if rc != 0:
        log(f"  git clone failed for {repo_url} (rc={rc})")
        return False
    return True


def install_real_tools(tools: list[str], os_name: str) -> dict[str, bool]:
    """Install the requested real tools.

    Returns dict of tool -> installed. A tool is only marked installed if its
    executable is actually found on disk *after* the install attempt -- a
    package manager returning 0 is not enough (it may succeed but not place
    the binary on PATH or in the expected location).
    """
    results: dict[str, bool] = {}
    for tool in tools:
        log(f"Checking {tool} ...")
        exe = find_tool_exe(tool)
        if exe:
            log(f"  found at {exe}")
            results[tool] = True
            continue
        log(f"  not found; attempting install ...")
        install_tool(tool, os_name)
        # Always verify the executable is actually present after install.
        exe = find_tool_exe(tool)
        if exe:
            log(f"  now available at {exe}")
            results[tool] = True
        else:
            log(f"  FAILED: {tool} is still not available after install attempt")
            results[tool] = False
    return results


def clone_repos(tools: list[str]) -> None:
    """Clone GitHub repos for tools that have them into src/tools/."""
    TOOLS_DIR.mkdir(parents=True, exist_ok=True)
    for tool in tools:
        d = TOOL_DEFS.get(tool)
        if not d or not d.get("repo"):
            continue
        dest = TOOLS_DIR / tool
        clone_repo(d["repo"], dest)


# ---------------------------------------------------------------------------
# Python venv / dependencies
# ---------------------------------------------------------------------------

def create_venv(uv: str) -> None:
    if VENV_DIR.exists():
        log(f"venv already exists at {VENV_DIR}")
        return
    log(f"Creating venv at {VENV_DIR}")
    rc = run([uv, "venv", str(VENV_DIR)])
    if rc != 0:
        raise SystemExit(f"uv venv failed with exit code {rc}")


def pip_install_offline(uv: str, venv_py: str, wheels_dir: Path) -> int:
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
    WHEELS_DIR.mkdir(exist_ok=True)
    log("Caching wheels into wheels/ (requires network, parallel downloads)")
    run([uv, "pip", "install", "--python", venv_py, "--upgrade", "pip"])
    return run([
        venv_py, "-m", "pip", "download",
        "-d", str(WHEELS_DIR),
        "-r", str(REQUIREMENTS),
    ])


def setup_docs(desired: bool) -> None:
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


def verify_tools(tools: list[str]) -> list[str]:
    """Return the list of tools whose executables are NOT actually found.

    A tool counts as installed only if find_tool_exe() locates its binary on
    disk. This is the authoritative check -- package manager return codes are
    not trusted.
    """
    missing: list[str] = []
    for tool in tools:
        exe = find_tool_exe(tool)
        if not exe:
            missing.append(tool)
    return missing


def verify(uv: str, venv_py: str, tools: list[str] | None = None) -> int:
    log("Verifying install: `cyberterminal` imports correctly")
    run([uv, "pip", "install", "--python", venv_py, "-e", str(ROOT)])
    rc = run([
        venv_py, "-c",
        "from src.terminal import CyberTerminal, main; print('cyberterminal OK')",
    ])
    if rc != 0:
        return rc

    if tools:
        log("Verifying real tools are actually installed ...")
        missing = verify_tools(tools)
        for tool in tools:
            exe = find_tool_exe(tool)
            status = "INSTALLED" if exe else "NOT FOUND"
            path = f" ({exe})" if exe else ""
            log(f"  {tool:<12} {status}{path}")
        if missing:
            log("")
            log(f"ERROR: These requested tools are still not installed: {', '.join(missing)}")
            log("Install them manually or re-run with --install-tools after installing the missing packages.")
            return 1
    return 0


def print_tool_report(results: dict[str, bool]) -> None:
    log("")
    log("=== Real tool availability report ===")
    for tool, ok in results.items():
        exe = find_tool_exe(tool)
        status = "INSTALLED" if ok else "NOT INSTALLED"
        path = f" ({exe})" if exe else ""
        log(f"  {tool:<12} {status}{path}")
    log("")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Install cyberterminal offline-capable environment.")
    parser.add_argument("--cache-wheels", action="store_true", help="Download dependency wheels into wheels/ for offline use.")
    parser.add_argument("--offline", action="store_true", help="Install from wheels/ only, no network.")
    parser.add_argument("--recreate", action="store_true", help="Delete existing .venv before creating a new one.")
    parser.add_argument("--non-interactive", action="store_true", help="Run without prompts (uses defaults: yes to everything).")
    parser.add_argument("--install-tools", action="store_true", help="Also install real system tools (wireshark, nmap, sqlmap, hydra, nikto, burpsuite).")
    parser.add_argument("--clone-repos", action="store_true", help="Clone GitHub repos for tools into src/tools/.")
    parser.add_argument("--tools", nargs="*", default=[], help="Specific tools to install (wireshark nmap sqlmap hydra nikto burpsuite).")
    args = parser.parse_args(argv)

    uv = find_uv()
    python = find_python()
    log(f"Using uv: {uv}")
    log(f"Using python: {python}")

    os_name = detect_os()
    log(f"Detected OS: {os_name}")

    # ---- Interactive setup ----
    if args.non_interactive:
        install_docs = True
        download_tuts = True
        install_real = args.install_tools
        clone_repos_flag = args.clone_repos
        tool_list = args.tools or ["wireshark", "nmap", "sqlmap", "hydra", "nikto", "burpsuite"]
        log("Non-interactive mode: defaults (docs=yes, tutorials=yes)")
    else:
        print()
        print("=== cyberterminal setup ===")
        install_docs = prompt_yes_no("Install tutorial docs?", default=True)
        download_tuts = prompt_yes_no("Download tutorials for offline use?", default=True)
        install_real = prompt_yes_no("Install real system tools (wireshark, nmap, sqlmap, hydra, nikto, burpsuite)?", default=True)
        clone_repos_flag = prompt_yes_no("Clone GitHub repos into src/tools/?", default=True)
        print()
        print("Available tools: wireshark, nmap, sqlmap, hydra, nikto, burpsuite")
        try:
            ans = input("Tools to install (comma-separated, or Enter for all): ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            ans = ""
        if ans:
            tool_list = [t.strip() for t in ans.split(",") if t.strip()]
        else:
            tool_list = ["wireshark", "nmap", "sqlmap", "hydra", "nikto", "burpsuite"]
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

    # Real tools
    results: dict[str, bool] = {}
    if install_real:
        results = install_real_tools(tool_list, os_name)
        print_tool_report(results)
    else:
        log("Skipping real tool installation.")

    # Clone repos
    if clone_repos_flag:
        clone_repos(tool_list)

    rc = verify(uv, vp, tool_list if install_real else None)
    if rc != 0:
        return rc

    log("")
    log("Install complete. Run:  python -m src.terminal   (or ./run.sh / run.bat)")
    if results:
        not_installed = [t for t, ok in results.items() if not ok]
        if not_installed:
            log(f"NOTE: These tools still need manual install: {', '.join(not_installed)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
