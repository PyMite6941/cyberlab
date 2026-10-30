"""Start and stop the local targets (each runs as its own background process).

A target's pid and port are kept in the workspace state, so `cyberlab stop`
works from any terminal. Before stopping a pid, it's checked to still be our
target, so a reused pid never kills an unrelated process.
"""

from __future__ import annotations

import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

from cyberlab.workspace import Workspace

HOST = "127.0.0.1"
PACKAGE_PARENT = Path(__file__).resolve().parent.parent  # the v2/ folder

# name -> (module to run, preferred port)
TARGETS = {
    "webapp": ("cyberlab.webapp", 8080),
}


def _port_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((HOST, port))
        except OSError:
            return False
    return True


def _any_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, 0))
        return s.getsockname()[1]


def _accepting(port: int) -> bool:
    try:
        with socket.create_connection((HOST, port), timeout=0.2):
            return True
    except OSError:
        return False


def _is_our_target(pid: int, module: str) -> bool:
    """Whether pid is alive and is running our target module."""
    try:
        cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode()
        return module in cmdline
    except FileNotFoundError:
        if Path("/proc/self").exists():
            return False  # Linux, and the pid is gone
    except OSError:
        return False
    # No /proc (macOS): fall back to "is it alive".
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def running(ws: Workspace, name: str) -> Optional[int]:
    """The port of a running target, or None (and forget it if it died)."""
    info = ws.state["targets"].get(name)
    if not info:
        return None
    module = TARGETS[name][0]
    if _is_our_target(info["pid"], module) and _accepting(info["port"]):
        return info["port"]
    del ws.state["targets"][name]
    ws.save()
    return None


def start(ws: Workspace, name: str) -> int:
    """Start a target if it isn't running; return its port."""
    port = running(ws, name)
    if port:
        return port
    module, preferred = TARGETS[name]
    port = preferred if _port_free(preferred) else _any_free_port()
    log = ws.path("logs", f"{name}.log")
    env = dict(os.environ, PYTHONPATH=str(PACKAGE_PARENT))
    with open(log, "ab") as out:
        proc = subprocess.Popen(
            [sys.executable, "-m", module, "--port", str(port), "--home", str(ws.home)],
            stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT,
            env=env, start_new_session=True,  # keeps running after this command exits
        )
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"{name} exited at startup; see {log}")
        if _accepting(port):
            ws.state["targets"][name] = {"pid": proc.pid, "port": port}
            ws.save()
            return port
        time.sleep(0.05)
    proc.terminate()
    raise RuntimeError(f"{name} didn't start listening on port {port}; see {log}")


def stop_all(ws: Workspace) -> list:
    """Stop every running target; return the names stopped."""
    stopped = []
    for name, info in list(ws.state["targets"].items()):
        module = TARGETS.get(name, ("",))[0]
        if module and _is_our_target(info["pid"], module):
            try:
                os.kill(info["pid"], signal.SIGTERM)
                stopped.append(name)
            except OSError:
                pass
        del ws.state["targets"][name]
    ws.save()
    return stopped
