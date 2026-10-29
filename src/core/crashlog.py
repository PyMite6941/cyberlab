"""Crash and error logging for cyberterminal.

Logs unhandled exceptions and runtime errors to a crash log file so users
can diagnose problems. Logs are written to CYBERTERMINAL_HOME/crash.log
(or ~/.cyberterminal/crash.log if the env var is not set).

Usage:
    from src.core.crashlog import log_error, crash_handler

    # Log a caught exception
    try:
        ...
    except Exception as e:
        log_error(e, context="running nmap scan")

    # Decorator for functions that should never crash the app
    @crash_handler(context="tool window launch")
    def launch_tool(name: str) -> None:
        ...
"""

from __future__ import annotations

import os
import sys
import traceback
from datetime import datetime
from pathlib import Path
from typing import Optional


def _crash_log_path() -> Path:
    """Return the path to the crash log file."""
    home = os.environ.get("CYBERTERMINAL_HOME")
    base = Path(home).expanduser() if home else Path.home() / ".cyberterminal"
    base.mkdir(parents=True, exist_ok=True)
    return base / "crash.log"


def log_error(exc: BaseException, context: Optional[str] = None) -> None:
    """Write an exception (with traceback) to the crash log.

    Args:
        exc: The exception that occurred.
        context: Optional human-readable context (e.g. "launching wireshark").
    """
    path = _crash_log_path()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines: list[str] = []
    lines.append(f"[{timestamp}] cyberterminal crash report")
    if context:
        lines.append(f"Context: {context}")
    lines.append(f"Exception: {type(exc).__name__}: {exc}")
    lines.append("Traceback:")
    lines.extend(traceback.format_exception(type(exc), exc, exc.__traceback__))
    lines.append("-" * 60)
    lines.append("")

    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write("\n".join(lines))
    except OSError:
        # If we can't write the crash log, there's nothing more we can do.
        pass


def crash_handler(context: str):
    """Decorator that catches exceptions, logs them to the crash log, and
    returns None instead of propagating. Use on tool-launch functions where
    a crash shouldn't kill the whole terminal.

    Example:
        @crash_handler(context="launching wireshark window")
        def launch_wireshark() -> None:
            ...
    """

    def decorator(func):
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as exc:  # noqa: BLE001 - we want to log everything
                log_error(exc, context=context)
                return None
        return wrapper
    return decorator


def format_crash(exc: BaseException) -> str:
    """Return a user-friendly string for displaying an error in the UI."""
    lines = [
        "cyberterminal encountered an error:",
        f"  {type(exc).__name__}: {exc}",
        "",
        "The full traceback has been written to the crash log.",
        f"  Location: {_crash_log_path()}",
        "",
        "If this keeps happening, please share the crash log contents.",
    ]
    return "\n".join(lines)
