"""Helpers for the log-analysis challenges: realistic log lines, written to disk.

The challenges generate ordinary text log files (an SSH auth.log, an nginx
access.log) that students read with grep, awk, sort and friends.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Tuple

HOST = "mintvm"
BASE = datetime(2026, 11, 11, 9, 0, 0)

MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
          "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def syslog_time(offset_seconds: float) -> str:
    """A syslog timestamp like 'Nov 11 09:14:02' (offset from the base time)."""
    t = BASE + timedelta(seconds=offset_seconds)
    return f"{MONTHS[t.month - 1]} {t.day:2d} {t.strftime('%H:%M:%S')}"


def clf_time(offset_seconds: float) -> str:
    """A Common Log Format timestamp like '11/Nov/2026:09:14:02 +0000'."""
    t = BASE + timedelta(seconds=offset_seconds)
    return t.strftime("%d/%b/%Y:%H:%M:%S +0000")


def write_log(path: Path, lines: List[Tuple[float, str]]) -> None:
    """Write (offset, line) pairs to path, sorted into time order."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for _, line in sorted(lines, key=lambda row: row[0]):
            f.write(line + "\n")
