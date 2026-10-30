"""`cyberlab report`: a progress summary a student hands in.

What it can and can't show: everything lives on the student's own machine, so
a report is a summary, not proof. The workspace ID (a hash of the workspace
secret, never the secret itself) lets the teacher see whether two reports came
from the same workspace; to check that someone really solved a challenge, ask
them to show it.
"""

from __future__ import annotations

import getpass
import hashlib
import json
import platform
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from cyberlab import __version__
from cyberlab.challenges import ordered
from cyberlab.workspace import Workspace


def workspace_id(ws: Workspace) -> str:
    """A short, stable ID for a workspace that reveals nothing about its secret."""
    return hashlib.sha256(b"workspace-id:" + bytes.fromhex(ws.state["secret"])).hexdigest()[:10]


def _local(iso: str) -> str:
    """A stored UTC timestamp as local time, e.g. 2026-10-30 09:20."""
    try:
        return datetime.fromisoformat(iso).astimezone().strftime("%Y-%m-%d %H:%M")
    except ValueError:
        return iso


def build(ws: Workspace, name: Optional[str] = None) -> Dict[str, Any]:
    challenges = []
    for c in ordered():
        solved_at = ws.state["solved"].get(c.id)
        challenges.append({
            "id": c.id,
            "title": c.title,
            "track": c.track,
            "difficulty": c.difficulty,
            "solved": solved_at is not None,
            "solved_at": solved_at,
            "hints_used": min(ws.next_hint_index(c.id), len(c.hints)),
            "hints_total": len(c.hints),
        })
    solved = sum(c["solved"] for c in challenges)
    return {
        "student": name or getpass.getuser(),
        "machine": platform.node(),
        "workspace_id": workspace_id(ws),
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "cyberlab_version": __version__,
        "solved": solved,
        "total": len(challenges),
        "challenges": challenges,
    }


def as_json(report: Dict[str, Any]) -> str:
    return json.dumps(report, indent=2) + "\n"


def as_text(report: Dict[str, Any]) -> str:
    total = report["total"]
    pct = round(100 * report["solved"] / total) if total else 0
    lines = [
        "cyberlab progress report",
        "",
        f"Student:    {report['student']}",
        f"Machine:    {report['machine']}",
        f"Workspace:  {report['workspace_id']}",
        f"Generated:  {_local(report['generated_at'])}",
        f"Version:    cyberlab {report['cyberlab_version']}",
        "",
        f"Solved {report['solved']} of {total} ({pct}%)",
        "",
        f"{'ID':<16} {'TRACK':<9} {'LEVEL':<8} {'SOLVED':<18} HINTS",
    ]
    for c in report["challenges"]:
        when = _local(c["solved_at"]) if c["solved"] else "-"
        lines.append(f"{c['id']:<16} {c['track']:<9} {c['difficulty']:<8} {when:<18} "
                     f"{c['hints_used']}/{c['hints_total']}")
    return "\n".join(lines) + "\n"
