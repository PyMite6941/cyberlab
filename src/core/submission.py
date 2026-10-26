"""Submission handling: local flag verification and progress storage."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from src.core.track import registry, Submission


SUBMISSIONS_PATH = Path(__file__).resolve().parent.parent / "data" / "submissions.json"


def verify_submission(tutorial_id: str, flag: str) -> bool:
    """Check whether a submitted flag matches the tutorial's expected flag.

    Returns True if the flag matches, False otherwise. The comparison is
    case-insensitive and strips surrounding whitespace.
    """
    from src.tutorials.manager import load_tutorials

    for t in load_tutorials():
        if t.get("id") == tutorial_id:
            expected = t.get("flag")
            if expected is None:
                return False
            return flag.strip().lower() == expected.strip().lower()
    return False


def record_submission(tutorial_id: str, flag: str) -> bool:
    """Record a submission and return whether it was correct.

    Persists the submission to the local submissions file so progress
    survives between sessions.
    """
    correct = verify_submission(tutorial_id, flag)
    timestamp = datetime.now(timezone.utc).isoformat()
    registry.add_submission(tutorial_id=tutorial_id, flag=flag,
                            correct=correct, timestamp=timestamp)
    registry.save(SUBMISSIONS_PATH)
    return correct


def get_progress() -> dict:
    """Return a summary of completion progress across all tutorials."""
    from src.tutorials.manager import load_tutorials

    tutorials = load_tutorials()
    total = len(tutorials)
    completed = sum(1 for t in tutorials if registry.is_completed(t.get("id", "")))
    return {
        "total": total,
        "completed": completed,
        "percent": round((completed / total * 100) if total else 0, 1),
    }


def load_progress() -> None:
    """Load previously saved submissions from disk."""
    registry.load(SUBMISSIONS_PATH)
