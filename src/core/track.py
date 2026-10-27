"""Core track system: organized learning paths with difficulty modes.

A Track groups related tutorials into a progressive learning path (e.g.
"Web Application Security"). Each tutorial within a track has a difficulty
(easy/medium/hard) and targets exactly one vulnerability so the user can
focus on identifying and exploiting that single issue.

Tracks, difficulties, and submissions are persisted locally so progress
survives between sessions.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


VALID_DIFFICULTIES = {"easy", "medium", "hard"}


@dataclass
class Difficulty:
    """A single difficulty mode for a tutorial.

    Attributes:
        name: ``easy``, ``medium``, or ``hard``.
        hint_count: How many AI hints are available at this difficulty.
        requires_submission: Whether the user must submit a flag to complete.
        max_attempts: Maximum submission attempts before lockout (None = unlimited).
    """

    name: str
    hint_count: int = 2
    requires_submission: bool = True
    max_attempts: Optional[int] = None


@dataclass
class Tutorial:
    """A guided tutorial within a track.

    Attributes:
        id: Unique identifier (e.g. ``web-sqli-01``).
        title: Human-readable title.
        category: Domain category (e.g. ``web``, ``network``).
        module: Which simulator module this tutorial uses.
        description: Summary of what the tutorial teaches (brief - not a walkthrough).
        vulnerability: The single vulnerability this tutorial isolates (e.g. ``sql_injection``).
        difficulty: Default difficulty (``easy``/``medium``/``hard``).
        track: Track ID this tutorial belongs to.
        steps: Ordered list of step dicts (description, command, notes).
        flag: The secret string the user must submit to complete (if any).
        ai_enabled: Whether AI hints are available for this tutorial.
    """

    id: str
    title: str
    category: str
    module: str
    description: str
    vulnerability: str
    difficulty: str = "easy"
    track: str = ""
    steps: List[dict] = field(default_factory=list)
    flag: Optional[str] = None
    ai_enabled: bool = True


@dataclass
class Track:
    """A learning path grouping related tutorials.

    Attributes:
        id: Unique identifier (e.g. ``web-security``).
        title: Human-readable title.
        description: What this track teaches.
        tutorials: Ordered list of tutorial IDs in this track.
    """

    id: str
    title: str
    description: str
    tutorials: List[str] = field(default_factory=list)


@dataclass
class Submission:
    """A user's submission for a tutorial.

    Attributes:
        tutorial_id: Which tutorial was attempted.
        flag: What the user submitted.
        correct: Whether the submission matched the flag.
        timestamp: ISO-8601 timestamp of the submission.
    """

    tutorial_id: str
    flag: str
    correct: bool
    timestamp: str


class TrackRegistry:
    """Holds all tracks, tutorials, difficulty settings, and submissions."""

    def __init__(self) -> None:
        self.tracks: Dict[str, Track] = {}
        self.tutorials: Dict[str, Tutorial] = {}
        self.submissions: List[Submission] = []
        self._track_order: List[str] = []

    # ----- tracks -----

    def register_track(self, track: Track) -> None:
        self.tracks[track.id] = track
        if track.id not in self._track_order:
            self._track_order.append(track.id)

    def get_track(self, track_id: str) -> Optional[Track]:
        return self.tracks.get(track_id)

    def list_tracks(self) -> List[Track]:
        return [self.tracks[tid] for tid in self._track_order if tid in self.tracks]

    # ----- tutorials -----

    def register_tutorial(self, tutorial: Tutorial) -> None:
        self.tutorials[tutorial.id] = tutorial

    def get_tutorial(self, tutorial_id: str) -> Optional[Tutorial]:
        return self.tutorials.get(tutorial_id)

    def list_tutorials(self, track_id: Optional[str] = None) -> List[Tutorial]:
        if track_id is None:
            return list(self.tutorials.values())
        track = self.get_track(track_id)
        if track is None:
            return []
        return [self.tutorials[tid] for tid in track.tutorials if tid in self.tutorials]

    def list_by_difficulty(self, difficulty: str) -> List[Tutorial]:
        return [t for t in self.tutorials.values() if t.difficulty == difficulty]

    # ----- submissions -----

    def add_submission(self, tutorial_id: str, flag: str, correct: bool,
                       timestamp: str) -> Submission:
        sub = Submission(tutorial_id=tutorial_id, flag=flag,
                         correct=correct, timestamp=timestamp)
        self.submissions.append(sub)
        return sub

    def get_submissions_for(self, tutorial_id: str) -> List[Submission]:
        return [s for s in self.submissions if s.tutorial_id == tutorial_id]

    def is_completed(self, tutorial_id: str) -> bool:
        return any(s.correct for s in self.get_submissions_for(tutorial_id))

    def completed_count(self, track_id: Optional[str] = None) -> int:
        if track_id is None:
            return sum(1 for t in self.tutorials.values() if self.is_completed(t.id))
        tuts = self.list_tutorials(track_id)
        return sum(1 for t in tuts if self.is_completed(t.id))

    # ----- persistence -----

    def save(self, path: Path) -> None:
        data = {
            "submissions": [
                {"tutorial_id": s.tutorial_id, "flag": s.flag,
                 "correct": s.correct, "timestamp": s.timestamp}
                for s in self.submissions
            ]
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def load(self, path: Path) -> None:
        if not path.exists():
            return
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for item in data.get("submissions", []):
            self.add_submission(
                tutorial_id=item["tutorial_id"],
                flag=None,
                correct=item.get("correct", False),
                timestamp=item.get("timestamp", ""),
            )


# Global registry instance
registry = TrackRegistry()
