"""Tutorial management: load, search, and open tutorials from data.json.

Tutorials are bundled as JSON in ``tutorials/data.json``. Each tutorial has an
id, title, category, module, description, vulnerability (the single issue it
isolates), difficulty (easy/medium/hard), track (which learning path it
belongs to), steps, an optional flag to submit, and an ai_enabled flag.

The :class:`TutorialManager` loads them into memory and provides search,
filter-by-category/track/difficulty, and lookup-by-id operations used by the
terminal's ``tutorials`` and ``tutorial <id>`` commands.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


VALID_DIFFICULTIES = {"easy", "medium", "hard"}


@dataclass
class TutorialStep:
    """A single step within a tutorial.

    Attributes:
        description: Human-readable explanation of what to do (brief).
        command: The exact command to type in the terminal.
        notes: Optional hint or context (shown with a ``#`` prefix).
    """

    description: str
    command: str
    notes: str = ""


@dataclass
class Tutorial:
    """A complete guided tutorial isolating one vulnerability.

    Attributes:
        id: Unique identifier (e.g. ``web-sqli-01``).
        title: Human-readable title.
        category: Domain category (e.g. ``web``, ``network``).
        module: Which simulator module this tutorial uses.
        description: Brief summary - not a full walkthrough.
        vulnerability: The single vulnerability this isolates.
        difficulty: ``easy``, ``medium``, or ``hard``.
        track: Track ID this tutorial belongs to.
        steps: Ordered list of :class:`TutorialStep` objects.
        flag: The secret string the user submits to complete (if any).
        ai_enabled: Whether AI hints are available.
    """

    id: str
    title: str
    category: str
    module: str
    description: str
    vulnerability: str
    difficulty: str = "easy"
    track: str = ""
    steps: List[TutorialStep] = field(default_factory=list)
    flag: Optional[str] = None
    ai_enabled: bool = True


def _data_path() -> Path:
    """Return the absolute path to the bundled ``data.json``."""
    return Path(__file__).resolve().parent / "data.json"


def load_tutorials() -> List[dict]:
    """Load all tutorials from the bundled ``data.json`` as raw dicts.

    Used by submission verification and the HTML page. Returns raw dicts so
    callers can access any field without dataclass conversion.
    """
    path = _data_path()
    if not path.exists():
        return []
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    return raw.get("tutorials", [])


def load_tutorial_objects() -> List[Tutorial]:
    """Load all tutorials as :class:`Tutorial` dataclass objects."""
    raw = load_tutorials()
    out: List[Tutorial] = []
    for item in raw:
        steps = [
            TutorialStep(
                description=s.get("description", ""),
                command=s.get("command", ""),
                notes=s.get("notes", ""),
            )
            for s in item.get("steps", [])
        ]
        out.append(
            Tutorial(
                id=item.get("id", ""),
                title=item.get("title", ""),
                category=item.get("category", ""),
                module=item.get("module", ""),
                description=item.get("description", ""),
                vulnerability=item.get("vulnerability", ""),
                difficulty=item.get("difficulty", "easy"),
                track=item.get("track", ""),
                steps=steps,
                flag=item.get("flag"),
                ai_enabled=item.get("ai_enabled", True),
            )
        )
    return out


def _data_path_tracks() -> Path:
    return Path(__file__).resolve().parent / "tracks.json"


def load_tracks() -> List[dict]:
    """Load track definitions from ``tracks.json``."""
    path = _data_path_tracks()
    if not path.exists():
        return []
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    return raw.get("tracks", [])


class TutorialManager:
    """In-memory tutorial index with search, filter, and lookup operations.

    Loaded once at construction from ``data.json`` and ``tracks.json``.
    Used by the terminal's ``tutorials`` (list/search) and ``tutorial <id>``
    (show steps) commands, and by the HTML page.
    """

    def __init__(self) -> None:
        self.raw: List[dict] = load_tutorials()
        self.tutorials: List[Tutorial] = load_tutorial_objects()
        self.tracks: List[dict] = load_tracks()
        self._by_id = {t.id: t for t in self.tutorials}

    def all(self) -> List[Tutorial]:
        """Return a copy of all loaded tutorials."""
        return list(self.tutorials)

    def raw_all(self) -> List[dict]:
        """Return raw tutorial dicts (for HTML page / submission)."""
        return list(self.raw)

    def get(self, tutorial_id: str) -> Optional[Tutorial]:
        """Return a tutorial by ID, or None if not found."""
        return self._by_id.get(tutorial_id)

    def get_raw(self, tutorial_id: str) -> Optional[dict]:
        """Return a raw tutorial dict by ID."""
        for t in self.raw:
            if t.get("id") == tutorial_id:
                return t
        return None

    def search(self, query: str,
             category: Optional[str] = None,
             track: Optional[str] = None,
             difficulty: Optional[str] = None) -> List[Tutorial]:
        """Search tutorials by text, optionally filtered by category/track/difficulty.

        Matches against title, description, category, module, vulnerability,
        and step commands/descriptions. Case-insensitive substring match.
        """
        q = query.lower()
        results = []
        for t in self.tutorials:
            if category and t.category != category:
                continue
            if track and t.track != track:
                continue
            if difficulty and t.difficulty != difficulty:
                continue
            haystack = (
                t.title + " " + t.description + " " + t.category + " "
                + t.module + " " + t.vulnerability
            ).lower()
            if q in haystack or any(
                q in (s.command + " " + s.description).lower() for s in t.steps
            ):
                results.append(t)
        return results

    def categories(self) -> List[str]:
        """Return the sorted unique list of tutorial categories."""
        return sorted({t.category for t in self.tutorials})

    def tracks_list(self) -> List[dict]:
        """Return track definitions."""
        return list(self.tracks)

    def difficulties(self) -> List[str]:
        """Return sorted valid difficulties."""
        return sorted(VALID_DIFFICULTIES)

    def by_track(self, track_id: str) -> List[Tutorial]:
        """Return all tutorials belonging to a track, in track order."""
        return [t for t in self.tutorials if t.track == track_id]

    def by_difficulty(self, difficulty: str) -> List[Tutorial]:
        """Return all tutorials at a given difficulty."""
        return [t for t in self.tutorials if t.difficulty == difficulty]

    def by_vulnerability(self, vulnerability: str) -> List[Tutorial]:
        """Return all tutorials isolating a given vulnerability."""
        return [t for t in self.tutorials if t.vulnerability == vulnerability]
