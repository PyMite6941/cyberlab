"""Tutorial management: load, search, and open tutorials from data.json.

Tutorials are bundled as JSON in ``tutorials/data.json``. Each tutorial has an
id, title, category, module, description, and a list of steps with commands.

The :class:`TutorialManager` loads them into memory and provides search,
filter-by-category, and lookup-by-id operations used by the terminal's
``tutorials`` and ``tutorial <id>`` commands.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


@dataclass
class TutorialStep:
    """A single step within a tutorial.

    Attributes:
        description: Human-readable explanation of what to do.
        command: The exact command to type in the terminal.
        notes: Optional hint or context (shown with a ``#`` prefix).
    """

    description: str
    command: str
    notes: str = ""


@dataclass
class Tutorial:
    """A complete guided tutorial.

    Attributes:
        id: Unique identifier (e.g. ``burp-basics``).
        title: Human-readable title.
        category: Domain category (e.g. ``web``, ``network``).
        module: Which simulator module this tutorial uses (``burp``, ``wireshark``).
        description: Summary of what the tutorial teaches.
        steps: Ordered list of :class:`TutorialStep` objects.
    """

    id: str
    title: str
    category: str
    module: str
    description: str
    steps: List[TutorialStep] = field(default_factory=list)


def _data_path() -> Path:
    """Return the absolute path to the bundled ``data.json``."""
    return Path(__file__).resolve().parent / "data.json"


def load_tutorials() -> List[Tutorial]:
    """Load all tutorials from the bundled ``data.json``.

    Returns an empty list if the file is missing or contains no tutorials.
    """
    path = _data_path()
    if not path.exists():
        return []
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    out: List[Tutorial] = []
    for item in raw.get("tutorials", []):
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
                steps=steps,
            )
        )
    return out


class TutorialManager:
    """In-memory tutorial index with search, filter, and lookup operations.

    Loaded once at construction from ``data.json``. Used by the terminal's
    ``tutorials`` (list/search) and ``tutorial <id>`` (show steps) commands.
    """

    def __init__(self) -> None:
        self.tutorials: List[Tutorial] = load_tutorials()
        self._by_id = {t.id: t for t in self.tutorials}

    def all(self) -> List[Tutorial]:
        """Return a copy of all loaded tutorials."""
        return list(self.tutorials)

    def get(self, tutorial_id: str) -> Optional[Tutorial]:
        """Return a tutorial by ID, or None if not found."""
        return self._by_id.get(tutorial_id)

    def search(self, query: str, category: Optional[str] = None) -> List[Tutorial]:
        """Search tutorials by text, optionally filtered by category.

        Matches against title, description, category, module, and step
        commands/descriptions. Case-insensitive substring match.
        """
        q = query.lower()
        results = []
        for t in self.tutorials:
            if category and t.category != category:
                continue
            haystack = (
                t.title + " " + t.description + " " + t.category + " " + t.module
            ).lower()
            if q in haystack or any(
                q in (s.command + " " + s.description).lower() for s in t.steps
            ):
                results.append(t)
        return results

    def categories(self) -> List[str]:
        """Return the sorted unique list of tutorial categories."""
        return sorted({t.category for t in self.tutorials})
