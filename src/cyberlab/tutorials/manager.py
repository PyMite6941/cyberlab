"""Tutorial management: load, search, and open tutorials from data.json."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


@dataclass
class TutorialStep:
    description: str
    command: str
    notes: str = ""


@dataclass
class Tutorial:
    id: str
    title: str
    category: str
    module: str
    description: str
    steps: List[TutorialStep] = field(default_factory=list)


def _data_path() -> Path:
    return Path(__file__).resolve().parent / "data.json"


def load_tutorials() -> List[Tutorial]:
    """Load all tutorials from the bundled data.json."""
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
    """In-memory tutorial index with search and open operations."""

    def __init__(self) -> None:
        self.tutorials: List[Tutorial] = load_tutorials()
        self._by_id = {t.id: t for t in self.tutorials}

    def all(self) -> List[Tutorial]:
        return list(self.tutorials)

    def get(self, tutorial_id: str) -> Optional[Tutorial]:
        return self._by_id.get(tutorial_id)

    def search(self, query: str, category: Optional[str] = None) -> List[Tutorial]:
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
        return sorted({t.category for t in self.tutorials})
