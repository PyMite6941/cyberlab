"""Challenge definitions and the registry the CLI reads.

A challenge is one file in this package that defines a Challenge and calls
register(). To add one: copy an existing file, change the fields, setup()
and (if the answer isn't a flag) check(), and import it at the bottom here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from cyberlab.workspace import Workspace


@dataclass
class Challenge:
    id: str
    title: str
    track: str        # web, network, logs ...
    difficulty: str   # easy, medium, hard
    goal: str         # one or two sentences shown by `start`
    hints: List[str] = field(default_factory=list)
    tools: List[str] = field(default_factory=list)  # suggested real tools

    def setup(self, ws: Workspace) -> str:
        """Start targets / write files; return what the student needs to know."""
        return ""

    def check(self, ws: Workspace, answer: str) -> bool:
        """Default: the answer is this challenge's flag."""
        return ws.matches_flag(self.id, answer)


REGISTRY: Dict[str, Challenge] = {}
TRACK_ORDER = ["web", "network", "logs"]
DIFFICULTY_ORDER = ["easy", "medium", "hard"]


def register(challenge: Challenge) -> Challenge:
    if challenge.id in REGISTRY:
        raise ValueError(f"duplicate challenge id: {challenge.id}")
    REGISTRY[challenge.id] = challenge
    return challenge


def ordered() -> List[Challenge]:
    def key(c: Challenge):
        track = TRACK_ORDER.index(c.track) if c.track in TRACK_ORDER else len(TRACK_ORDER)
        return (track, DIFFICULTY_ORDER.index(c.difficulty), c.id)
    return sorted(REGISTRY.values(), key=key)


# Each module registers its challenge on import.
from cyberlab.challenges import web_sqli  # noqa: E402,F401
