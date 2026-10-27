"""Core challenge framework: base Challenge class and challenge registry.

This module defines the data model and registry for guided practice challenges.
Each challenge represents a hands-on cybersecurity exercise (e.g. "Analyze this
pcap for malicious packets", "Find the SQL injection in this HTTP traffic").

Key design principles:
- Challenges GENERATE dynamic data each time they are instantiated.
- Challenges VERIFY answers against computed values, NOT hardcoded strings.
- Packet captures and traffic dumps are written to real files in data/captures/.
- Tutorials guide users but never contain the answer/flag.
- Everything is fully offline - no real network traffic.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
CAPTURES_DIR = DATA_DIR / "captures"
CAPTURES_DIR.mkdir(parents=True, exist_ok=True)


@dataclass
class ChallengeResult:
    """Result of a challenge verification attempt."""

    challenge_id: str
    submitted_answer: Any
    correct: bool
    feedback: str
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


@dataclass
class Challenge:
    """A single guided practice challenge.

    Attributes:
        id: Unique identifier (e.g. ``wireshark-dns-01``).
        title: Human-readable title.
        category: Domain category (e.g. ``web``, ``network``, ``auth``).
        module: Which simulator module this challenge uses.
        description: Brief summary of what the challenge teaches.
        vulnerability: The single vulnerability/skill this isolates.
        difficulty: ``easy``, ``medium``, or ``hard``.
        track: Which learning track this belongs to.
        steps: Ordered list of step dicts (description, command, notes).
        ai_enabled: Whether AI hints are available for this challenge.
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
    ai_enabled: bool = True
    requires_online: bool = False

    # These are set by subclasses at runtime - NOT hardcoded in data files
    _expected_answer: Optional[str] = None
    _challenge_data: Optional[dict] = None

    def generate(self) -> dict:
        """Generate challenge data. Returns a dict with all challenge-specific
        data that the user needs to see (packets, HTTP traffic, etc.).

        Subclasses must override this. The generated data should be written
        to files (e.g. pcap captures) and returned so the user can inspect
        them.
        """
        raise NotImplementedError

    def verify(self, submitted_answer: str) -> ChallengeResult:
        """Verify a user's submitted answer against the expected answer.

        Subclasses must override this. The comparison should be based on
        computed values from generate(), NOT hardcoded strings.
        """
        raise NotImplementedError

    def get_hint(self) -> str:
        """Return a hint for this challenge. Difficulty-appropriate."""
        return "Try examining the data more carefully."

    def requires_network(self) -> bool:
        """Return True if this challenge requires network access."""
        return self.requires_online

    def to_dict(self) -> dict:
        """Serialize challenge metadata (without sensitive answer data)."""
        return {
            "id": self.id,
            "title": self.title,
            "category": self.category,
            "module": self.module,
            "description": self.description,
            "vulnerability": self.vulnerability,
            "difficulty": self.difficulty,
            "track": self.track,
            "steps": self.steps,
            "ai_enabled": self.ai_enabled,
            "requires_online": self.requires_online,
        }


class ChallengeRegistry:
    """Holds all registered challenge classes.

    Challenges are registered by module at import time. The registry is the
    single source of truth for listing and instantiating challenges.
    """

    def __init__(self) -> None:
        self._challenges: Dict[str, Challenge] = {}
        self._track_order: List[str] = []

    def register(self, challenge: Challenge) -> None:
        """Register a challenge instance."""
        self._challenges[challenge.id] = challenge
        if challenge.track not in self._track_order:
            self._track_order.append(challenge.track)

    def get(self, challenge_id: str) -> Optional[Challenge]:
        return self._challenges.get(challenge_id)

    def list_all(self) -> List[Challenge]:
        return sorted(self._challenges.values(), key=lambda c: c.id)

    def list_tracks(self) -> List[str]:
        return list(self._track_order)

    def list_by_track(self, track_id: str) -> List[Challenge]:
        return [t for t in self._challenges.values() if t.track == track_id]

    def list_by_difficulty(self, difficulty: str) -> List[Challenge]:
        return [t for t in self._challenges.values() if t.difficulty == difficulty]

    def list_by_category(self, category: str) -> List[Challenge]:
        return [t for t in self._challenges.values() if t.category == category]


# Global registry instance
registry = ChallengeRegistry()