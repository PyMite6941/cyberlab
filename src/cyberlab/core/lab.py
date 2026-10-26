"""Core lab framework: scenario registry and base scenario class."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional


@dataclass
class Scenario:
    """A single guided practice scenario."""

    id: str
    title: str
    description: str
    module: str  # module name to load (e.g. "burp", "wireshark")
    run: Callable[[], int]
    tags: List[str] = field(default_factory=list)


class LabRegistry:
    """Holds all registered scenarios."""

    def __init__(self) -> None:
        self._scenarios: Dict[str, Scenario] = {}

    def register(self, scenario: Scenario) -> None:
        self._scenarios[scenario.id] = scenario

    def list(self) -> List[Scenario]:
        return sorted(self._scenarios.values(), key=lambda s: s.id)

    def get(self, scenario_id: str) -> Optional[Scenario]:
        return self._scenarios.get(scenario_id)

    def modules(self) -> List[str]:
        """Unique module names across all scenarios."""
        return sorted({s.module for s in self._scenarios.values()})


# Global registry instance
registry = LabRegistry()
