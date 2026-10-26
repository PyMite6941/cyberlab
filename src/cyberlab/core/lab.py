"""Core lab framework: scenario registry and base scenario class.

This module defines the data model and registry for guided practice scenarios.
Each scenario represents a hands-on lab (e.g. "BurpSuite Basics") that maps to
a simulator module (burp, wireshark, etc.) and a runnable function.

Scenarios self-register at import time via the module-level ``registry``
instance, so adding a new scenario in any module automatically makes it
available through ``cyberterminal labs`` and ``cyberterminal run <id>``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional


@dataclass
class Scenario:
    """A single guided practice scenario.

    Attributes:
        id: Unique identifier (e.g. ``burp-01``).
        title: Human-readable title shown in lists.
        description: One-paragraph summary of what the lab teaches.
        module: Name of the simulator module (``burp``, ``wireshark``, ...).
        run: Callable that executes the lab (must return an int exit code).
        tags: Searchable category tags (e.g. ``["web", "proxy", "offline"]``).
    """

    id: str
    title: str
    description: str
    module: str  # module name to load (e.g. "burp", "wireshark")
    run: Callable[[], int]
    tags: List[str] = field(default_factory=list)


class LabRegistry:
    """Holds all registered scenarios in a central index.

    Scenarios are added via :meth:`register`, typically at module import time
    by each simulator module. The registry is the single source of truth for
    ``labs`` and ``run`` commands in the terminal.
    """

    def __init__(self) -> None:
        self._scenarios: Dict[str, Scenario] = {}

    def register(self, scenario: Scenario) -> None:
        """Register a scenario by its unique ``id``."""
        self._scenarios[scenario.id] = scenario

    def list(self) -> List[Scenario]:
        """Return all scenarios sorted by ID."""
        return sorted(self._scenarios.values(), key=lambda s: s.id)

    def get(self, scenario_id: str) -> Optional[Scenario]:
        """Return a scenario by ID, or None if not found."""
        return self._scenarios.get(scenario_id)

    def modules(self) -> List[str]:
        """Return the sorted unique list of simulator module names."""
        return sorted({s.module for s in self._scenarios.values()})


# Global registry instance. Imported by terminal.py and simulator modules.
registry = LabRegistry()
