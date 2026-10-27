"""Core package exports: lab registry, tracks, and progress."""

from src.core.lab import LabRegistry, Scenario, registry as lab_registry
from src.core.track import (
    Difficulty,
    Track,
    Tutorial,
    registry as track_registry,
)

__all__ = [
    "LabRegistry",
    "Scenario",
    "Difficulty",
    "Track",
    "Tutorial",
    "registry",
    "track_registry",
    "lab_registry",
]
