"""Core package exports: lab registry, tracks, progress, and crash logging."""

from src.core.crashlog import crash_handler, format_crash, log_error
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
    "crash_handler",
    "format_crash",
    "log_error",
]
