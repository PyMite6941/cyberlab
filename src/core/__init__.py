"""Core package exports: lab registry, tracks, and submissions."""

from src.core.lab import LabRegistry, Scenario, registry as lab_registry
from src.core.track import (
    Difficulty,
    Track,
    Tutorial,
    registry as track_registry,
)
from src.core.submission import (
    SUBMISSIONS_PATH,
    get_progress,
    load_progress,
    record_submission,
    verify_submission,
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
    "SUBMISSIONS_PATH",
    "get_progress",
    "load_progress",
    "record_submission",
    "verify_submission",
]
