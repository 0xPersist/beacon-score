"""beacon-score: Multi-signal C2 beacon detection engine."""

__version__ = "1.0.0"
__author__ = "NorthQuinn Inc."

from .engine import BeaconCandidate, SignalResult, score_candidate, DEFAULT_WEIGHTS
from .correlator import correlate_and_score

__all__ = [
    "BeaconCandidate",
    "SignalResult",
    "score_candidate",
    "correlate_and_score",
    "DEFAULT_WEIGHTS",
]
