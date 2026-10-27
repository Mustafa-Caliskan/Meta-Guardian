"""Pixel-level operator presence detection.

Honest scope: this is **motion/silhouette analysis against a clean baseline
frame**, not face recognition and not biometric identification. It answers one
narrow question the policy engine needs: *did something operator-sized move in
front of the console during this event, or was the seat empty?*

Why it matters: the Ghost Attack scenario must not be decided by a hard-coded
boolean. ``operator_present`` is computed here from the frame captured at
incident time, and the same ROI is then handed to SAM 3.1 for segmentation.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import numpy as np

from .roi_detector import detect_motion
from .webcam_capture import load_frame

# Fraction of the frame that must change to count as "a person is here".
# Calibrated against the synthetic 640x480 demo frames; configurable per run.
DEFAULT_MOTION_THRESHOLD = 0.004


class BaselineUnavailableError(RuntimeError):
    """Raised when no clean baseline frame can be loaded."""


@dataclass
class PresenceResult:
    present: bool
    confidence: float
    roi: list[int] | None
    motion_ratio: float
    method: str
    description: str
    baseline_path: str | None = None
    reliable: bool = True

    def to_summary(self) -> str:
        state = "operator present" if self.present else "no operator"
        return (
            f"{state} ({self.confidence:.2f}) via {self.method}; "
            f"motion_ratio={self.motion_ratio:.4f}"
        )


class PresenceDetector:
    def __init__(
        self,
        baseline: np.ndarray | None = None,
        *,
        baseline_path: Path | str | None = None,
        motion_threshold: float = DEFAULT_MOTION_THRESHOLD,
        min_area: int = 900,
        max_motion_ratio: float = 0.45,
    ) -> None:
        self._baseline = baseline
        self.baseline_path = Path(baseline_path) if baseline_path is not None else None
        self.motion_threshold = float(motion_threshold)
        self.min_area = int(min_area)
        self.max_motion_ratio = float(max_motion_ratio)

    @property
    def baseline(self) -> np.ndarray | None:
        if self._baseline is None and self.baseline_path is not None:
            self._baseline = load_frame(self.baseline_path)
        return self._baseline

    def detect(self, frame: np.ndarray) -> PresenceResult:
        baseline = self.baseline
        if baseline is None:
            raise BaselineUnavailableError(
                "no baseline frame configured; pass baseline= or baseline_path="
            )

        motion = detect_motion(
            baseline,
            frame,
            min_area=self.min_area,
            min_ratio=self.motion_threshold,
        )
        if motion.motion_ratio >= self.max_motion_ratio:
            # The whole frame changed: the camera is pointed somewhere else than
            # the baseline (moved laptop, different lighting). Presence cannot be
            # inferred safely, so never claim it.
            return PresenceResult(
                present=False,
                confidence=0.2,
                roi=motion.roi,
                motion_ratio=motion.motion_ratio,
                method="baseline_diff",
                description=(
                    f"scene mismatch: {motion.motion_ratio:.1%} of the frame differs "
                    "from the baseline; recalibrate the baseline for this camera"
                ),
                baseline_path=str(self.baseline_path) if self.baseline_path else None,
                reliable=False,
            )

        present = bool(motion.changed and motion.roi)

        if present:
            # Saturating confidence: a small hand gives ~0.66, a full operator
            # silhouette saturates near 0.96. Deterministic, no model needed.
            overshoot = motion.motion_ratio / max(self.motion_threshold, 1e-6)
            confidence = min(0.96, 0.62 + 0.22 * min(overshoot, 1.6))
            description = (
                "operator-sized motion detected in the camera frame "
                f"(ROI {motion.roi}, {motion.motion_ratio:.3%} of pixels changed)"
            )
        else:
            # Low motion means we are fairly confident the seat is empty, but
            # never claim certainty from a single frame.
            confidence = max(0.55, 0.9 - motion.motion_ratio * 8)
            description = (
                "no operator-sized motion versus the clean baseline "
                f"({motion.motion_ratio:.3%} of pixels changed)"
            )

        return PresenceResult(
            present=present,
            confidence=round(confidence, 3),
            roi=motion.roi,
            motion_ratio=motion.motion_ratio,
            method="baseline_diff",
            description=description,
            baseline_path=str(self.baseline_path) if self.baseline_path else None,
        )


__all__ = [
    "BaselineUnavailableError",
    "DEFAULT_MOTION_THRESHOLD",
    "PresenceDetector",
    "PresenceResult",
]
