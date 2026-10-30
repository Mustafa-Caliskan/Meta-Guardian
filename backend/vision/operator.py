"""Pixel-level operator presence detection.

Honest scope: this is **motion/silhouette analysis against a clean baseline
frame**, not face recognition and not biometric identification. It answers one
narrow question the policy engine needs: *did something operator-sized move in
front of the console during this event, or was the seat empty?*

Why it matters: the Ghost Attack scenario must not be decided by a hard-coded
boolean. ``operator_present`` is computed here from the frame captured at
incident time, and the same ROI is then handed to SAM 3.1 for segmentation.

Tamper handling: a covered lens does not look like "nobody is at the desk", it
looks like a flat frame. Without an explicit check, a flat frame produces the
same low-motion verdict as an empty seat — a confident wrong answer. A flat,
blown-out or unreadable frame is therefore reported as ``tampered`` and never as
"no operator present".
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

# A real webcam with the lens covered is not pure black: auto-exposure raises it
# to a dark, slightly noisy grey. These limits therefore treat "almost no detail"
# as tampering, using luminance spread rather than a single pixel value.
DEFAULT_TAMPER_DARK_MEAN = 22.0
DEFAULT_TAMPER_BRIGHT_MEAN = 240.0
DEFAULT_TAMPER_MIN_STDDEV = 3.0


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
    tampered: bool = False
    tamper_reason: str = ""
    frame_mean: float = 0.0
    frame_stddev: float = 0.0

    def to_summary(self) -> str:
        if self.tampered:
            return f"camera tampered ({self.tamper_reason}) via {self.method}"
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
        tamper_dark_mean: float = DEFAULT_TAMPER_DARK_MEAN,
        tamper_bright_mean: float = DEFAULT_TAMPER_BRIGHT_MEAN,
        tamper_min_stddev: float = DEFAULT_TAMPER_MIN_STDDEV,
    ) -> None:
        self._baseline = baseline
        self.baseline_path = Path(baseline_path) if baseline_path is not None else None
        self.motion_threshold = float(motion_threshold)
        self.min_area = int(min_area)
        self.max_motion_ratio = float(max_motion_ratio)
        self.tamper_dark_mean = float(tamper_dark_mean)
        self.tamper_bright_mean = float(tamper_bright_mean)
        self.tamper_min_stddev = float(tamper_min_stddev)

    @property
    def baseline(self) -> np.ndarray | None:
        if self._baseline is None and self.baseline_path is not None:
            self._baseline = load_frame(self.baseline_path)
        return self._baseline

    def _check_tamper(self, frame: np.ndarray) -> tuple[bool, str, float, float]:
        """Return (tampered, reason, mean, stddev) for the captured frame.

        Runs before any motion analysis, because a flat frame would otherwise be
        scored as "no motion" with high confidence.
        """
        if frame is None or frame.size == 0:
            return True, "empty frame", 0.0, 0.0

        if frame.ndim == 3:
            gray = frame.mean(axis=2)
        else:
            gray = frame.astype(np.float32)

        mean = float(gray.mean())
        stddev = float(gray.std())

        if stddev < self.tamper_min_stddev and mean < self.tamper_dark_mean:
            return (
                True,
                f"lens covered or camera in the dark (mean {mean:.1f}, spread {stddev:.1f})",
                mean,
                stddev,
            )
        if stddev < self.tamper_min_stddev and mean > self.tamper_bright_mean:
            return (
                True,
                f"frame blown out (mean {mean:.1f}, spread {stddev:.1f})",
                mean,
                stddev,
            )
        if stddev < self.tamper_min_stddev:
            return (
                True,
                f"frame has no detail (spread {stddev:.1f}); lens obstructed",
                mean,
                stddev,
            )
        return False, "", mean, stddev

    def detect(self, frame: np.ndarray) -> PresenceResult:
        baseline = self.baseline
        if baseline is None:
            raise BaselineUnavailableError(
                "no baseline frame configured; pass baseline= or baseline_path="
            )

        tampered, tamper_reason, mean, stddev = self._check_tamper(frame)
        if tampered:
            return PresenceResult(
                present=False,
                confidence=0.0,
                roi=None,
                motion_ratio=0.0,
                method="tamper_check",
                description=(
                    "camera tampered: "
                    f"{tamper_reason}; presence cannot be established"
                ),
                baseline_path=str(self.baseline_path) if self.baseline_path else None,
                reliable=False,
                tampered=True,
                tamper_reason=tamper_reason,
                frame_mean=round(mean, 2),
                frame_stddev=round(stddev, 2),
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
                frame_mean=round(mean, 2),
                frame_stddev=round(stddev, 2),
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
            frame_mean=round(mean, 2),
            frame_stddev=round(stddev, 2),
        )


__all__ = [
    "BaselineUnavailableError",
    "DEFAULT_MOTION_THRESHOLD",
    "DEFAULT_TAMPER_BRIGHT_MEAN",
    "DEFAULT_TAMPER_DARK_MEAN",
    "DEFAULT_TAMPER_MIN_STDDEV",
    "PresenceDetector",
    "PresenceResult",
]
