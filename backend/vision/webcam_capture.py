"""Single-frame webcam capture with a recorded-scenario fallback.

Meta-Guardian never streams video to the cloud: it grabs exactly one frame when
an event fires. If no camera is available (CI, demo machine without permission,
locked laptop) the capture transparently falls back to a recorded frame from
``data/scenarios/`` so the pipeline stays demonstrable and testable.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Literal

import numpy as np

try:  # pragma: no cover - exercised only when OpenCV is missing
    import cv2
except ImportError:  # pragma: no cover
    cv2 = None  # type: ignore[assignment]

from ..config import SCENARIOS_DIR, get_settings

FrameProvider = Callable[[], np.ndarray | None]

IMAGE_SUFFIXES = (".png", ".jpg", ".jpeg", ".bmp", ".webp")
DEFAULT_FALLBACK_ORDER = ("operator_present.png", "operator_absent.png", "hand_usb.png")


class FrameUnavailableError(RuntimeError):
    """Raised when neither a camera nor a recorded frame is available."""


@dataclass
class CapturedFrame:
    image: np.ndarray
    source: Literal["webcam", "fallback"]
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    path: Path | None = None
    detail: str = ""

    @property
    def width(self) -> int:
        return int(self.image.shape[1])

    @property
    def height(self) -> int:
        return int(self.image.shape[0])

    def save(self, destination: Path | str) -> Path:
        return save_frame(self.image, Path(destination))


def _require_cv2():
    if cv2 is None:  # pragma: no cover
        raise FrameUnavailableError("OpenCV (cv2) is not installed")
    return cv2


def save_frame(image: np.ndarray, destination: Path) -> Path:
    """Write an image to disk without OpenCV's Unicode path limitation.

    ``cv2.imwrite`` fails on Windows paths containing non-ASCII characters
    (for example a Turkish user folder). Encoding in memory and writing with
    ``Path.write_bytes`` keeps the pipeline working for every user.
    """
    cv2_module = _require_cv2()
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    suffix = destination.suffix or ".png"
    ok, buffer = cv2_module.imencode(suffix, image)
    if not ok:
        raise FrameUnavailableError(f"could not encode frame for {destination}")
    destination.write_bytes(buffer.tobytes())
    return destination


def load_frame(path: Path | str) -> np.ndarray:
    cv2_module = _require_cv2()
    path = Path(path)
    try:
        raw = np.frombuffer(path.read_bytes(), dtype=np.uint8)
    except OSError as exc:
        raise FrameUnavailableError(f"could not read frame from {path}: {exc}") from exc
    image = cv2_module.imdecode(raw, cv2_module.IMREAD_COLOR)
    if image is None:
        raise FrameUnavailableError(f"could not decode frame from {path}")
    return image


class WebcamCapture:
    """Thin, testable wrapper around ``cv2.VideoCapture``."""

    def __init__(
        self,
        camera_index: int | None = None,
        *,
        warmup_frames: int = 3,
        provider: FrameProvider | None = None,
    ) -> None:
        self.camera_index = (
            get_settings().webcam_index if camera_index is None else camera_index
        )
        self.warmup_frames = max(0, warmup_frames)
        self._provider = provider
        self._capture = None
        self.last_error = ""

    @property
    def is_open(self) -> bool:
        if self._provider is not None:
            return True
        return bool(self._capture is not None and self._capture.isOpened())

    def open(self) -> bool:
        if self._provider is not None:
            return True
        if self._capture is not None and self._capture.isOpened():
            return True
        if cv2 is None:  # pragma: no cover
            self.last_error = "OpenCV not installed"
            return False
        try:
            capture = cv2.VideoCapture(self.camera_index)
            if not capture.isOpened():
                capture.release()
                self.last_error = f"camera {self.camera_index} could not be opened"
                return False
            self._capture = capture
            for _ in range(self.warmup_frames):
                capture.read()
            return True
        except Exception as exc:  # noqa: BLE001 - camera backends raise many types
            self.last_error = f"{type(exc).__name__}: {exc}"
            return False

    def read(self) -> np.ndarray | None:
        if self._provider is not None:
            try:
                frame = self._provider()
            except Exception as exc:  # noqa: BLE001
                self.last_error = f"{type(exc).__name__}: {exc}"
                return None
            return frame
        if not self.open():
            return None
        ok, frame = self._capture.read()  # type: ignore[union-attr]
        if not ok or frame is None:
            self.last_error = "camera returned an empty frame"
            return None
        return frame

    def close(self) -> None:
        if self._capture is not None:
            try:
                self._capture.release()
            finally:
                self._capture = None

    def __enter__(self) -> "WebcamCapture":
        self.open()
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()


def find_fallback_frame(
    fallback_dir: Path | None = None,
    preferred: str | None = None,
) -> Path:
    directory = Path(fallback_dir or SCENARIOS_DIR)
    if preferred:
        candidate = directory / preferred
        if candidate.is_file():
            return candidate

    for name in DEFAULT_FALLBACK_ORDER:
        candidate = directory / name
        if candidate.is_file():
            return candidate

    if directory.is_dir():
        for candidate in sorted(directory.iterdir()):
            if candidate.suffix.lower() in IMAGE_SUFFIXES and candidate.is_file():
                return candidate

    raise FrameUnavailableError(
        f"no camera and no recorded frame found in {directory}"
    )


def capture_frame(
    output_path: Path | str | None = None,
    *,
    camera_index: int | None = None,
    fallback_dir: Path | None = None,
    fallback_name: str | None = None,
    provider: FrameProvider | None = None,
    warmup_frames: int = 3,
) -> CapturedFrame:
    """Grab one frame from the camera, else from a recorded scenario.

    ``provider`` is for tests: a callable returning a BGR ndarray or ``None``.
    """
    capture = WebcamCapture(
        camera_index, warmup_frames=warmup_frames, provider=provider
    )
    started = time.perf_counter()
    try:
        image = capture.read()
        source: Literal["webcam", "fallback"] = "webcam"
        detail = ""
        if image is None:
            fallback_path = find_fallback_frame(fallback_dir, fallback_name)
            image = load_frame(fallback_path)
            source = "fallback"
            detail = f"webcam unavailable ({capture.last_error}); used {fallback_path.name}"
    finally:
        capture.close()

    elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
    frame = CapturedFrame(image=image, source=source, detail=detail or f"{elapsed_ms} ms")

    if output_path is not None:
        frame.path = frame.save(output_path)
    return frame
