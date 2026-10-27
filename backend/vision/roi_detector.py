"""Frame-differencing ROI extraction.

Given a clean baseline frame and the frame captured at incident time, compute a
binary motion mask and a union bounding box of everything that changed. The bbox
is then used as the prompt for SAM 3.1 (or as the offline mask itself).
"""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np

try:  # pragma: no cover - exercised only when OpenCV is missing
    import cv2
except ImportError:  # pragma: no cover
    cv2 = None  # type: ignore[assignment]

DEFAULT_BLUR = 5
DEFAULT_THRESHOLD = 25
DEFAULT_MIN_AREA = 400


@dataclass
class MotionResult:
    roi: list[int] | None
    motion_ratio: float
    changed: bool
    threshold: int
    diff_mask: np.ndarray = field(repr=False)
    contours: int = 0

    @property
    def bbox_area(self) -> int:
        if not self.roi:
            return 0
        return int(self.roi[2]) * int(self.roi[3])


def _require_cv2():
    if cv2 is None:  # pragma: no cover
        raise RuntimeError("OpenCV (cv2) is not installed")
    return cv2


def to_gray(frame: np.ndarray) -> np.ndarray:
    if frame.ndim == 2:
        return frame
    return _require_cv2().cvtColor(frame, cv2.COLOR_BGR2GRAY)


def align(baseline: np.ndarray, current: np.ndarray) -> np.ndarray:
    if baseline.shape[:2] == current.shape[:2]:
        return current
    return _require_cv2().resize(current, (baseline.shape[1], baseline.shape[0]))


def compute_diff(
    baseline: np.ndarray,
    current: np.ndarray,
    *,
    blur: int = DEFAULT_BLUR,
    threshold: int = DEFAULT_THRESHOLD,
) -> np.ndarray:
    cv2_module = _require_cv2()
    current = align(baseline, current)
    gray_base = to_gray(baseline)
    gray_cur = to_gray(current)

    if blur and blur > 1:
        ksize = (blur, blur) if blur % 2 == 1 else (blur + 1, blur + 1)
        gray_base = cv2_module.GaussianBlur(gray_base, ksize, 0)
        gray_cur = cv2_module.GaussianBlur(gray_cur, ksize, 0)

    delta = cv2_module.absdiff(gray_base, gray_cur)
    _, mask = cv2_module.threshold(delta, threshold, 255, cv2.THRESH_BINARY)
    kernel = np.ones((3, 3), np.uint8)
    mask = cv2_module.morphologyEx(mask, cv2.MORPH_OPEN, kernel, iterations=1)
    mask = cv2_module.dilate(mask, kernel, iterations=2)
    return mask


def _mask_bbox(mask: np.ndarray) -> list[int] | None:
    ys, xs = np.nonzero(mask)
    if xs.size == 0 or ys.size == 0:
        return None
    x0, x1 = int(xs.min()), int(xs.max())
    y0, y1 = int(ys.min()), int(ys.max())
    return [x0, y0, x1 - x0 + 1, y1 - y0 + 1]


def find_roi(mask: np.ndarray, min_area: int = DEFAULT_MIN_AREA) -> list[int] | None:
    """Union bbox of contours larger than ``min_area``; falls back to mask bbox."""
    cv2_module = _require_cv2()
    contours, _ = cv2_module.findContours(
        mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE
    )

    boxes: list[tuple[int, int, int, int]] = []
    for contour in contours:
        x, y, w, h = cv2_module.boundingRect(contour)
        if w * h >= min_area:
            boxes.append((x, y, w, h))

    if not boxes:
        if contours and int(mask.sum()) > 0:
            return _mask_bbox(mask)
        return None

    x0 = min(box[0] for box in boxes)
    y0 = min(box[1] for box in boxes)
    x1 = max(box[0] + box[2] for box in boxes)
    y1 = max(box[1] + box[3] for box in boxes)
    return [x0, y0, x1 - x0, y1 - y0]


def detect_motion(
    baseline: np.ndarray,
    current: np.ndarray,
    *,
    blur: int = DEFAULT_BLUR,
    threshold: int = DEFAULT_THRESHOLD,
    min_area: int = DEFAULT_MIN_AREA,
    min_ratio: float = 0.002,
) -> MotionResult:
    mask = compute_diff(baseline, current, blur=blur, threshold=threshold)
    roi = find_roi(mask, min_area=min_area)
    total = mask.shape[0] * mask.shape[1] or 1
    ratio = float(np.count_nonzero(mask)) / float(total)
    cv2_module = _require_cv2()
    found, _ = cv2_module.findContours(
        mask, cv2_module.RETR_EXTERNAL, cv2_module.CHAIN_APPROX_SIMPLE
    )
    contours = int(len(found))
    changed = roi is not None and ratio >= min_ratio
    return MotionResult(
        roi=roi if changed else None,
        motion_ratio=round(ratio, 6),
        changed=changed,
        threshold=threshold,
        diff_mask=mask,
        contours=contours,
    )


def crop_roi(frame: np.ndarray, roi: list[int]) -> np.ndarray:
    x, y, w, h = (int(value) for value in roi)
    height, width = frame.shape[:2]
    x = max(0, min(x, width - 1))
    y = max(0, min(y, height - 1))
    w = max(1, min(w, width - x))
    h = max(1, min(h, height - y))
    return frame[y : y + h, x : x + w]


def mask_from_roi(shape: tuple[int, ...], roi: list[int]) -> np.ndarray:
    mask = np.zeros(shape[:2], dtype=np.uint8)
    x, y, w, h = (int(value) for value in roi)
    mask[max(0, y) : max(0, y) + max(0, h), max(0, x) : max(0, x) + max(0, w)] = 255
    return mask
