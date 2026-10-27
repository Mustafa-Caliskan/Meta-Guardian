"""Meta Model API ``sam-3.1`` segmentation bridge with an offline fallback.

Live mode sends a single image plus a text prompt (optionally with a bbox hint)
to the Meta Model API Responses endpoint and parses boxes/masks defensively,
because provider response envelopes evolve.

Offline mode (no ``MODEL_API_KEY``) never touches the network: it reuses the
frame-diff mask from :mod:`roi_detector`, which is exactly the crop used for the
demo. That keeps the pipeline real, deterministic and testable.
"""

from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import numpy as np

try:  # pragma: no cover
    import cv2
except ImportError:  # pragma: no cover
    cv2 = None  # type: ignore[assignment]

from ..config import get_settings
from .roi_detector import detect_motion, mask_from_roi

DEFAULT_PROMPT = "the hand inserting the USB drive"


@dataclass
class SegmentationResult:
    boxes: list[list[int]] = field(default_factory=list)
    mask_path: Path | None = None
    model: str = "sam-3.1"
    prompt: str = ""
    fallback_used: bool = False
    latency_ms: float = 0.0
    detail: str = ""

    @property
    def primary_box(self) -> list[int] | None:
        return self.boxes[0] if self.boxes else None


def _as_int(value: Any) -> int | None:
    try:
        return int(round(float(value)))
    except (TypeError, ValueError):
        return None


def _normalize_box(raw: Any) -> list[int] | None:
    if isinstance(raw, dict):
        if {"x", "y", "w", "h"} <= set(raw):
            values = [raw["x"], raw["y"], raw["w"], raw["h"]]
        elif {"x1", "y1", "x2", "y2"} <= set(raw):
            x1, y1, x2, y2 = raw["x1"], raw["y1"], raw["x2"], raw["y2"]
            values = [x1, y1, _safe_sub(x2, x1), _safe_sub(y2, y1)]
        elif {"left", "top", "width", "height"} <= set(raw):
            values = [raw["left"], raw["top"], raw["width"], raw["height"]]
        else:
            return None
        ints = [_as_int(value) for value in values]
    elif isinstance(raw, (list, tuple)) and len(raw) >= 4:
        ints = [_as_int(value) for value in raw[:4]]
    else:
        return None
    if any(value is None for value in ints):
        return None
    return [int(value) for value in ints]  # type: ignore[arg-type]


def _safe_sub(a: Any, b: Any) -> Any:
    try:
        return float(a) - float(b)
    except (TypeError, ValueError):
        return 0


def extract_boxes(payload: Any, *, _depth: int = 0) -> list[list[int]]:
    """Find boxes anywhere in an unknown response envelope."""
    if _depth > 8:
        return []
    boxes: list[list[int]] = []

    if isinstance(payload, dict):
        for key in ("boxes", "bboxes", "detections", "masks"):
            if key in payload:
                boxes.extend(_boxes_from_collection(payload[key]))
        if "box" in payload:
            normalized = _normalize_box(payload["box"])
            if normalized:
                boxes.append(normalized)
        for value in payload.values():
            if isinstance(value, (dict, list)):
                boxes.extend(extract_boxes(value, _depth=_depth + 1))
            elif isinstance(value, str) and value.strip().startswith(("{", "[")):
                try:
                    parsed = json.loads(value)
                except json.JSONDecodeError:
                    continue
                boxes.extend(extract_boxes(parsed, _depth=_depth + 1))
    elif isinstance(payload, list):
        for item in payload:
            boxes.extend(extract_boxes(item, _depth=_depth + 1))

    deduped: list[list[int]] = []
    for box in boxes:
        if box not in deduped:
            deduped.append(box)
    return deduped


def _boxes_from_collection(collection: Any) -> list[list[int]]:
    boxes: list[list[int]] = []
    if isinstance(collection, dict):
        normalized = _normalize_box(collection)
        return [normalized] if normalized else []
    if not isinstance(collection, list):
        return []
    for item in collection:
        normalized = _normalize_box(item)
        if normalized:
            boxes.append(normalized)
        elif isinstance(item, dict):
            boxes.extend(extract_boxes(item))
    return boxes


class SAMBridge:
    """Async SAM 3.1 client. Falls back to diff masking when unavailable."""

    def __init__(
        self,
        *,
        api_key: str | None = None,
        base_url: str | None = None,
        model: str | None = None,
        timeout: float | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        settings = get_settings()
        self.api_key = settings.meta_api_key if api_key is None else api_key
        self.base_url = (base_url or settings.meta_base_url).rstrip("/")
        self.model = model or settings.sam_model
        self.timeout = timeout if timeout is not None else settings.request_timeout
        self.transport = transport

    @property
    def available(self) -> bool:
        return bool(self.api_key)

    async def segment(
        self,
        image: np.ndarray,
        *,
        prompt: str = DEFAULT_PROMPT,
        roi: list[int] | None = None,
        baseline: np.ndarray | None = None,
        mask_path: Path | str | None = None,
    ) -> SegmentationResult:
        started = time.perf_counter()
        if self.available:
            try:
                boxes, detail = await self._call_api(image, prompt, roi)
                if boxes:
                    result = SegmentationResult(
                        boxes=boxes,
                        model=self.model,
                        prompt=prompt,
                        detail=detail,
                    )
                    result.latency_ms = round((time.perf_counter() - started) * 1000, 2)
                    result.mask_path = self._write_mask(mask_path, image, roi=boxes[0])
                    return result
                failure = detail or "SAM API returned no boxes"
            except Exception as exc:  # noqa: BLE001 - fall back on any provider error
                failure = f"{type(exc).__name__}: {exc}"
        else:
            failure = "MODEL_API_KEY not configured"

        result = self._fallback(
            image, prompt=prompt, roi=roi, baseline=baseline, detail=failure
        )
        result.latency_ms = round((time.perf_counter() - started) * 1000, 2)
        result.mask_path = self._write_mask(
            mask_path, image, roi=result.primary_box
        )
        return result

    async def _call_api(
        self, image: np.ndarray, prompt: str, roi: list[int] | None
    ) -> tuple[list[list[int]], str]:
        text = prompt
        if roi:
            x, y, w, h = roi
            text = f"{prompt}\nBounding box hint (x, y, w, h): [{x}, {y}, {w}, {h}]"

        body = {
            "model": self.model,
            "input": [
                {
                    "role": "user",
                    "content": [
                        {"type": "input_text", "text": text},
                        {"type": "input_image", "image_url": self._data_uri(image)},
                    ],
                }
            ],
        }
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        async with httpx.AsyncClient(
            timeout=self.timeout, transport=self.transport
        ) as client:
            response = await client.post(
                f"{self.base_url}/responses", headers=headers, json=body
            )
            response.raise_for_status()
            data = response.json()

        boxes = extract_boxes(data)
        return boxes, f"HTTP {response.status_code}, {len(boxes)} box(es)"

    def _fallback(
        self,
        image: np.ndarray,
        *,
        prompt: str,
        roi: list[int] | None,
        baseline: np.ndarray | None,
        detail: str,
    ) -> SegmentationResult:
        fallback_roi = roi
        if baseline is not None:
            motion = detect_motion(baseline, image)
            if motion.changed and motion.roi:
                fallback_roi = motion.roi

        boxes = [fallback_roi] if fallback_roi else []
        reason = "diff-based offline fallback" if boxes else "no ROI available offline"
        return SegmentationResult(
            boxes=boxes,
            model="diff-fallback",
            prompt=prompt,
            fallback_used=True,
            detail=f"{reason} ({detail})",
        )

    @staticmethod
    def _data_uri(image: np.ndarray) -> str:
        if cv2 is None:  # pragma: no cover
            raise RuntimeError("OpenCV (cv2) is not installed")
        ok, buffer = cv2.imencode(".jpg", image, [int(cv2.IMWRITE_JPEG_QUALITY), 85])
        if not ok:
            raise ValueError("could not encode frame as JPEG")
        encoded = base64.b64encode(buffer.tobytes()).decode("ascii")
        return f"data:image/jpeg;base64,{encoded}"

    @staticmethod
    def _write_mask(
        mask_path: Path | str | None,
        image: np.ndarray,
        *,
        roi: list[int] | None,
    ) -> Path | None:
        if mask_path is None or roi is None or cv2 is None:
            return None
        path = Path(mask_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        mask = mask_from_roi(image.shape, roi)
        if not cv2.imwrite(str(path), mask):
            return None
        return path
