"""Three-tier Segment Anything bridge.

Order of preference, first working tier wins:

1. **Meta Model API ``sam-3.1``** (hosted) ? needs ``MODEL_API_KEY``.
2. **Modal GPU Segment Anything** (open weights, ``scripts/modal_sam.py``) ?
   needs ``MODAL_SAM_URL`` plus the Modal proxy token pair.
3. **Offline frame-diff mask** ? no network, always available.

The offline tier reuses :mod:`roi_detector`, so the demo stays deterministic when
there is no key, no GPU and no internet. Every result records which tier actually
produced the mask, so the cockpit never overstates what happened.
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
from .webcam_capture import save_frame

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
    mask_source: str = ""

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
        modal_url: str | None = None,
        modal_token: str | None = None,
        modal_auth: str | None = None,
        modal_timeout: float | None = None,
        modal_transport: httpx.AsyncBaseTransport | None = None,
        prefer: str = "auto",
    ) -> None:
        settings = get_settings()
        self.api_key = settings.meta_api_key if api_key is None else api_key
        self.base_url = (base_url or settings.meta_base_url).rstrip("/")
        self.model = model or settings.sam_model
        self.timeout = timeout if timeout is not None else settings.request_timeout
        self.transport = transport

        self.modal_url = (
            settings.modal_sam_url if modal_url is None else modal_url
        ).rstrip("/")
        self.modal_token = (
            settings.modal_sam_token if modal_token is None else modal_token
        )
        self.modal_auth = (
            settings.modal_proxy_auth_header if modal_auth is None else modal_auth
        )
        self.modal_timeout = (
            settings.modal_sam_timeout if modal_timeout is None else modal_timeout
        )
        self.modal_transport = modal_transport
        self.prefer = prefer

    @property
    def available(self) -> bool:
        """True when at least one networked tier is configured."""
        return bool(self.api_key or self.modal_available)

    @property
    def modal_available(self) -> bool:
        return bool(self.modal_url)

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
        failures: list[str] = []
        remote_boxes: list[list[int]] = []
        remote_model = ""
        remote_mask: str | None = None

        tiers = ["meta", "modal"]
        if self.prefer in ("meta", "modal"):
            tiers = [self.prefer] + [t for t in tiers if t != self.prefer]

        for tier in tiers:
            if tier == "meta":
                if not self.api_key:
                    failures.append("meta: MODEL_API_KEY not configured")
                    continue
                try:
                    boxes, detail, mask_b64 = await self._call_api(image, prompt, roi)
                    if boxes:
                        remote_boxes, remote_model, remote_mask = boxes, self.model, mask_b64
                        failures.append(f"meta: ok ({detail})")
                        break
                    failures.append(f"meta: {detail}")
                except Exception as exc:  # noqa: BLE001
                    failures.append(f"meta: {type(exc).__name__}: {exc}")
            else:
                if not self.modal_url:
                    failures.append("modal: MODAL_SAM_URL not configured")
                    continue
                try:
                    boxes, detail, mask_b64 = await self._call_modal(image, roi)
                    if boxes:
                        remote_boxes, remote_model, remote_mask = boxes, "sam-vit_b@modal", mask_b64
                        failures.append(f"modal: ok ({detail})")
                        break
                    failures.append(f"modal: {detail}")
                except Exception as exc:  # noqa: BLE001
                    failures.append(f"modal: {type(exc).__name__}: {exc}")

        if remote_boxes:
            result = SegmentationResult(
                boxes=remote_boxes,
                model=remote_model,
                prompt=prompt,
                detail="; ".join(failures),
                mask_source=remote_model,
            )
            result.latency_ms = round((time.perf_counter() - started) * 1000, 2)
            result.mask_path = self._persist_remote_mask(mask_path, image, remote_mask, remote_boxes[0])
            return result

        failure = "; ".join(failures) or "no segmentation tier configured"
        if self.prefer == "meta" and not self.api_key:
            failure = "MODEL_API_KEY not configured; " + failure

        result = self._fallback(
            image, prompt=prompt, roi=roi, baseline=baseline, detail=failure
        )
        result.latency_ms = round((time.perf_counter() - started) * 1000, 2)
        result.mask_path = self._write_mask(
            mask_path, image, roi=result.primary_box
        )
        return result

    async def _call_modal(
        self, image: np.ndarray, roi: list[int] | None
    ) -> tuple[list[list[int]], str, str | None]:
        """Segment on the Modal GPU service (scripts/modal_sam.py)."""
        body: dict[str, Any] = {"image_b64": self._image_b64(image)}
        if roi:
            body["box"] = [int(value) for value in roi[:4]]
        if self.modal_token:
            # Sent in the body because Modal's fastapi_endpoint exposes only the
            # JSON payload to the handler. HTTPS protects it in transit.
            body["token"] = self.modal_token
        headers = {"Content-Type": "application/json"}
        if self.modal_token:
            headers["X-MG-SAM-Token"] = self.modal_token
        if self.modal_auth:
            headers["Authorization"] = self.modal_auth

        async with httpx.AsyncClient(
            timeout=self.modal_timeout, transport=self.modal_transport
        ) as client:
            response = await client.post(self.modal_url, headers=headers, json=body)
            response.raise_for_status()
            data = response.json()

        if not isinstance(data, dict):
            raise ValueError(f"unexpected Modal response: {data!r}")
        if data.get("error"):
            raise ValueError(f"Modal service error: {data['error']}")

        boxes = extract_boxes(data)
        mask_b64 = data.get("mask_b64")
        detail = (
            f"HTTP {response.status_code}, {len(boxes)} box(es), "
            f"score={data.get('score')}, device={data.get('device')}, "
            f"gpu_ms={data.get('latency_ms')}"
        )
        return boxes, detail, mask_b64 if isinstance(mask_b64, str) else None

    async def _call_api(
        self, image: np.ndarray, prompt: str, roi: list[int] | None
    ) -> tuple[list[list[int]], str, str | None]:
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
        return boxes, f"HTTP {response.status_code}, {len(boxes)} box(es)", None

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
            mask_source="frame-diff",
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
    def _image_b64(image: np.ndarray) -> str:
        return SAMBridge._data_uri(image).split(",", 1)[1]

    @staticmethod
    def _persist_remote_mask(
        mask_path: Path | str | None,
        image: np.ndarray,
        mask_b64: str | None,
        fallback_box: list[int] | None,
    ) -> Path | None:
        """Save the mask the remote model actually produced.

        A real mask from SAM must never be replaced by a drawn rectangle. Only if
        the provider returned no mask do we fall back to the ROI geometry, and the
        result records which happened via ``mask_source``.
        """
        if mask_path is None:
            return None
        path = Path(mask_path)
        if mask_b64:
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(base64.b64decode(mask_b64))
                return path
            except Exception:  # noqa: BLE001 - fall through to geometry
                pass
        return SAMBridge._write_mask(path, image, roi=fallback_box)

    @staticmethod
    def _write_mask(
        mask_path: Path | str | None,
        image: np.ndarray,
        *,
        roi: list[int] | None,
    ) -> Path | None:
        if mask_path is None or roi is None or cv2 is None:
            return None
        try:
            mask = mask_from_roi(image.shape, roi)
            return save_frame(mask, Path(mask_path))
        except Exception:  # noqa: BLE001 - mask is optional evidence
            return None
