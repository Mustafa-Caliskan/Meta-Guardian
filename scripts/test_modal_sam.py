"""Verify the Modal GPU/CPU Segment Anything service end to end.

Sends a real local frame to the deployed Modal endpoint, saves the returned mask
and prints timings. This is the evidence that segmentation is produced by a real
model, not by the offline frame-diff fallback.

Usage
-----
    python scripts/test_modal_sam.py
    python scripts/test_modal_sam.py --image data/scenarios/hand_usb.png --box 228,360,130,40
    python scripts/test_modal_sam.py --offline-check    # only validates local tier order

Exit codes: 0 ok, 2 service error, 3 not configured.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import sys
import time
from pathlib import Path

import httpx
import numpy as np

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from backend.config import get_settings  # noqa: E402
from backend.vision import SAMBridge, load_frame  # noqa: E402

DEFAULT_IMAGE = "data/scenarios/hand_usb.png"
DEFAULT_BOX = "228,360,130,40"


def parse_box(raw: str) -> list[int]:
    parts = [part.strip() for part in raw.split(",")]
    if len(parts) != 4:
        raise argparse.ArgumentTypeError("box must be x,y,w,h")
    return [int(float(part)) for part in parts]


def probe(image_path: Path, box: list[int], out_dir: Path) -> int:
    settings = get_settings()
    if not settings.modal_sam_url:
        print("MODAL_SAM_URL is not set; deploy with `modal deploy scripts/modal_sam.py`")
        return 3
    if not settings.modal_sam_token:
        print("MODAL_SAM_TOKEN is not set; create the Modal secret first")
        return 3

    image = load_frame(image_path)
    ok, buffer = __import__("cv2").imencode(".png", image)
    if not ok:
        print("could not encode the test frame")
        return 2
    image_b64 = base64.b64encode(buffer.tobytes()).decode("ascii")

    payload = {"image_b64": image_b64, "box": box, "token": settings.modal_sam_token}

    print(f"endpoint  : {settings.modal_sam_url}")
    print(f"image     : {image_path} ({image.shape[1]}x{image.shape[0]})")
    print(f"box prompt: {box}")

    started = time.perf_counter()
    try:
        response = httpx.post(
            settings.modal_sam_url, json=payload, timeout=settings.modal_sam_timeout + 60
        )
    except httpx.HTTPError as exc:
        print(f"request failed: {type(exc).__name__}: {exc}")
        return 2
    wall_ms = round((time.perf_counter() - started) * 1000, 2)

    if response.status_code != 200:
        print(f"HTTP {response.status_code}: {response.text[:400]}")
        return 2

    data = response.json()
    if not isinstance(data, dict) or data.get("error"):
        print(f"service error: {data}")
        return 2

    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%S")
    mask_b64 = data.get("mask_b64") or ""
    mask_path = out_dir / f"modal_sam_mask_{stamp}.png"
    if mask_b64:
        mask_bytes = base64.b64decode(mask_b64)
        mask_path.write_bytes(mask_bytes)
        coverage = _mask_coverage(mask_path)
        print(f"mask      : {mask_path} ({len(mask_bytes)} bytes, {coverage:.2%} covered)")
    else:
        print("mask      : the service returned no mask")

    record = {
        "endpoint": settings.modal_sam_url,
        "image": str(image_path),
        "box_prompt": box,
        "boxes": data.get("boxes"),
        "score": data.get("score"),
        "model": data.get("model"),
        "device": data.get("device"),
        "service_latency_ms": data.get("latency_ms"),
        "wall_ms": wall_ms,
        "mask_path": str(mask_path) if mask_b64 else None,
        "recorded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    record_path = out_dir / f"modal_sam_run_{stamp}.json"
    record_path.write_text(json.dumps(record, indent=2), encoding="utf-8")

    print(f"model     : {data.get('model')} on {data.get('device')}")
    print(f"score     : {data.get('score')}")
    print(f"box out   : {data.get('boxes')}")
    print(f"gpu/infer : {data.get('latency_ms')} ms")
    print(f"wall      : {wall_ms} ms (includes cold start)")
    print(f"record    : {record_path}")
    return 0


def _mask_coverage(mask_path: Path) -> float:
    try:
        import cv2

        mask = cv2.imread(str(mask_path), cv2.IMREAD_GRAYSCALE)
        if mask is None:
            return 0.0
        return float(np.count_nonzero(mask)) / float(mask.size)
    except Exception:  # noqa: BLE001
        return 0.0


async def bridge_check(image_path: Path, box: list[int], out_dir: Path) -> int:
    """Verify the bridge actually selects the remote tier and keeps its mask."""
    settings = get_settings()
    if not settings.modal_sam_url:
        print("MODAL_SAM_URL is not set")
        return 3

    image = load_frame(image_path)
    bridge = SAMBridge(api_key="", modal_url=settings.modal_sam_url)
    mask_path = out_dir / "bridge_mask.png"
    result = await bridge.segment(image, roi=box, mask_path=mask_path)

    print(f"model       : {result.model}")
    print(f"mask source : {result.mask_source or 'n/a'}")
    print(f"fallback    : {result.fallback_used}")
    print(f"boxes       : {result.boxes}")
    print(f"detail      : {result.detail}")
    if result.mask_path:
        print(f"mask        : {result.mask_path}")

    if result.fallback_used:
        print("FAIL: the bridge fell back instead of using the Modal service")
        return 2
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default=DEFAULT_IMAGE)
    parser.add_argument("--box", type=parse_box, default=parse_box(DEFAULT_BOX))
    parser.add_argument("--out", default="data/runtime")
    parser.add_argument(
        "--bridge",
        action="store_true",
        help="also exercise SAMBridge so the tier selection is verified",
    )
    args = parser.parse_args(argv)

    image_path = Path(args.image)
    if not image_path.is_file():
        print(f"image not found: {image_path}")
        return 3

    out_dir = Path(args.out)
    code = probe(image_path, args.box, out_dir)
    if code != 0:
        return code

    if args.bridge:
        print()
        print("--- SAMBridge tier check ---")
        return asyncio.run(bridge_check(image_path, args.box, out_dir))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
