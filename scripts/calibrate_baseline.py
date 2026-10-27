"""Calibrate a clean baseline frame for operator-presence detection.

The presence detector compares an incident frame against a **clean** baseline.
With a real webcam you must capture that baseline while the seat is empty;
otherwise the "whole frame changed" guard correctly refuses to guess.

Usage
-----
    # step away from the desk, then run
    python scripts/calibrate_baseline.py

    # use an existing photo instead
    python scripts/calibrate_baseline.py --from data/scenarios/diff_pair/baseline.png

    # average 10 frames over 3 seconds (more stable)
    python scripts/calibrate_baseline.py --frames 10

Then point the app at it:

    $env:BASELINE_FRAME="data/runtime/baseline.png"
    # or put BASELINE_FRAME=data/runtime/baseline.png in .env

The default baseline (`data/scenarios/diff_pair/baseline.png`) is a synthetic
desk image used for deterministic recorded scenarios.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from backend.config import SCENARIOS_DIR, get_settings  # noqa: E402
from backend.vision import capture_frame, load_frame, save_frame  # noqa: E402


def average_camera_frames(camera_index: int, frames: int, delay: float) -> np.ndarray:
    import cv2

    capture = cv2.VideoCapture(camera_index)
    if not capture.isOpened():
        raise SystemExit(f"camera {camera_index} could not be opened")
    collected: list[np.ndarray] = []
    try:
        for _ in range(max(1, frames)):
            ok, frame = capture.read()
            if ok and frame is not None:
                collected.append(frame.astype(np.float32))
            time.sleep(max(0.0, delay))
    finally:
        capture.release()

    if not collected:
        raise SystemExit("camera returned no frames")
    return np.mean(collected, axis=0).astype(np.uint8)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--from", dest="source", default=None, help="use an image instead of the camera")
    parser.add_argument("--out", default=None, help="output path (default data/runtime/baseline.png)")
    parser.add_argument("--frames", type=int, default=5, help="frames to average")
    parser.add_argument("--delay", type=float, default=0.2, help="delay between frames (s)")
    args = parser.parse_args(argv)

    settings = get_settings()
    output = Path(args.out) if args.out else settings.runtime_dir / "baseline.png"
    output.parent.mkdir(parents=True, exist_ok=True)

    if args.source:
        image = load_frame(args.source)
        detail = f"copied from {args.source}"
    else:
        print(
            f"Capturing {args.frames} frames from camera {settings.webcam_index}. "
            "Make sure the seat is EMPTY and the laptop/camera will not move."
        )
        try:
            image = average_camera_frames(settings.webcam_index, args.frames, args.delay)
        except SystemExit as exc:
            fallback = SCENARIOS_DIR / "diff_pair" / "baseline.png"
            print(f"camera unavailable ({exc}); using synthetic baseline {fallback}")
            image = load_frame(fallback)
            detail = "synthetic fallback"
        else:
            detail = "averaged live webcam frames"

    save_frame(image, output)
    print(f"baseline written: {output} ({output.stat().st_size} bytes, {detail})")
    print()
    print("Use it with:")
    print(f'  $env:BASELINE_FRAME="{output}"')
    print("  # or add BASELINE_FRAME=<path> to .env")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
