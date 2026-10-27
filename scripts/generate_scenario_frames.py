"""Generate deterministic fallback frames for the demo cockpit.

These are *synthetic* frames, not photos: a dark desk scene with a monitor and an
optional operator silhouette. They exist so the pipeline and UI stay fully
demonstrable on a machine without a camera (CI, locked laptop). On a machine with
a webcam the real frame is captured instead.

Usage:
    python scripts/generate_scenario_frames.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from backend.config import SCENARIOS_DIR  # noqa: E402
from backend.vision.webcam_capture import save_frame  # noqa: E402

try:
    import cv2
except ImportError:  # pragma: no cover
    cv2 = None

WIDTH, HEIGHT = 640, 480


def _require_cv2():
    if cv2 is None:  # pragma: no cover
        raise SystemExit("opencv-python is required to generate frames")
    return cv2


def base_scene() -> np.ndarray:
    cv2_module = _require_cv2()
    frame = np.zeros((HEIGHT, WIDTH, 3), dtype=np.uint8)

    # vertical wall gradient
    for y in range(HEIGHT):
        shade = int(14 + 26 * (y / HEIGHT))
        frame[y, :] = (shade + 6, shade + 2, shade)

    # desk surface
    cv2_module.rectangle(frame, (0, 360), (WIDTH, HEIGHT), (32, 28, 24), -1)
    cv2_module.line(frame, (0, 360), (WIDTH, 360), (60, 58, 54), 2)

    # monitor
    cv2_module.rectangle(frame, (330, 150), (600, 330), (18, 18, 20), -1)
    cv2_module.rectangle(frame, (338, 158), (592, 322), (30, 52, 68), -1)
    cv2_module.rectangle(frame, (352, 172), (578, 250), (18, 30, 44), -1)
    for i in range(6):
        y = 186 + i * 14
        cv2_module.line(frame, (362, y), (362 + 40 + i * 18, y), (60, 120, 150), 2)
    cv2_module.rectangle(frame, (455, 330), (475, 360), (24, 24, 26), -1)
    cv2_module.rectangle(frame, (410, 358), (520, 366), (24, 24, 26), -1)

    # keyboard + notebook
    cv2_module.rectangle(frame, (250, 400), (470, 445), (44, 42, 40), -1)
    for row in range(3):
        for col in range(12):
            x = 258 + col * 17
            y = 408 + row * 12
            cv2_module.rectangle(frame, (x, y), (x + 13, y + 8), (58, 56, 54), -1)
    cv2_module.rectangle(frame, (70, 392), (200, 452), (52, 46, 38), -1)
    cv2_module.line(frame, (78, 402), (192, 402), (86, 78, 66), 1)
    cv2_module.line(frame, (78, 414), (170, 414), (86, 78, 66), 1)

    return frame


def operator_present(baseline: np.ndarray) -> np.ndarray:
    cv2_module = _require_cv2()
    frame = baseline.copy()
    cv2_module.ellipse(frame, (170, 210), (46, 56), 0, 0, 360, (54, 58, 66), -1)
    cv2_module.ellipse(frame, (170, 335), (95, 105), 0, 180, 360, (40, 44, 52), -1)
    cv2_module.circle(frame, (152, 200), 5, (72, 78, 88), -1)
    cv2_module.circle(frame, (188, 200), 5, (72, 78, 88), -1)
    cv2_module.line(frame, (150, 230), (190, 230), (70, 74, 84), 2)
    # arm reaching toward the desk
    cv2_module.line(frame, (230, 340), (300, 300), (46, 50, 58), 26)
    return frame


def hand_with_usb(baseline: np.ndarray) -> np.ndarray:
    cv2_module = _require_cv2()
    frame = baseline.copy()
    cv2_module.ellipse(frame, (300, 372), (46, 26), 0, 0, 360, (86, 92, 104), -1)
    cv2_module.rectangle(frame, (250, 366), (278, 380), (30, 30, 34), -1)
    cv2_module.rectangle(frame, (228, 368), (250, 378), (150, 120, 60), -1)
    cv2_module.rectangle(frame, (232, 371), (246, 375), (90, 200, 230), -1)
    cv2_module.line(frame, (300, 390), (360, 410), (78, 84, 96), 18)
    return frame


def empty_seat(baseline: np.ndarray) -> np.ndarray:
    return baseline.copy()


def main() -> int:
    cv2_module = _require_cv2()
    SCENARIOS_DIR.mkdir(parents=True, exist_ok=True)
    base = base_scene()

    frames = {
        "operator_present.png": operator_present(base),
        "operator_absent.png": empty_seat(base),
        "hand_usb.png": hand_with_usb(base),
    }
    for name, image in frames.items():
        path = save_frame(image, SCENARIOS_DIR / name)
        print(f"wrote {path.relative_to(ROOT)} ({path.stat().st_size} bytes)")

    # a diff pair for offline ROI demos
    pair_dir = SCENARIOS_DIR / "diff_pair"
    pair_dir.mkdir(exist_ok=True)
    save_frame(base, pair_dir / "baseline.png")
    save_frame(hand_with_usb(base), pair_dir / "current.png")
    print(f"wrote {pair_dir.relative_to(ROOT)}/baseline.png and current.png")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
