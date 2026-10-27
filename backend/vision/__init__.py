from .roi_detector import (
    MotionResult,
    compute_diff,
    crop_roi,
    detect_motion,
    find_roi,
    mask_from_roi,
)
from .sam_bridge import DEFAULT_PROMPT, SAMBridge, SegmentationResult, extract_boxes
from .webcam_capture import (
    CapturedFrame,
    FrameUnavailableError,
    WebcamCapture,
    capture_frame,
    find_fallback_frame,
    load_frame,
    save_frame,
)

__all__ = [
    "MotionResult",
    "compute_diff",
    "crop_roi",
    "detect_motion",
    "find_roi",
    "mask_from_roi",
    "DEFAULT_PROMPT",
    "SAMBridge",
    "SegmentationResult",
    "extract_boxes",
    "CapturedFrame",
    "FrameUnavailableError",
    "WebcamCapture",
    "capture_frame",
    "find_fallback_frame",
    "load_frame",
    "save_frame",
]
