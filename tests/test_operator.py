import numpy as np
import pytest

from backend.vision.operator import (
    BaselineUnavailableError,
    PresenceDetector,
)
from backend.vision.webcam_capture import save_frame
from tests.support import add_rect, make_frame


def desk_baseline() -> np.ndarray:
    frame = make_frame(320, 240, color=10)
    frame[180:, :] = 40  # desk surface
    return frame


def test_empty_seat_is_detected_absent():
    baseline = desk_baseline()
    detector = PresenceDetector(baseline=baseline, motion_threshold=0.004)

    result = detector.detect(baseline.copy())

    assert result.present is False
    assert result.motion_ratio == 0.0
    assert result.method == "baseline_diff"
    assert 0.5 <= result.confidence <= 1.0
    assert "no operator-sized motion" in result.description


def test_operator_silhouette_is_detected_present():
    baseline = desk_baseline()
    frame = baseline.copy()
    add_rect(frame, 40, 30, 90, 150, color=90)

    detector = PresenceDetector(baseline=baseline, motion_threshold=0.004)
    result = detector.detect(frame)

    assert result.present is True
    assert result.roi is not None
    assert 0.6 <= result.confidence <= 0.96
    assert result.motion_ratio > 0.004
    assert "operator-sized motion" in result.description


def test_small_noise_does_not_claim_presence():
    baseline = desk_baseline()
    frame = baseline.copy()
    add_rect(frame, 5, 5, 4, 4, color=255)  # 16 px on a 76800 px frame

    detector = PresenceDetector(baseline=baseline, motion_threshold=0.004)
    result = detector.detect(frame)

    assert result.present is False


def test_baseline_can_be_loaded_from_disk(tmp_path):
    baseline = desk_baseline()
    path = save_frame(baseline, tmp_path / "baseline.png")

    detector = PresenceDetector(baseline_path=path)
    result = detector.detect(baseline)

    assert result.present is False
    assert result.baseline_path == str(path)


def test_scene_mismatch_is_marked_unreliable():
    baseline = desk_baseline()
    completely_different = make_frame(320, 240, color=250)

    detector = PresenceDetector(baseline=baseline)
    result = detector.detect(completely_different)

    assert result.reliable is False
    assert result.present is False
    assert "scene mismatch" in result.description


def test_missing_baseline_raises():
    detector = PresenceDetector()
    with pytest.raises(BaselineUnavailableError):
        detector.detect(make_frame())


def test_summary_is_honest_about_method():
    detector = PresenceDetector(baseline=desk_baseline())
    summary = detector.detect(desk_baseline()).to_summary()
    assert "baseline_diff" in summary
    assert "no operator" in summary
