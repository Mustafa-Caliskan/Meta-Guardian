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
    # A different but detailed scene (tiled wall), not a flat frame: a flat frame
    # is a camera problem and is covered by the tamper tests below.
    rng = np.random.RandomState(7)
    completely_different = rng.randint(120, 200, size=(240, 320, 3), dtype=np.uint8)

    detector = PresenceDetector(baseline=baseline)
    result = detector.detect(completely_different)

    assert result.reliable is False
    assert result.present is False
    assert result.tampered is False
    assert "scene mismatch" in result.description


# ------------------------------------------------------------------ tamper --

def test_covered_lens_is_tampering_not_an_empty_seat():
    """A flat dark frame must never read as a confident "seat is empty"."""
    baseline = desk_baseline()
    covered = make_frame(320, 240, color=0)

    detector = PresenceDetector(baseline=baseline)
    result = detector.detect(covered)

    assert result.tampered is True
    assert result.present is False
    assert result.reliable is False
    assert result.confidence == 0.0
    assert "lens covered" in result.tamper_reason
    assert "camera tampered" in result.description


def test_dark_noisy_frame_from_auto_exposure_is_tampering():
    """A real covered lens is dark grey noise, not pure black."""
    baseline = desk_baseline()
    rng = np.random.RandomState(3)
    dark_noise = rng.randint(2, 12, size=(240, 320, 3), dtype=np.uint8)

    detector = PresenceDetector(baseline=baseline)
    result = detector.detect(dark_noise)

    assert result.tampered is True
    assert "lens covered" in result.tamper_reason


def test_blown_out_frame_is_tampering():
    baseline = desk_baseline()
    detector = PresenceDetector(baseline=baseline)
    result = detector.detect(make_frame(320, 240, color=255))

    assert result.tampered is True
    assert "blown out" in result.tamper_reason


def test_flat_grey_frame_is_tampering():
    """No detail at all: the lens is obstructed by something mid-grey."""
    baseline = desk_baseline()
    detector = PresenceDetector(baseline=baseline)
    result = detector.detect(make_frame(320, 240, color=128))

    assert result.tampered is True
    assert "no detail" in result.tamper_reason


def test_empty_frame_is_tampering():
    baseline = desk_baseline()
    detector = PresenceDetector(baseline=baseline)
    result = detector.detect(np.zeros((0, 0, 3), dtype=np.uint8))

    assert result.tampered is True
    assert result.tamper_reason == "empty frame"


def test_normal_desk_frame_is_not_tampering():
    baseline = desk_baseline()
    detector = PresenceDetector(baseline=baseline)
    result = detector.detect(baseline.copy())

    assert result.tampered is False
    assert result.tamper_reason == ""
    assert result.reliable is True
    assert result.present is False
    assert result.frame_mean > 0
    assert result.frame_stddev > 3.0


def test_operator_frame_with_detail_is_not_tampering():
    baseline = desk_baseline()
    frame = baseline.copy()
    add_rect(frame, 40, 30, 90, 150, color=90)

    result = PresenceDetector(baseline=baseline).detect(frame)

    assert result.tampered is False
    assert result.present is True


def test_tamper_thresholds_are_configurable():
    baseline = desk_baseline()
    detector = PresenceDetector(
        baseline=baseline, tamper_min_stddev=0.5, tamper_dark_mean=5.0
    )
    # with a very low spread requirement, a dark but detailed frame is fine
    rng = np.random.RandomState(11)
    frame = rng.randint(10, 60, size=(240, 320, 3), dtype=np.uint8)
    assert detector.detect(frame).tampered is False


def test_missing_baseline_raises():
    detector = PresenceDetector()
    with pytest.raises(BaselineUnavailableError):
        detector.detect(make_frame())


def test_summary_is_honest_about_method():
    detector = PresenceDetector(baseline=desk_baseline())
    summary = detector.detect(desk_baseline()).to_summary()
    assert "baseline_diff" in summary
    assert "no operator" in summary
