import base64
import json
from pathlib import Path

import httpx
import pytest

from backend.vision import (
    FrameUnavailableError,
    SAMBridge,
    capture_frame,
    crop_roi,
    detect_motion,
    extract_boxes,
    load_frame,
    mask_from_roi,
    save_frame,
)
from tests.support import add_rect, make_frame


def test_detect_motion_finds_moved_rectangle():
    baseline = make_frame()
    current = add_rect(make_frame(), 30, 20, 60, 40)

    result = detect_motion(baseline, current)

    assert result.changed is True
    assert result.roi is not None
    x, y, w, h = result.roi
    assert abs(x - 30) <= 4
    assert abs(y - 20) <= 4
    assert w >= 60 and h >= 40
    assert result.motion_ratio > 0.01
    assert result.threshold == 25


def test_detect_motion_returns_none_for_identical_frames():
    frame = make_frame()
    result = detect_motion(frame, frame.copy())
    assert result.changed is False
    assert result.roi is None
    assert result.motion_ratio == 0.0


def test_detect_motion_handles_resolution_mismatch():
    baseline = make_frame(160, 120)
    current = add_rect(make_frame(320, 240), 60, 40, 120, 80)
    result = detect_motion(baseline, current)
    assert result.changed is True
    assert result.roi is not None


def test_crop_and_mask_helpers():
    frame = make_frame()
    add_rect(frame, 10, 10, 20, 20)
    crop = crop_roi(frame, [10, 10, 20, 20])
    assert crop.shape[:2] == (20, 20)

    mask = mask_from_roi(frame.shape, [10, 10, 20, 20])
    assert mask.shape == (120, 160)
    assert int(mask[15, 15]) == 255
    assert int(mask[0, 0]) == 0


def test_capture_frame_uses_provider_when_webcam_works(tmp_path: Path):
    frame = make_frame()
    captured = capture_frame(
        tmp_path / "shot.png", provider=lambda: frame, fallback_dir=tmp_path
    )
    assert captured.source == "webcam"
    assert captured.width == 160
    assert captured.path is not None and captured.path.exists()


def test_capture_frame_falls_back_to_recorded_scenario(tmp_path: Path):
    save_frame(add_rect(make_frame(), 20, 20, 40, 40), tmp_path / "operator_present.png")

    captured = capture_frame(
        tmp_path / "shot.png",
        provider=lambda: None,
        fallback_dir=tmp_path,
    )

    assert captured.source == "fallback"
    assert "operator_present.png" in captured.detail
    assert captured.path is not None and captured.path.exists()


def test_capture_frame_falls_back_to_first_image(tmp_path: Path):
    save_frame(make_frame(), tmp_path / "zzz_last.png")
    captured = capture_frame(provider=lambda: None, fallback_dir=tmp_path)
    assert captured.source == "fallback"


def test_capture_frame_raises_without_any_source(tmp_path: Path):
    with pytest.raises(FrameUnavailableError):
        capture_frame(provider=lambda: None, fallback_dir=tmp_path / "empty")


async def test_sam_offline_uses_roi_fallback(tmp_path: Path):
    bridge = SAMBridge(api_key="")
    assert bridge.available is False
    frame = add_rect(make_frame(), 40, 30, 50, 60)

    result = await bridge.segment(
        frame, roi=[40, 30, 50, 60], mask_path=tmp_path / "mask.png"
    )

    assert result.fallback_used is True
    assert result.model == "diff-fallback"
    assert result.boxes == [[40, 30, 50, 60]]
    assert "MODEL_API_KEY not configured" in result.detail
    assert result.mask_path is not None and result.mask_path.exists()


async def test_sam_offline_uses_baseline_diff(tmp_path: Path):
    bridge = SAMBridge(api_key="")
    baseline = make_frame()
    current = add_rect(make_frame(), 25, 15, 40, 30)

    result = await bridge.segment(current, baseline=baseline)

    assert result.fallback_used is True
    assert result.primary_box is not None
    x, y, w, h = result.primary_box
    assert abs(x - 25) <= 4 and abs(y - 15) <= 4


async def test_sam_live_parses_boxes_from_responses_api(tmp_path: Path):
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["auth"] = request.headers.get("authorization")
        body = json.loads(request.content)
        seen["model"] = body["model"]
        assert body["input"][0]["content"][1]["image_url"].startswith(
            "data:image/jpeg;base64,"
        )
        text = json.dumps({"boxes": [[5, 6, 70, 80]]})
        return httpx.Response(
            200,
            json={"output": [{"content": [{"type": "output_text", "text": text}]}]},
        )

    bridge = SAMBridge(
        api_key="test-key",
        base_url="https://api.meta.ai/v1",
        model="sam-3.1",
        transport=httpx.MockTransport(handler),
    )
    result = await bridge.segment(
        make_frame(), prompt="hand", roi=[1, 2, 3, 4], mask_path=tmp_path / "m.png"
    )

    assert result.fallback_used is False
    assert result.model == "sam-3.1"
    assert result.boxes == [[5, 6, 70, 80]]
    assert seen["url"].endswith("/v1/responses")
    assert seen["auth"] == "Bearer test-key"
    assert seen["model"] == "sam-3.1"
    assert result.mask_path is not None and result.mask_path.exists()


async def test_sam_live_falls_back_on_http_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="boom")

    bridge = SAMBridge(
        api_key="test-key", transport=httpx.MockTransport(handler)
    )
    result = await bridge.segment(make_frame(), roi=[10, 10, 20, 20])
    assert result.fallback_used is True
    assert result.boxes == [[10, 10, 20, 20]]
    assert "HTTPStatusError" in result.detail


async def test_sam_live_falls_back_when_no_boxes():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"output": []})

    bridge = SAMBridge(api_key="test-key", transport=httpx.MockTransport(handler))
    result = await bridge.segment(make_frame(), roi=[3, 4, 5, 6])
    assert result.fallback_used is True
    assert "0 box(es)" in result.detail


def test_extract_boxes_accepts_multiple_shapes():
    assert extract_boxes({"boxes": [[1, 2, 3, 4]]}) == [[1, 2, 3, 4]]
    assert extract_boxes({"detections": [{"x": 1, "y": 2, "w": 3, "h": 4}]}) == [
        [1, 2, 3, 4]
    ]
    assert extract_boxes({"box": {"x1": 10, "y1": 20, "x2": 30, "y2": 60}}) == [
        [10, 20, 20, 40]
    ]
    nested = {"output": [{"content": [{"text": json.dumps({"bboxes": [[7, 8, 9, 10]]})}]}]}
    assert extract_boxes(nested) == [[7, 8, 9, 10]]
    assert extract_boxes({"nothing": True}) == []


def test_data_uri_is_valid_base64():
    from backend.vision.sam_bridge import SAMBridge

    uri = SAMBridge._data_uri(make_frame())
    prefix, encoded = uri.split(",", 1)
    assert prefix == "data:image/jpeg;base64"
    assert base64.b64decode(encoded)[:2] == b"\xff\xd8"


def test_save_and_load_frame_with_unicode_path(tmp_path: Path):
    target = tmp_path / "Masa\u00fcst\u00fc" / "\u00e7ekim" / "frame.png"
    image = add_rect(make_frame(), 10, 10, 30, 30)
    saved = save_frame(image, target)

    assert saved.exists()
    assert saved.read_bytes()[:4] == b"\x89PNG"

    loaded = load_frame(saved)
    assert loaded.shape == (120, 160, 3)
