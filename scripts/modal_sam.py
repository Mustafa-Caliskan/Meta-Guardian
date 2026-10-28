"""Modal GPU service: open-weight Segment Anything prompted by a bounding box.

This is the middle tier of Meta-Guardian's three-tier segmentation:

  1. Meta Model API ``sam-3.1`` (hosted, needs ``MODEL_API_KEY``)
  2. **this service** — Segment Anything open weights on a Modal GPU
  3. offline frame-diff mask (always available, no network)

The physical claim in the demo is only honest if a real segmenter produced the
mask; this tier makes that possible without a Meta API key.

Deploy / run
------------
    modal deploy scripts/modal_sam.py            # prints the public URL
    modal run scripts/modal_sam.py::selftest     # GPU smoke test, no HTTP
    modal serve scripts/modal_sam.py             # ephemeral dev URL

Then point the app at it:

    $env:MODAL_SAM_URL="https://<workspace>--meta-guardian-sam-api.modal.run"

Auth: a shared secret is checked before any GPU work. It is stored as the Modal
secret ``meta-guardian-sam`` (key ``MG_SAM_TOKEN``) and must be sent as the
``X-MG-SAM-Token`` header. If the secret is missing the endpoint refuses to serve,
so a leaked public URL is not a free GPU.

    modal secret create meta-guardian-sam MG_SAM_TOKEN=<random-string>

The client reads the same value from ``MODAL_SAM_TOKEN``.

Request (POST JSON):
    {"image_b64": "<base64 PNG/JPEG>", "box": [x, y, w, h]}
Response:
    {"boxes": [[x, y, w, h]], "mask_b64": "<base64 PNG>",
     "score": 0.93, "model": "sam-vit_b", "device": "cuda", "latency_ms": 812.4}

The checkpoint is baked into the image so a cold start does not download it.
"""

from __future__ import annotations

import base64
import os
import time

import modal

SAM_CHECKPOINT_URL = (
    "https://dl.fbaipublicfiles.com/segment_anything/sam_vit_b_01ec64.pth"
)
SAM_MODEL_TYPE = "vit_b"
CHECKPOINT_PATH = "/root/sam_vit_b.pth"

# The official PyTorch runtime image already contains torch + CUDA. Installing
# torch from PyPI would pull the whole NVIDIA stack again and make the build ten
# times slower, so we start from the CUDA-ready base.
image = (
    modal.Image.from_registry(
        "pytorch/pytorch:2.3.1-cuda12.1-cudnn8-runtime",
        add_python="3.11",
    )
    .apt_install("libgl1", "libglib2.0-0", "wget")
    .pip_install(
        "segment-anything==1.0",
        "opencv-python-headless==4.10.0.84",
        "numpy<2",
        "fastapi==0.115.0",
    )
    .run_commands(
        f"wget -q -O {CHECKPOINT_PATH} {SAM_CHECKPOINT_URL}"
    )
)

app = modal.App("meta-guardian-sam", image=image)

sam_secret = modal.Secret.from_name("meta-guardian-sam", required_keys=["MG_SAM_TOKEN"])

# GPUs need a payment method on the account even when credits exist. Set
# MG_SAM_GPU=cpu to validate the pipeline on CPU (ViT-B on a 640x480 frame is
# ~1-3 s), then switch back to "T4" / "A10G" once billing is enabled.
GPU = os.environ.get("MG_SAM_GPU", "T4").strip()
GPU_ARG = None if GPU.lower() in ("", "cpu", "none") else GPU

MAX_IMAGE_BYTES = 8 * 1024 * 1024


def _decode_image(b64: str):
    import cv2
    import numpy as np

    raw = base64.b64decode(b64)
    if len(raw) > MAX_IMAGE_BYTES:
        raise ValueError(f"image too large: {len(raw)} bytes")
    array = np.frombuffer(raw, dtype=np.uint8)
    bgr = cv2.imdecode(array, cv2.IMREAD_COLOR)
    if bgr is None:
        raise ValueError("could not decode image bytes")
    return cv2.cvtColor(bgr, cv2.COLOR_BGR2RGB)


def _encode_mask(mask, width: int, height: int) -> str:
    import cv2
    import numpy as np

    canvas = np.zeros((height, width), dtype=np.uint8)
    visible = mask[:height, :width]
    canvas[: visible.shape[0], : visible.shape[1]] = (visible * 255).astype(np.uint8)
    ok, buffer = cv2.imencode(".png", canvas)
    if not ok:
        raise ValueError("could not encode mask")
    return base64.b64encode(buffer.tobytes()).decode("ascii")


@app.cls(gpu=GPU_ARG, timeout=300, scaledown_window=180)
class SamService:
    """Keeps the checkpoint warm across requests in the same container."""

    @modal.enter()
    def load(self):
        import torch
        from segment_anything import SamPredictor, sam_model_registry

        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        sam = sam_model_registry[SAM_MODEL_TYPE](checkpoint=CHECKPOINT_PATH)
        sam.to(device=self.device)
        self.predictor = SamPredictor(sam)

    @modal.method()
    def segment(self, image_b64: str, box: list[float] | None = None) -> dict:
        started = time.perf_counter()
        import numpy as np

        rgb = _decode_image(image_b64)
        height, width = rgb.shape[:2]
        self.predictor.set_image(rgb)

        prompt = None
        if box:
            x, y, w, h = (float(value) for value in box)
            prompt = np.array([[x, y, x + w, y + h]], dtype=np.float32)

        masks, scores, _ = self.predictor.predict(
            box=prompt, multimask_output=True
        )
        best = int(np.argmax(scores))
        mask = masks[best]

        ys, xs = np.nonzero(mask)
        if xs.size:
            box_out = [
                int(xs.min()),
                int(ys.min()),
                int(xs.max() - xs.min() + 1),
                int(ys.max() - ys.min() + 1),
            ]
        else:
            box_out = [0, 0, 0, 0]

        return {
            "boxes": [box_out],
            "mask_b64": _encode_mask(mask, width, height),
            "score": float(scores[best]),
            "model": f"sam-{SAM_MODEL_TYPE}",
            "device": self.device,
            "latency_ms": round((time.perf_counter() - started) * 1000, 2),
        }


def _token_ok(candidate: str | None) -> bool:
    import hashlib
    import hmac
    import os

    expected = os.environ.get("MG_SAM_TOKEN", "")
    if not expected:
        return False
    return hmac.compare_digest(
        hashlib.sha256(str(candidate or "").encode()).digest(),
        hashlib.sha256(expected.encode()).digest(),
    )


@app.function(image=image, timeout=300, secrets=[sam_secret])
@modal.fastapi_endpoint(method="POST", docs=False)
def api(payload: dict) -> dict:
    """HTTP entry point. Requires the ``MG_SAM_TOKEN`` shared secret."""
    if not _token_ok(payload.get("token")):
        return {"error": "unauthorized"}

    image_b64 = payload.get("image_b64")
    if not image_b64:
        return {"error": "image_b64 is required"}
    if not isinstance(image_b64, str):
        return {"error": "image_b64 must be a base64 string"}

    box = payload.get("box")
    if box is not None:
        if not isinstance(box, (list, tuple)) or len(box) != 4:
            return {"error": "box must be [x, y, w, h]"}
        try:
            box = [float(value) for value in box]
        except (TypeError, ValueError):
            return {"error": "box values must be numbers"}
        box = None if all(value == 0 for value in box) else box

    try:
        return SamService().segment.remote(image_b64, box)
    except Exception as exc:  # noqa: BLE001 - surface a clean error to the client
        return {"error": f"{type(exc).__name__}: {exc}"}


@app.local_entrypoint()
def selftest() -> None:
    """GPU smoke test with a synthetic frame; prints latency and mask size."""
    import cv2
    import numpy as np

    canvas = np.zeros((240, 320, 3), dtype=np.uint8)
    canvas[60:200, 80:220] = (40, 180, 240)
    ok, buffer = cv2.imencode(".png", canvas)
    if not ok:
        raise SystemExit("could not encode test frame")
    image_b64 = base64.b64encode(buffer.tobytes()).decode("ascii")

    started = time.perf_counter()
    result = SamService().segment.remote(image_b64, [80, 60, 140, 140])
    elapsed = round((time.perf_counter() - started) * 1000, 2)

    print(f"device      : {result['device']}")
    print(f"model       : {result['model']}")
    print(f"internal ms : {result['latency_ms']}")
    print(f"round trip  : {elapsed} ms")
    print(f"score       : {result['score']:.3f}")
    print(f"box         : {result['boxes'][0]}")
    print(f"mask bytes  : {len(result['mask_b64'])} (base64)")
