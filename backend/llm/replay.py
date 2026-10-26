"""Fixture-backed LLM used when LLM_MODE=replay (demo recording insurance)."""

from __future__ import annotations

import json
import time
from pathlib import Path

from .base import BaseLLM, LLMResponse, Message
from ..config import FIXTURES_DIR


class ReplayLLM(BaseLLM):
    name = "replay"

    def __init__(self, fixtures_dir: Path | None = None) -> None:
        self.fixtures_dir = Path(fixtures_dir or FIXTURES_DIR)

    def _fixture_path(self, task: str) -> Path:
        key = (task or "default").replace(":", "_").replace("/", "_")
        return self.fixtures_dir / f"{key}.json"

    async def complete(
        self,
        messages: list[Message],
        *,
        task: str = "",
        model: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
        json_mode: bool = False,
    ) -> LLMResponse:
        started = time.perf_counter()
        path = self._fixture_path(task)
        if not path.exists():
            raise FileNotFoundError(
                f"no replay fixture for task {task!r} at {path}. "
                "Run a live call with LLM_MODE=record first."
            )

        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and "response" in data:
            data = data["response"]

        if isinstance(data, str):
            text = data
        elif isinstance(data, dict) and "text" in data:
            text = str(data["text"])
        else:
            text = json.dumps(data, indent=2, ensure_ascii=False)

        return LLMResponse(
            text=text,
            model=model or f"replay-{task or 'default'}",
            latency_ms=round((time.perf_counter() - started) * 1000, 2),
            raw=data if isinstance(data, dict) else {},
        )
