"""Wraps a live LLM and stores its replies as replayable fixtures."""

from __future__ import annotations

import json
from pathlib import Path

from .base import BaseLLM, LLMResponse, Message, extract_json
from ..config import FIXTURES_DIR


class RecordingLLM(BaseLLM):
    name = "record"

    def __init__(self, inner: BaseLLM, fixtures_dir: Path | None = None) -> None:
        self.inner = inner
        self.fixtures_dir = Path(fixtures_dir or FIXTURES_DIR)
        self.fixtures_dir.mkdir(parents=True, exist_ok=True)

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
        response = await self.inner.complete(
            messages,
            task=task,
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
            json_mode=json_mode,
        )
        self._save(task, messages, response)
        return response

    def _save(self, task: str, messages: list[Message], response: LLMResponse) -> None:
        key = (task or "default").replace(":", "_").replace("/", "_")
        path = self.fixtures_dir / f"{key}.json"
        payload = {
            "task": task,
            "model": response.model,
            "latency_ms": response.latency_ms,
            "request_messages": messages,
            "response": response.text,
        }
        try:
            payload["response_json"] = extract_json(response.text)
        except ValueError:
            payload["response_json"] = None
        path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
        )
