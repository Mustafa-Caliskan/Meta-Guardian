"""LLM abstraction shared by every provider and by mock/replay modes."""

from __future__ import annotations

import json
import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

Message = dict[str, str]

_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL | re.IGNORECASE)


@dataclass
class LLMResponse:
    text: str
    model: str = ""
    latency_ms: float = 0.0
    input_tokens: int = 0
    output_tokens: int = 0
    raw: dict[str, Any] = field(default_factory=dict)


def extract_json(text: str) -> dict[str, Any]:
    """Best-effort extraction of a JSON object from an LLM reply."""
    if not text or not text.strip():
        raise ValueError("empty LLM response")

    candidate = text.strip()
    fence = _FENCE_RE.search(candidate)
    if fence:
        candidate = fence.group(1).strip()

    try:
        parsed = json.loads(candidate)
    except json.JSONDecodeError:
        start = candidate.find("{")
        end = candidate.rfind("}")
        if start == -1 or end <= start:
            raise ValueError(f"no JSON object found in response: {text[:200]!r}")
        parsed = json.loads(candidate[start : end + 1])

    if not isinstance(parsed, dict):
        raise ValueError("expected a JSON object")
    return parsed


class BaseLLM(ABC):
    name: str = "base"

    @abstractmethod
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
        """Return the model completion for ``messages``."""

    async def complete_json(
        self,
        messages: list[Message],
        *,
        task: str = "",
        model: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> tuple[dict[str, Any], LLMResponse]:
        started = time.perf_counter()
        response = await self.complete(
            messages,
            task=task,
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
            json_mode=True,
        )
        if response.latency_ms == 0.0:
            response.latency_ms = round((time.perf_counter() - started) * 1000, 2)
        return extract_json(response.text), response
