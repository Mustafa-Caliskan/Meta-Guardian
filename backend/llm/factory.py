"""Build the LLM client that matches the configured runtime mode."""

from __future__ import annotations

from .base import BaseLLM
from .meta_api import MetaAPILLM
from .mock import MockLLM
from .record import RecordingLLM
from .replay import ReplayLLM
from ..config import LLMMode, Settings, get_settings


def build_llm(settings: Settings | None = None) -> BaseLLM:
    settings = settings or get_settings()

    if settings.mode is LLMMode.MOCK:
        return MockLLM()
    if settings.mode is LLMMode.REPLAY:
        return ReplayLLM(settings.fixtures_dir)

    live = MetaAPILLM(settings)
    if settings.mode is LLMMode.RECORD:
        return RecordingLLM(live, settings.fixtures_dir)
    return live


def has_live_credentials(settings: Settings | None = None) -> bool:
    settings = settings or get_settings()
    return bool(settings.meta_api_key or settings.baseten_api_key or settings.fireworks_api_key)
