"""Provider routing for Meta open-weight models.

Glimmer (edge OODA) is typically served by Fireworks or Baseten, Spark Open
(1M-context forensics) by Baseten, and Muse Code by the Meta API. Each target
is OpenAI-compatible, so routing is just endpoint + key + model selection.
"""

from __future__ import annotations

from .base import BaseLLM, LLMResponse, Message
from .openai_compat import OpenAICompatLLM
from ..config import Settings


class MetaAPILLM(BaseLLM):
    name = "meta-api"

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._clients: dict[str, OpenAICompatLLM] = {}

    def _provider_for(self, model: str) -> str:
        lowered = model.lower()
        if "glimmer" in lowered:
            if self.settings.fireworks_api_key:
                return "fireworks"
            if self.settings.baseten_api_key:
                return "baseten"
        if "spark" in lowered and self.settings.baseten_api_key:
            return "baseten"
        return "meta"

    def _client(self, provider: str, model: str) -> OpenAICompatLLM:
        cache_key = f"{provider}:{model}"
        if cache_key in self._clients:
            return self._clients[cache_key]

        if provider == "fireworks":
            client = OpenAICompatLLM(
                base_url=self.settings.fireworks_base_url,
                api_key=self.settings.fireworks_api_key,
                default_model=model,
                timeout=self.settings.request_timeout,
                temperature=self.settings.temperature,
                max_tokens=self.settings.max_tokens,
            )
        elif provider == "baseten":
            client = OpenAICompatLLM(
                base_url=self.settings.baseten_base_url,
                api_key=self.settings.baseten_api_key,
                default_model=model,
                timeout=self.settings.request_timeout,
                temperature=self.settings.temperature,
                max_tokens=self.settings.max_tokens,
            )
        else:
            client = OpenAICompatLLM(
                base_url=self.settings.meta_base_url,
                api_key=self.settings.meta_api_key,
                default_model=model,
                timeout=self.settings.request_timeout,
                temperature=self.settings.temperature,
                max_tokens=self.settings.max_tokens,
            )
        self._clients[cache_key] = client
        return client

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
        chosen = model or self._default_model_for(task)
        provider = self._provider_for(chosen)
        client = self._client(provider, chosen)
        response = await client.complete(
            messages,
            task=task,
            model=chosen,
            temperature=temperature,
            max_tokens=max_tokens,
            json_mode=json_mode,
        )
        response.model = f"{chosen}@{provider}"
        return response

    def _default_model_for(self, task: str) -> str:
        if task.startswith("forensics"):
            return self.settings.forensics_model
        if task.startswith("patch"):
            return self.settings.code_model
        return self.settings.ooda_model
