"""Central configuration for Meta-Guardian.

All runtime behaviour is driven by environment variables so the same codebase
can run fully offline (mock), from recorded fixtures (replay) or against real
Meta / OpenAI-compatible endpoints (live / record).

Model identifiers follow the official Meta Model API documentation
(https://dev.meta.ai/docs) plus the hackathon participant guide:

* Meta Model API  -> ``muse-spark-1.3`` (1M context), ``sam-3.1``
* Baseten         -> ``meta-models/muse-spark-open-1026`` (hackathon override
                     of the public ``meta-models/muse-spark-open`` id)
* Muse Glimmer    -> open-weight, self-hosted or Fireworks/Baseten served
* Muse Code       -> a terminal/CI coding agent, NOT an API model
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
FIXTURES_DIR = DATA_DIR / "fixtures"
SCENARIOS_DIR = DATA_DIR / "scenarios"
HISTORY_LOGS_DIR = DATA_DIR / "history_logs"
RUNTIME_DIR = DATA_DIR / "runtime"

load_dotenv(PROJECT_ROOT / ".env")


class LLMMode(str, Enum):
    MOCK = "mock"
    REPLAY = "replay"
    LIVE = "live"
    RECORD = "record"


META_SPARK_MODEL = "muse-spark-1.3"
META_SAM_MODEL = "sam-3.1"
BASETEN_SPARK_OPEN_MODEL = "meta-models/muse-spark-open-1026"
GLIMMER_MODEL = "muse-glimmer"


def _env(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def _env_first(*names: str, default: str = "") -> str:
    for name in names:
        value = _env(name)
        if value:
            return value
    return default


def _env_int(name: str, default: int) -> int:
    try:
        return int(_env(name, str(default)))
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(_env(name, str(default)))
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    mode: LLMMode = LLMMode.MOCK

    host: str = "127.0.0.1"
    port: int = 8000
    target_port: int = 8001

    meta_api_key: str = ""
    meta_base_url: str = "https://api.meta.ai/v1"
    baseten_api_key: str = ""
    baseten_base_url: str = "https://inference.baseten.co/v1"
    fireworks_api_key: str = ""
    fireworks_base_url: str = "https://api.fireworks.ai/inference/v1"

    ooda_model: str = GLIMMER_MODEL
    forensics_model: str = META_SPARK_MODEL
    code_model: str = META_SPARK_MODEL
    sam_model: str = META_SAM_MODEL
    spark_open_model: str = BASETEN_SPARK_OPEN_MODEL

    webcam_index: int = 0
    request_timeout: float = 60.0
    temperature: float = 0.2
    max_tokens: int = 2048
    reasoning_effort: str = "low"

    action_timeout: float = 10.0
    max_actions_per_minute: int = 30
    kill_allowlist: str = ""

    correlation_window_seconds: float = 30.0
    correlation_cooldown_seconds: float = 10.0
    operator_motion_threshold: float = 0.004
    baseline_frame: str = ""
    persist_incidents: bool = True

    trust_forwarded_for: bool = False
    internal_api_token: str = ""

    fixtures_dir: Path = field(default_factory=lambda: FIXTURES_DIR)
    runtime_dir: Path = field(default_factory=lambda: RUNTIME_DIR)
    quarantine_dir: Path = field(default_factory=lambda: PROJECT_ROOT / "quarantine")
    change_tickets_path: Path = field(default_factory=lambda: DATA_DIR / "change_tickets.json")

    @property
    def is_offline(self) -> bool:
        return self.mode in (LLMMode.MOCK, LLMMode.REPLAY)

    @property
    def target_base_url(self) -> str:
        return f"http://{self.host}:{self.target_port}"

    @property
    def request_log_path(self) -> Path:
        return self.runtime_dir / "target_requests.jsonl"

    @property
    def incidents_dir(self) -> Path:
        return self.runtime_dir / "incidents"

    @property
    def baseline_frame_path(self) -> Path:
        if self.baseline_frame:
            candidate = Path(self.baseline_frame)
            return candidate if candidate.is_absolute() else PROJECT_ROOT / candidate
        return SCENARIOS_DIR / "diff_pair" / "baseline.png"

    def ensure_dirs(self) -> None:
        for path in (
            DATA_DIR,
            self.fixtures_dir,
            SCENARIOS_DIR,
            HISTORY_LOGS_DIR,
            self.runtime_dir,
            self.quarantine_dir,
            self.incidents_dir,
        ):
            path.mkdir(parents=True, exist_ok=True)


def _parse_mode(raw: str) -> LLMMode:
    try:
        return LLMMode(raw.lower() or "mock")
    except ValueError:
        return LLMMode.MOCK


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    settings = Settings(
        mode=_parse_mode(_env("LLM_MODE", "mock")),
        host=_env("HOST", "127.0.0.1"),
        port=_env_int("PORT", 8000),
        target_port=_env_int("TARGET_PORT", 8001),
        meta_api_key=_env_first("MODEL_API_KEY", "META_API_KEY"),
        meta_base_url=_env("META_BASE_URL", "https://api.meta.ai/v1"),
        baseten_api_key=_env("BASETEN_API_KEY"),
        baseten_base_url=_env("BASETEN_BASE_URL", "https://inference.baseten.co/v1"),
        fireworks_api_key=_env("FIREWORKS_API_KEY"),
        fireworks_base_url=_env("FIREWORKS_BASE_URL", "https://api.fireworks.ai/inference/v1"),
        ooda_model=_env("OODA_MODEL", GLIMMER_MODEL),
        forensics_model=_env("FORENSICS_MODEL", META_SPARK_MODEL),
        code_model=_env("CODE_MODEL", META_SPARK_MODEL),
        sam_model=_env("SAM_MODEL", META_SAM_MODEL),
        spark_open_model=_env("SPARK_OPEN_MODEL", BASETEN_SPARK_OPEN_MODEL),
        webcam_index=_env_int("WEBCAM_INDEX", 0),
        request_timeout=_env_float("REQUEST_TIMEOUT", 60.0),
        temperature=_env_float("TEMPERATURE", 0.2),
        max_tokens=_env_int("MAX_TOKENS", 2048),
        reasoning_effort=_env("REASONING_EFFORT", "low"),
        action_timeout=_env_float("ACTION_TIMEOUT", 10.0),
        max_actions_per_minute=_env_int("MAX_ACTIONS_PER_MINUTE", 30),
        kill_allowlist=_env("KILL_ALLOWLIST", ""),
        correlation_window_seconds=_env_float("CORRELATION_WINDOW_SECONDS", 30.0),
        correlation_cooldown_seconds=_env_float("CORRELATION_COOLDOWN_SECONDS", 10.0),
        operator_motion_threshold=_env_float("OPERATOR_MOTION_THRESHOLD", 0.004),
        baseline_frame=_env("BASELINE_FRAME", ""),
        persist_incidents=_env("PERSIST_INCIDENTS", "1") not in ("0", "false", "False"),
        trust_forwarded_for=_env("TRUST_FORWARDED_FOR", "0") in ("1", "true", "True"),
        internal_api_token=_env("INTERNAL_API_TOKEN", ""),
        fixtures_dir=Path(_env("FIXTURES_DIR", str(FIXTURES_DIR))),
        runtime_dir=Path(_env("RUNTIME_DIR", str(RUNTIME_DIR))),
        quarantine_dir=Path(_env("QUARANTINE_DIR", str(PROJECT_ROOT / "quarantine"))),
        change_tickets_path=Path(
            _env("CHANGE_TICKETS_PATH", str(DATA_DIR / "change_tickets.json"))
        ),
    )
    settings.ensure_dirs()
    return settings
