import dataclasses

from backend.config import LLMMode, Settings


def _settings(**kwargs) -> Settings:
    base = dict(mode=LLMMode.MOCK, fixtures_dir=None, runtime_dir=None, quarantine_dir=None)
    return Settings(**kwargs)


def test_target_host_defaults_to_bind_host():
    settings = Settings(mode=LLMMode.MOCK, host="127.0.0.1", target_port=8001)
    assert settings.resolve_target_host == "127.0.0.1"
    assert settings.target_base_url == "http://127.0.0.1:8001"


def test_wildcard_bind_host_is_not_used_as_destination():
    # 0.0.0.0/:: mean "listen everywhere", they are not reachable addresses.
    for bind in ("0.0.0.0", "::", ""):
        settings = Settings(mode=LLMMode.MOCK, host=bind, target_port=8001)
        assert settings.resolve_target_host == "127.0.0.1"


def test_explicit_target_host_wins_for_container_dns():
    settings = Settings(
        mode=LLMMode.MOCK, host="0.0.0.0", target_host="target-api", target_port=8001
    )
    assert settings.target_base_url == "http://target-api:8001"


def test_cors_origin_list_parsing():
    settings = Settings(mode=LLMMode.MOCK, cors_origins=" http://a.test , http://b.test ,,")
    assert settings.cors_origin_list == ["http://a.test", "http://b.test"]
    assert Settings(mode=LLMMode.MOCK).cors_origin_list == []


def test_watchers_are_enabled_by_default():
    assert Settings(mode=LLMMode.MOCK).enable_watchers is True
    assert Settings(mode=LLMMode.MOCK, enable_watchers=False).enable_watchers is False
