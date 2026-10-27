import json

import pytest

from backend.config import LLMMode, Settings
from backend.llm import MockLLM, ReplayLLM, build_llm, extract_json
from backend.llm.record import RecordingLLM


def _user(text: str) -> list[dict[str, str]]:
    return [{"role": "user", "content": text}]


def test_extract_json_plain_and_fenced():
    assert extract_json('{"a": 1}') == {"a": 1}
    assert extract_json('```json\n{"a": 2}\n```') == {"a": 2}
    assert extract_json('prefix {"a": 3} suffix') == {"a": 3}


def test_extract_json_rejects_empty():
    with pytest.raises(ValueError):
        extract_json("")


async def test_mock_ooda_detects_threat():
    llm = MockLLM()
    payload, response = await llm.complete_json(_user("usb payload exfiltration"), task="ooda")
    assert payload["classification"] == "THREAT_CRITICAL"
    assert payload["actions"]
    assert response.latency_ms >= 0


async def test_mock_ooda_detects_authorized_maintenance():
    llm = MockLLM()
    payload, _ = await llm.complete_json(
        _user('{"change_ticket_valid": true, "operator_present": true}'), task="ooda"
    )
    assert payload["classification"] == "BENIGN_AUTHORIZED"
    assert payload["actions"] == []


async def test_mock_ghost_attack_has_no_operator():
    llm = MockLLM()
    payload, _ = await llm.complete_json(
        _user('{"operator_present": false, "change_ticket_valid": false}'), task="ooda"
    )
    assert payload["classification"] == "GHOST_ATTACK"


async def test_replay_returns_fixture(tmp_path):
    fixture = {"task": "ooda", "response": json.dumps({"classification": "THREAT_CRITICAL"})}
    (tmp_path / "ooda.json").write_text(json.dumps(fixture), encoding="utf-8")
    llm = ReplayLLM(tmp_path)
    payload, _ = await llm.complete_json(_user("anything"), task="ooda")
    assert payload["classification"] == "THREAT_CRITICAL"


async def test_replay_missing_fixture_raises(tmp_path):
    llm = ReplayLLM(tmp_path)
    with pytest.raises(FileNotFoundError):
        await llm.complete(_user("x"), task="missing")


async def test_recording_writes_replayable_fixture(tmp_path):
    recorder = RecordingLLM(MockLLM(), tmp_path)
    await recorder.complete(_user("usb"), task="ooda")
    assert (tmp_path / "ooda.json").exists()
    replay = ReplayLLM(tmp_path)
    payload, _ = await replay.complete_json(_user("usb"), task="ooda")
    assert payload["classification"] == "THREAT_CRITICAL"


def test_factory_modes(tmp_path):
    base = dict(fixtures_dir=tmp_path, meta_api_key="dummy")
    assert build_llm(Settings(mode=LLMMode.MOCK)).name == "mock"
    assert build_llm(Settings(mode=LLMMode.REPLAY, **base)).name == "replay"
    assert build_llm(Settings(mode=LLMMode.RECORD, **base)).name == "record"
    assert build_llm(Settings(mode=LLMMode.LIVE, **base)).name == "meta-api"
