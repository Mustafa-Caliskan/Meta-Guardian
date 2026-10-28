import json
from pathlib import Path

from scripts.benchmark_baseline import (
    NAIVE_BLACKLIST_IPS,
    NaiveRuleEngine,
    build_scenarios,
    render_markdown,
    score,
    Comparison,
)


def test_scenarios_are_structurally_complete(tmp_path: Path):
    scenarios = build_scenarios(tmp_path)
    assert [s.id for s in scenarios] == ["A", "B", "C"]
    for scenario in scenarios:
        assert scenario.events
        assert scenario.expected is not None


def test_scenario_a_uses_a_real_staged_payload(tmp_path: Path):
    scenarios = build_scenarios(tmp_path)
    findings = scenarios[0].events[0].payload["findings"]
    payload_path = Path(scenarios[0].events[0].payload["mountpoint"]) / findings[0]["name"]
    assert payload_path.is_file()
    assert len(findings[0]["sha256"]) == 64


def test_naive_engine_static_deny_list_does_not_know_the_attacker(tmp_path: Path):
    # This is the structural weakness, not a bug: a deny-list is stale by design.
    assert "203.0.113.66" not in NAIVE_BLACKLIST_IPS


def test_naive_engine_results(tmp_path: Path):
    scenarios = build_scenarios(tmp_path)
    engine = NaiveRuleEngine()
    verdicts = {scenario.id: engine.evaluate(scenario) for scenario in scenarios}

    # A: alerts on the script but cannot stop the export
    assert verdicts["A"].detected is True
    assert verdicts["A"].contained is False
    assert verdicts["A"].patched is False

    # B: no camera, no ticket, unknown IP -> false negative
    assert verdicts["B"].detected is False
    assert "cannot see operator absence" in verdicts["B"].notes

    # C: no ticket correlation -> false positive during approved maintenance
    assert verdicts["C"].detected is True
    assert "false positive" in verdicts["C"].notes


def test_naive_scores_are_reproducible(tmp_path: Path):
    scenarios = build_scenarios(tmp_path)
    engine = NaiveRuleEngine()
    verdicts = [engine.evaluate(scenario) for scenario in scenarios]
    recall, fpr = score(verdicts, scenarios)
    assert recall == 0.5
    assert fpr == 1.0


def test_markdown_renders_all_scenarios(tmp_path: Path):
    scenarios = build_scenarios(tmp_path)
    engine = NaiveRuleEngine()
    naive = [engine.evaluate(scenario) for scenario in scenarios]
    result = Comparison(naive=naive, guardian=naive)
    result.naive_recall, result.naive_fpr = score(naive, scenarios)

    markdown = render_markdown(result, scenarios)
    for scenario in scenarios:
        assert scenario.name in markdown
    assert "Recall" in markdown
    assert "Honest caveats" in markdown
