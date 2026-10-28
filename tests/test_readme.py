"""Guard the documentation against the claims the code actually supports."""

from pathlib import Path

README = Path(__file__).resolve().parent.parent / "README.md"


def readme() -> str:
    return README.read_text(encoding="utf-8")


def test_readme_opens_with_problem_solution_evidence():
    text = readme()
    lowered = text.lower()
    problem = lowered.index("airport and critical-facility operations")
    solution = lowered.index("meta-guardian is a blue-team agent")
    evidence = lowered.index("what is proven, and how")
    assert problem < solution < evidence


def test_readme_has_a_mermaid_architecture_diagram():
    text = readme()
    assert "```mermaid" in text
    block = text.split("```mermaid", 1)[1].split("```", 1)[0]
    for node in (
        "USBWatcher",
        "NetWatcher",
        "EventBus",
        "Correlator",
        "OODA",
        "PolicyEngine",
        "MCP",
        "Patcher",
        "target-api",
    ):
        assert node in block, node


def test_readme_measurement_tables_match_the_recorded_runs():
    text = readme()
    # live docker measurements, expressed as observed ranges
    # values appear inside ranges such as "236–371 ms", so check the numbers
    for expected in ("236", "371", "42", "93", "115", "123"):
        assert expected in text, expected
    assert "ms" in text
    # 1M run
    assert "1,026,768" in text
    assert "7 / 7" in text
    assert "13.5 s" in text
    # benchmark
    assert "50%" in text and "100%" in text
    assert "docs/BENCHMARK.md" in text


def test_readme_model_routing_explains_why():
    text = readme()
    assert "which model, where, and why" in text.lower()
    for model in ("muse-glimmer", "muse-spark-1.3", "sam-3.1", "sam-vit_b"):
        assert model in text, model
    # the deliberate choice not to let a model execute actions
    assert "never emits executable code" in text


def test_readme_documents_casefile_and_live_attack():
    text = readme()
    assert "/casefile?format=markdown" in text
    assert "POST /api/attack" in text
    assert "429" in text


def test_readme_does_not_contain_unmeasured_vendor_claims():
    lowered = readme().lower()
    for forbidden in ("crowdstrike", "wazuh", "detects 99", "100% secure"):
        assert forbidden not in lowered, forbidden


def test_readme_is_clean_utf8():
    raw = README.read_bytes()
    text = raw.decode("utf-8")  # raises if invalid
    assert "\ufffd" not in text
    # the author name and the field reference survived the encoding
    assert "Mustafa \u00c7al\u0131\u015fkan" in text
    assert "Sabiha" in text
