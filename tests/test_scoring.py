import sys
from pathlib import Path

from helpers import sample_finding

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "agents"))

from scoring import score_project  # noqa: E402

FULL_COVERAGE = {
    "analyzed_languages": ["python"], "unanalyzed_languages": [], "partial_languages": [],
    "unaudited_automation": [], "truncated": False, "files_total": 3, "files_scanned": 3,
}
HEALTHY_TOOLS = {"secrets": "ok", "ruff": "ok", "bandit": "ok"}
HEALTHY_PANEL = {"reviewed": 1, "min_size": 3, "diverse": True, "overflow": 0}


def _result(findings=(), statuses=None, coverage=None, tools=None, panel=None):
    statuses = statuses or {}
    return {
        "findings": list(findings),
        "consolidated": {f["id"]: {"status": statuses.get(f["id"], "confirmed"), "votes": []}
                         for f in findings},
        "coverage": coverage if coverage is not None else FULL_COVERAGE,
        "tools": tools if tools is not None else HEALTHY_TOOLS,
        "panel": panel if panel is not None else {"reviewed": 0, "min_size": 0, "diverse": False},
    }


def test_clean_fully_covered_project_is_ready():
    score = score_project(_result())
    assert score["production_readiness"] == "READY"
    assert (score["engineering_health"], score["evidence_confidence"]) == (100, 100)
    assert score["reasons"] == []


def test_confirmed_high_finding_blocks():
    finding = sample_finding(severity="high")
    score = score_project(_result([finding], panel=HEALTHY_PANEL))
    assert score["production_readiness"] == "BLOCKED"
    assert score["engineering_health"] == 75


def test_dismissed_findings_do_not_count_but_are_not_hidden_from_ready_logic():
    finding = sample_finding(severity="high")
    score = score_project(_result([finding], {"F001": "dismissed"}, panel=HEALTHY_PANEL))
    assert score["production_readiness"] == "READY"
    assert score["engineering_health"] == 100


def test_disputed_counts_at_sixty_percent_and_needs_human_review():
    finding = sample_finding(severity="high")
    score = score_project(_result([finding], {"F001": "disputed"}, panel=HEALTHY_PANEL))
    assert score["production_readiness"] == "CONDITIONAL"
    assert score["engineering_health"] == 85
    assert any("disputa" in r for r in score["reasons"])


def test_language_without_analyzer_is_never_ready():
    coverage = {**FULL_COVERAGE, "unanalyzed_languages": ["go"]}
    score = score_project(_result(coverage=coverage))
    assert score["production_readiness"] == "CONDITIONAL"
    assert any("go" in r for r in score["reasons"])
    assert score["evidence_confidence"] < 100


def test_partial_js_analysis_is_never_ready():
    coverage = {**FULL_COVERAGE, "partial_languages": ["javascript"]}
    score = score_project(_result(coverage=coverage, tools={"secrets": "ok", "npm_audit": "ok"}))
    assert score["production_readiness"] == "CONDITIONAL"
    assert any("javascript" in r for r in score["reasons"])


def test_failed_tool_is_a_limitation_not_a_pass():
    tools = {"secrets": "ok", "ruff": "ok", "bandit": "unavailable"}
    score = score_project(_result(tools=tools))
    assert score["production_readiness"] == "CONDITIONAL"
    assert any("bandit (unavailable)" in r for r in score["reasons"])


def test_degraded_panel_lowers_confidence_and_says_why():
    finding = sample_finding(severity="medium")
    panel = {"reviewed": 1, "min_size": 1, "diverse": False, "overflow": 0}
    score = score_project(_result([finding], {"F001": "unverified"}, panel=panel))
    assert score["evidence_confidence"] <= 50
    assert any("menos de 2 revisores" in r for r in score["reasons"])


def test_panel_without_verified_diversity_is_flagged():
    finding = sample_finding(severity="medium")
    panel = {"reviewed": 1, "min_size": 3, "diverse": False, "overflow": 0}
    score = score_project(_result([finding], panel=panel))
    assert any("Diversidad" in r for r in score["reasons"])


def test_empty_target_is_not_assessed():
    coverage = {**FULL_COVERAGE, "files_scanned": 0}
    assert score_project(_result(coverage=coverage))["production_readiness"] == "NOT_ASSESSED"


def test_unaudited_automation_is_a_limitation():
    coverage = {**FULL_COVERAGE, "unaudited_automation": ["n8n:flow.json"]}
    score = score_project(_result(coverage=coverage))
    assert score["production_readiness"] == "CONDITIONAL"
    assert any("n8n:flow.json" in r for r in score["reasons"])
