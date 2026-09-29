import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "agents"))

from findings import make_finding  # noqa: E402
from verdicts import (  # noqa: E402
    build_votes,
    consolidate_finding,
    is_grounded,
    parse_verdict_payload,
)


def _finding(tier="heuristic", severity="medium"):
    finding = make_finding(
        source="bandit", rule="B324", severity=severity, tier=tier,
        file="a.py", line=1, message="m", evidence="1: h = md5(x)",
    )
    finding["id"] = "F001"
    return finding


def _vote(verdict, provider="p", confidence=0.9):
    return {
        "provider": provider, "family": provider, "verdict": verdict,
        "confidence": confidence, "reason": "r", "grounded": True,
    }


def _payload(*items):
    return json.dumps({"verdicts": list(items)})


ITEM = {"id": "F001", "verdict": "real", "confidence": 0.9, "reason": "x", "evidence_quote": "md5(x)"}


def test_parse_accepts_fenced_json_with_prose():
    fence = "`" * 3  # evita backticks triples literales dentro del bloque de codigo
    text = f"Aqui va:\n{fence}json\n" + _payload(ITEM) + f"\n{fence}\nfin"
    assert parse_verdict_payload(text)["F001"]["verdict"] == "real"


def test_parse_skips_unrelated_json_before_the_payload():
    text = 'ejemplo {"a": 1} y luego ' + _payload(ITEM)
    assert "F001" in parse_verdict_payload(text)


@pytest.mark.parametrize("text", [
    "sin json",
    json.dumps({"otra_cosa": []}),
    json.dumps({"verdicts": "no lista"}),
    _payload({"id": "F001", "verdict": "quizas"}),
    _payload({"verdict": "real"}),
    _payload({"id": "F001", "verdict": "real", "confidence": "alta"}),
])
def test_parse_rejects_invalid_payloads(text):
    with pytest.raises(ValueError):
        parse_verdict_payload(text)


def test_parse_clamps_confidence_and_truncates_reason():
    parsed = parse_verdict_payload(_payload({**ITEM, "confidence": 7, "reason": "x" * 999}))
    assert parsed["F001"]["confidence"] == 1.0
    assert len(parsed["F001"]["reason"]) <= 240


def test_grounding_requires_exact_fragment_ignoring_whitespace():
    assert is_grounded("h  =\n md5(x)", "1: h = md5(x)") is True
    assert is_grounded("h = sha256(x)", "1: h = md5(x)") is False
    assert is_grounded("h", "1: h = md5(x)") is False  # demasiado corta


def test_ungrounded_or_low_confidence_votes_become_abstentions():
    shown = {"F001": "1: h = md5(x)"}
    parsed = {"F001": {"verdict": "false_positive", "confidence": 0.9, "reason": "r",
                       "evidence_quote": "algo inventado"}}
    assert build_votes("p", "f", parsed, shown)["F001"]["verdict"] == "uncertain"

    parsed = {"F001": {"verdict": "real", "confidence": 0.2, "reason": "r",
                       "evidence_quote": "md5(x)"}}
    assert build_votes("p", "f", parsed, shown)["F001"]["verdict"] == "uncertain"


def test_missing_verdict_for_a_finding_is_an_abstention():
    votes = build_votes("p", "f", {}, {"F001": "1: h = md5(x)"})
    assert votes["F001"]["verdict"] == "uncertain"


@pytest.mark.parametrize("verdicts,responding,expected", [
    (["real", "real", "false_positive"], 3, "confirmed"),
    (["false_positive", "false_positive", "uncertain"], 3, "dismissed"),
    (["false_positive", "false_positive", "real"], 3, "disputed"),
    (["real", "false_positive", "uncertain"], 3, "disputed"),
    (["uncertain", "uncertain", "uncertain"], 3, "unverified"),
    (["false_positive"], 1, "unverified"),
    ([], 0, "unverified"),
])
def test_heuristic_consolidation_matrix(verdicts, responding, expected):
    votes = [_vote(v, provider=f"p{i}") for i, v in enumerate(verdicts)]
    assert consolidate_finding(_finding(), votes, responding)["status"] == expected


def test_deterministic_high_can_never_be_dismissed():
    finding = _finding(tier="deterministic", severity="critical")
    three_fp = [_vote("false_positive", provider=f"p{i}") for i in range(3)]
    assert consolidate_finding(finding, three_fp, 3)["status"] == "disputed"
    one_fp = [_vote("false_positive"), _vote("real", "q"), _vote("real", "r")]
    assert consolidate_finding(finding, one_fp, 3)["status"] == "confirmed"
    assert consolidate_finding(finding, [], 0)["status"] == "confirmed"


def test_not_sent_to_panel_is_unreviewed_unless_high_precision():
    low = _finding(severity="low")
    assert consolidate_finding(low, [], None)["status"] == "unreviewed"
    critical = _finding(tier="deterministic", severity="critical")
    assert consolidate_finding(critical, [], None)["status"] == "confirmed"


def test_false_positive_votes_from_unverified_families_never_dismiss():
    votes = [
        {**_vote("false_positive", provider=f"p{i}"), "verified": False} for i in range(3)
    ]
    assert consolidate_finding(_finding(), votes, 3)["status"] == "disputed"
