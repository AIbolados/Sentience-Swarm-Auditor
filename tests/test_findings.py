import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "agents"))

from findings import assign_ids, make_finding  # noqa: E402


def _f(**overrides):
    base = dict(
        source="ruff", rule="F821", severity="low", tier="deterministic",
        file="a.py", line=1, message="m",
    )
    base.update(overrides)
    return make_finding(**base)


def test_make_finding_rejects_unknown_severity():
    with pytest.raises(ValueError):
        _f(severity="gravisimo")


def test_make_finding_rejects_unknown_tier():
    with pytest.raises(ValueError):
        _f(tier="quizas")


def test_make_finding_starts_without_id_and_with_empty_evidence():
    finding = _f()
    assert finding["id"] == ""
    assert finding["evidence"] == ""


def test_assign_ids_orders_by_severity_then_location():
    findings = assign_ids([
        _f(severity="low", file="z.py"),
        _f(severity="critical", file="b.py", line=9),
        _f(severity="critical", file="a.py", line=3),
    ])
    assert [(f["id"], f["severity"], f["file"]) for f in findings] == [
        ("F001", "critical", "a.py"),
        ("F002", "critical", "b.py"),
        ("F003", "low", "z.py"),
    ]
