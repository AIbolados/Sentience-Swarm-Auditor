import sys
from pathlib import Path

from helpers import sample_finding

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "agents"))

from report import render_project_section  # noqa: E402


def _project():
    confirmed = sample_finding("F001", message="subprocess con shell=True")
    dismissed = sample_finding("F002", rule="B324", message="md5 como llave de cache")
    return {
        "name": "proj_x",
        "discovery": {"classification": "code", "languages": {"python": 2}},
        "findings": [confirmed, dismissed],
        "consolidated": {
            "F001": {"status": "confirmed", "votes": []},
            "F002": {"status": "dismissed", "votes": [
                {"provider": "a", "family": "fx", "verdict": "false_positive",
                 "confidence": 0.9, "reason": "llave de cache, no criptografia", "grounded": True},
            ]},
        },
        "panel": {"reviewed": 2, "min_size": 3, "diverse": True, "error": None},
        "score": {
            "production_readiness": "BLOCKED", "engineering_health": 75,
            "vibe_slop_risk": 15, "evidence_confidence": 100, "reasons": ["Limitacion de prueba"],
        },
    }


def test_section_lists_confirmed_and_dismissed_with_reason():
    text = render_project_section(_project())
    assert "### proj_x" in text
    assert "**BLOCKED**" in text
    assert "Clasificacion: code (python: 2)" in text
    assert "Limitacion: Limitacion de prueba" in text
    assert "Confirmados (1)" in text and "[HIGH] src/app.py:8 `B602`" in text
    assert "Descartados por el panel (1)" in text and "llave de cache, no criptografia" in text
    assert "diversidad verificada" in text


def test_section_without_panel_says_not_required():
    project = _project()
    project["panel"] = {"reviewed": 0, "min_size": 0, "diverse": False, "error": None}
    assert "Panel: no requerido" in render_project_section(project)
