import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "agents"))

import audit_agent  # noqa: E402


def test_run_tool_returns_none_when_binary_missing(tmp_path):
    """Bug fix: una herramienta no instalada no debe contarse como
    hallazgo de seguridad en el scoring (antes devolvia 'Error: ...',
    un string truthy que scoring.py interpretaba como riesgo real)."""
    result = audit_agent.run_tool("herramienta-que-no-existe", str(tmp_path))
    assert result is None


def test_run_static_checks_missing_tool_is_not_a_finding(tmp_path):
    (tmp_path / "main.py").write_text("print('hola')")

    with patch.object(audit_agent, "run_tool", return_value=None):
        checks, ok = audit_agent.run_static_checks(str(tmp_path))

    assert checks["bandit"] is None
    assert checks["ruff"] is None
    assert ok is True


def test_run_static_checks_real_finding_is_truthy(tmp_path):
    (tmp_path / "main.py").write_text("print('hola')")

    with patch.object(audit_agent, "run_tool", side_effect=["", "main.py:1: B101 assert used"]):
        checks, _ = audit_agent.run_static_checks(str(tmp_path))

    assert checks["ruff"] == ""
    assert checks["bandit"] == "main.py:1: B101 assert used"
