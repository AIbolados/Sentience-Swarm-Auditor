import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "agents"))

import graph  # noqa: E402
import mcp_server  # noqa: E402
from llm_router import CredentialRouter, Provider  # noqa: E402

FAKE_PROVIDERS = [
    Provider("prov_a", "https://a.example/v1", "PROV_A_KEY", "model-a", "capaz"),
    Provider("prov_b", "https://b.example/v1", "PROV_B_KEY", "model-b", "rapido"),
]


def _fake_llm_client(content: str):
    client = MagicMock()
    response = MagicMock()
    response.choices = [MagicMock(message=MagicMock(content=content))]
    client.chat.completions.create.return_value = response
    return client


def test_mcp_server_registers_expected_tools():
    tool_names = {t.name for t in mcp_server.mcp._tool_manager._tools.values()}
    assert {"audit_project", "audit_all_projects", "get_last_report"} <= tool_names


@pytest.mark.asyncio
async def test_audit_project_tool_rejects_nonexistent_path(tmp_path):
    fake_path = tmp_path / "no-existe"
    result = await mcp_server.audit_project(str(fake_path))
    assert "error" in result


@pytest.mark.asyncio
async def test_audit_project_tool_audits_real_directory(tmp_path, monkeypatch):
    project = tmp_path / "target"
    project.mkdir()
    (project / "main.py").write_text("print('hola')")

    monkeypatch.setenv("PROV_A_KEY", "key-a")
    monkeypatch.setenv("PROV_B_KEY", "key-b")
    monkeypatch.setattr(graph, "run_static_checks", lambda path: ({}, True))

    client = _fake_llm_client("sin hallazgos")
    fake_router = CredentialRouter(providers=FAKE_PROVIDERS, client_factory=lambda k, u: client)
    monkeypatch.setattr(mcp_server, "_router", fake_router)

    result = await mcp_server.audit_project(str(project))

    assert result["name"] == "target"
    assert result["ensemble"]["scan_provider"] != result["ensemble"]["debate_provider"]
    assert "score" in result


def test_get_last_report_without_reports(tmp_path, monkeypatch):
    monkeypatch.setenv("LOG_DIR", str(tmp_path / "empty_logs"))
    assert mcp_server.get_last_report() == "Sin reportes generados todavia."


def test_get_last_report_returns_most_recent(tmp_path, monkeypatch):
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    (log_dir / "2026-01-01_report.md").write_text("viejo")
    (log_dir / "2026-01-02_report.md").write_text("nuevo")
    monkeypatch.setenv("LOG_DIR", str(log_dir))

    assert mcp_server.get_last_report() == "nuevo"
