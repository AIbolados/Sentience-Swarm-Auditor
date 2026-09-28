import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "agents"))

import graph  # noqa: E402
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


@pytest.fixture
def isolated_swarm(tmp_path, monkeypatch):
    projects_home = tmp_path / "projects"
    projects_home.mkdir()
    (projects_home / "proj_a").mkdir()
    (projects_home / "proj_b").mkdir()

    swarm_home = tmp_path / "swarm"
    log_dir = tmp_path / "logs"

    monkeypatch.setattr(graph, "PROJECTS_HOME", projects_home)
    monkeypatch.setattr(graph, "IGNORE_DIRS", set())

    import change_detector

    monkeypatch.setattr(change_detector, "SWARM_HOME", swarm_home)
    monkeypatch.setattr(change_detector, "STATE_FILE", swarm_home / "state.json")

    monkeypatch.setattr(graph, "run_static_checks", lambda path: ({}, True))
    monkeypatch.setattr(graph, "watch_intelligence", lambda: {"findings": []})

    monkeypatch.setenv("PROV_A_KEY", "key-a")
    monkeypatch.setenv("PROV_B_KEY", "key-b")

    return {"projects_home": projects_home, "log_dir": log_dir}


@pytest.mark.asyncio
async def test_graph_audits_all_projects_concurrently(isolated_swarm):
    client = _fake_llm_client("todo ok")
    router = CredentialRouter(providers=FAKE_PROVIDERS, client_factory=lambda k, u: client)

    compiled = graph.build_graph(router=router, log_dir=isolated_swarm["log_dir"])
    final_state = await compiled.ainvoke(
        {"project_results": [], "github_intel": None, "report_path": None}
    )

    audited_names = {p["name"] for p in final_state["project_results"]}
    assert audited_names == {"proj_a", "proj_b"}
    for project in final_state["project_results"]:
        assert project["ensemble"]["scan_provider"] != project["ensemble"]["debate_provider"]
        assert "score" in project

    report_path = Path(final_state["report_path"])
    assert report_path.exists()
    content = report_path.read_text()
    assert "proj_a" in content and "proj_b" in content


@pytest.mark.asyncio
async def test_graph_no_changes_produces_empty_report(isolated_swarm, monkeypatch):
    import change_detector

    def already_seen(name, path):
        return False, "irrelevant"

    monkeypatch.setattr(change_detector, "has_changed", already_seen)
    monkeypatch.setattr(graph, "has_changed", already_seen)

    router = CredentialRouter(providers=FAKE_PROVIDERS)
    compiled = graph.build_graph(router=router, log_dir=isolated_swarm["log_dir"])
    final_state = await compiled.ainvoke(
        {"project_results": [], "github_intel": None, "report_path": None}
    )

    assert final_state["project_results"] == []
