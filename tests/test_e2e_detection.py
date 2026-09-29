"""Regresion de la auditoria del 2026-09-29: un repo vulnerable con layout
src/ recibia READY. Aqui NINGUN analizador esta mockeado; solo el LLM."""

import json
import sys
from pathlib import Path

import pytest
from helpers import verdict_client

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "agents"))

import graph  # noqa: E402
from llm_router import CredentialRouter, Provider  # noqa: E402

AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
ANTHROPIC_LIKE = "sk-ant-" + "api03-" + "A1b2C3d4E5f6G7h8I9j0"

PROVIDERS = [
    Provider("a", "https://a/v1", "PA_KEY", "m-a", "capaz", family="fx"),
    Provider("b", "https://b/v1", "PB_KEY", "m-b", "rapido", family="fy"),
    Provider("c", "https://c/v1", "PC_KEY", "m-c", "rapido", family="fz"),
]


def _router(monkeypatch, verdict="real"):
    for env in ("PA_KEY", "PB_KEY", "PC_KEY"):
        monkeypatch.setenv(env, "k")
    clients = {p.base_url: verdict_client(verdict) for p in PROVIDERS}
    return CredentialRouter(providers=PROVIDERS, client_factory=lambda k, u: clients[u]), clients


def _sent_to_llms(clients) -> str:
    return json.dumps([
        call.kwargs["messages"] for c in clients.values() for call in c.chat.completions.create.call_args_list
    ])


@pytest.mark.asyncio
async def test_vulnerable_src_layout_is_blocked_and_secret_never_leaks(tmp_path, monkeypatch):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text(
        "import os\nimport subprocess\n\n"
        f'AWS_KEY = "{AWS_KEY}"\n\n\n'
        "def run(cmd):\n    subprocess.call(cmd, shell=True)\n    os.system(cmd)\n"
    )
    router, clients = _router(monkeypatch)

    result, static_ok = await graph.run_project_audit("vuln", str(tmp_path), router)

    assert result["score"]["production_readiness"] == "BLOCKED"
    assert static_ok is True
    assert {f["source"] for f in result["findings"]} >= {"secrets", "bandit"}
    assert AWS_KEY not in json.dumps(result, default=str)
    assert AWS_KEY not in _sent_to_llms(clients)


@pytest.mark.asyncio
async def test_clean_python_project_is_ready_and_calls_no_llm(tmp_path, monkeypatch):
    (tmp_path / "calc.py").write_text("def add(a: int, b: int) -> int:\n    return a + b\n")
    router, clients = _router(monkeypatch)

    result, _ = await graph.run_project_audit("clean", str(tmp_path), router)

    assert result["score"]["production_readiness"] == "READY"
    assert result["findings"] == []
    assert all(c.chat.completions.create.call_count == 0 for c in clients.values())


@pytest.mark.asyncio
async def test_go_only_repo_is_never_ready(tmp_path, monkeypatch):
    (tmp_path / "main.go").write_text("package main\n\nfunc main() {}\n")
    router, _ = _router(monkeypatch)

    result, _ = await graph.run_project_audit("go", str(tmp_path), router)

    assert result["score"]["production_readiness"] == "CONDITIONAL"
    assert any("go" in reason for reason in result["score"]["reasons"])


@pytest.mark.asyncio
async def test_n8n_export_with_embedded_secret_is_not_skipped(tmp_path, monkeypatch):
    (tmp_path / "wf.json").write_text(json.dumps({
        "name": "sync",
        "nodes": [{"type": "n8n-nodes-base.httpRequest", "parameters": {"auth": ANTHROPIC_LIKE}}],
        "connections": {},
    }))
    router, clients = _router(monkeypatch)

    result, _ = await graph.run_project_audit("auto", str(tmp_path), router)

    assert result["discovery"]["classification"] == "automation"
    assert result["score"]["production_readiness"] == "BLOCKED"
    assert any(f["rule"] == "anthropic-api-key" for f in result["findings"])
    assert result["coverage"]["unaudited_automation"] == ["n8n:wf.json"]
    assert ANTHROPIC_LIKE not in json.dumps(result, default=str)
    assert ANTHROPIC_LIKE not in _sent_to_llms(clients)


@pytest.mark.asyncio
async def test_panel_dismisses_a_benign_heuristic_finding_but_keeps_it_visible(tmp_path, monkeypatch):
    (tmp_path / "cache.py").write_text(
        "import hashlib\n\n\n"
        "def cache_key(url: str) -> str:\n"
        "    # llave de cache, no es un uso criptografico\n"
        "    return hashlib.md5(url.encode()).hexdigest()\n"
    )
    router, _ = _router(monkeypatch, verdict="false_positive")

    result, _ = await graph.run_project_audit("cache", str(tmp_path), router)

    md5 = next(f for f in result["findings"] if f["source"] == "bandit")
    assert result["consolidated"][md5["id"]]["status"] == "dismissed"
    assert result["score"]["production_readiness"] == "READY"
    assert result["consolidated"][md5["id"]]["votes"], "el descarte debe quedar auditable"
