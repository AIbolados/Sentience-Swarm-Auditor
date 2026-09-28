import http.server
import socket
import sys
import tempfile
import threading
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "agents"))

import dast_nuclei  # noqa: E402
import graph  # noqa: E402
from active_scan_guard import TargetNotAuthorizedError  # noqa: E402
from llm_router import CredentialRouter, Provider  # noqa: E402

FAKE_PROVIDERS = [
    Provider("prov_a", "https://a.example/v1", "PROV_A_KEY", "model-a", "capaz"),
    Provider("prov_b", "https://b.example/v1", "PROV_B_KEY", "model-b", "rapido"),
]

NUCLEI_TEMPLATES_DIR = "/root/nuclei-templates"


def _fake_llm_client(content: str):
    client = MagicMock()
    response = MagicMock()
    response.choices = [MagicMock(message=MagicMock(content=content))]
    client.chat.completions.create.return_value = response
    return client


@pytest.fixture
def local_http_target():
    serve_dir = tempfile.mkdtemp(prefix="active-scan-test-")
    (Path(serve_dir) / "index.html").write_text("<html><body>test</body></html>")

    def handler(*args, **kwargs):
        return http.server.SimpleHTTPRequestHandler(*args, directory=serve_dir, **kwargs)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.asyncio
async def test_run_active_scan_rejects_without_authorization():
    with pytest.raises(TargetNotAuthorizedError):
        await graph.run_active_scan(
            "http://localhost:9999",
            environment="local_staging",
            confirm_own_target=False,
        )


@pytest.mark.asyncio
async def test_run_active_scan_rejects_production_without_second_confirmation():
    with pytest.raises(TargetNotAuthorizedError):
        await graph.run_active_scan(
            "https://miapp.com",
            environment="production",
            confirm_own_target=True,
            confirm_production_risk=False,
        )


@pytest.mark.asyncio
async def test_run_active_scan_handles_missing_nuclei_gracefully(monkeypatch):
    monkeypatch.setattr(dast_nuclei, "is_nuclei_available", lambda: False)
    monkeypatch.setattr(graph, "run_nuclei_scan", dast_nuclei.run_nuclei_scan)

    router = CredentialRouter(providers=FAKE_PROVIDERS)
    result = await graph.run_active_scan(
        "http://localhost:9999",
        environment="local_staging",
        confirm_own_target=True,
        router=router,
    )
    assert "error" in result


@pytest.mark.skipif(
    not dast_nuclei.is_nuclei_available() or not Path(NUCLEI_TEMPLATES_DIR).exists(),
    reason="nuclei o los templates no estan disponibles en este entorno",
)
@pytest.mark.asyncio
async def test_run_active_scan_end_to_end_real_nuclei_mocked_llm(
    local_http_target, monkeypatch
):
    monkeypatch.setattr(graph, "NUCLEI_TEMPLATES_DIR", NUCLEI_TEMPLATES_DIR)
    monkeypatch.setenv("PROV_A_KEY", "key-a")
    monkeypatch.setenv("PROV_B_KEY", "key-b")

    client = _fake_llm_client("confirmo: sin riesgos criticos detectados")
    router = CredentialRouter(providers=FAKE_PROVIDERS, client_factory=lambda k, u: client)

    result = await graph.run_active_scan(
        local_http_target,
        environment="local_staging",
        confirm_own_target=True,
        router=router,
        severity=[],  # sin filtro de severidad, pero acotado por tags abajo
        tags=["tech"],  # pocos templates, rapido: solo para validar el flujo
    )

    valid_readiness = {"READY", "CONDITIONAL", "NOT_ASSESSED", "BLOCKED"}
    assert result["target"] == local_http_target
    assert "score" in result
    assert result["score"]["production_readiness"] in valid_readiness
    if result["findings"]:
        assert result["ensemble"]["scan_provider"] != result["ensemble"]["debate_provider"]
