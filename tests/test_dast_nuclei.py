import http.server
import socket
import sys
import tempfile
import threading
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "agents"))

import dast_nuclei  # noqa: E402

NUCLEI_TEMPLATES_DIR = "/root/nuclei-templates"


def test_extract_finding_normalizes_and_drops_raw_request_response():
    raw = {
        "template-id": "tech-detect",
        "info": {"name": "Wappalyzer", "severity": "info", "tags": ["tech"]},
        "matched-at": "http://x/",
        "matcher-name": "python",
        "curl-command": "curl http://x/",
        "request": "GET / HTTP/1.1\r\n...(muy largo)...",
        "response": "HTTP/1.1 200 OK\r\n...(muy largo, puede tener datos sensibles)...",
    }
    finding = dast_nuclei._extract_finding(raw)
    assert finding["template_id"] == "tech-detect"
    assert finding["severity"] == "info"
    assert "request" not in finding
    assert "response" not in finding


def test_is_nuclei_available_false_when_binary_missing():
    with patch.object(dast_nuclei.shutil, "which", return_value=None):
        assert dast_nuclei.is_nuclei_available() is False


def test_run_nuclei_scan_raises_when_not_available():
    with patch.object(dast_nuclei, "is_nuclei_available", return_value=False):
        with pytest.raises(dast_nuclei.NucleiNotAvailableError):
            dast_nuclei.run_nuclei_scan(
                "http://localhost:1", rate_limit=10, concurrency=1, max_duration_seconds=5
            )


def test_run_nuclei_scan_wraps_timeout_as_scan_error():
    import subprocess

    with patch.object(dast_nuclei, "is_nuclei_available", return_value=True):
        with patch.object(
            dast_nuclei.subprocess, "run",
            side_effect=subprocess.TimeoutExpired(cmd="nuclei", timeout=5),
        ):
            with pytest.raises(dast_nuclei.NucleiScanError):
                dast_nuclei.run_nuclei_scan(
                    "http://localhost:1", rate_limit=10, concurrency=1, max_duration_seconds=5
                )


@pytest.fixture
def local_http_target():
    """Servidor HTTP real en un directorio vacio y aislado (no /tmp
    completo), para no exponer archivos del sistema en las respuestas."""
    serve_dir = tempfile.mkdtemp(prefix="nuclei-test-target-")
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


@pytest.mark.skipif(
    not dast_nuclei.is_nuclei_available() or not Path(NUCLEI_TEMPLATES_DIR).exists(),
    reason="nuclei o los templates no estan disponibles en este entorno",
)
def test_run_nuclei_scan_real_against_local_target(local_http_target):
    """Integracion real (no mock): corre nuclei de verdad contra un
    servidor HTTP propio y aislado, validando el parseo del JSONL real."""
    findings = dast_nuclei.run_nuclei_scan(
        local_http_target,
        rate_limit=50,
        concurrency=10,
        max_duration_seconds=30,
        templates_dir=NUCLEI_TEMPLATES_DIR,
        tags=["tech"],
    )
    assert isinstance(findings, list)
    for finding in findings:
        assert "template_id" in finding
        assert "severity" in finding
        assert "request" not in finding
        assert "response" not in finding
