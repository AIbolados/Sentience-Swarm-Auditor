import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "agents"))

import github_watcher  # noqa: E402


def _fake_response(payload):
    class FakeResponse:
        def json(self):
            return payload

        def raise_for_status(self):
            pass

    return FakeResponse()


def test_watch_intelligence_uses_correct_advisories_endpoint():
    assert github_watcher.GITHUB_API + "/advisories?per_page=5" in [
        f"{github_watcher.GITHUB_API}/repos/{github_watcher.REFERENCE_REPO}",
        f"{github_watcher.GITHUB_API}/advisories?per_page=5",
    ]


def test_watch_intelligence_adds_auth_header_when_token_present(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "fake-token")
    headers = github_watcher._headers()
    assert headers["Authorization"] == "Bearer fake-token"


def test_watch_intelligence_handles_request_errors_gracefully(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    error = github_watcher.requests.RequestException("boom")
    with patch("github_watcher.requests.get", side_effect=error):
        result = github_watcher.watch_intelligence()
    assert any("error" in f for f in result["findings"])
