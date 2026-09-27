import sys
from pathlib import Path
from unittest.mock import MagicMock

import httpx
import openai
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "agents"))

from llm_router import CredentialRouter, NoProviderAvailableError, Provider  # noqa: E402

FAKE_PROVIDERS = [
    Provider("prov_a", "https://a.example/v1", "PROV_A_KEY", "model-a", "capaz"),
    Provider("prov_b", "https://b.example/v1", "PROV_B_KEY", "model-b", "rapido"),
    Provider("prov_c", "https://c.example/v1", "PROV_C_KEY", "model-c", "rapido"),
]


def _set_all_keys(monkeypatch):
    monkeypatch.setenv("PROV_A_KEY", "key-a")
    monkeypatch.setenv("PROV_B_KEY", "key-b")
    monkeypatch.setenv("PROV_C_KEY", "key-c")


def _fake_client(content: str = "ok", raise_error: Exception | None = None):
    client = MagicMock()
    if raise_error:
        client.chat.completions.create.side_effect = raise_error
    else:
        response = MagicMock()
        response.choices = [MagicMock(message=MagicMock(content=content))]
        client.chat.completions.create.return_value = response
    return client


def _rate_limit_error() -> openai.RateLimitError:
    req = httpx.Request("POST", "https://example.com")
    resp = httpx.Response(429, request=req)
    return openai.RateLimitError("rate limited", response=resp, body=None)


def test_configured_providers_filters_by_env(monkeypatch):
    monkeypatch.delenv("PROV_A_KEY", raising=False)
    monkeypatch.delenv("PROV_B_KEY", raising=False)
    monkeypatch.delenv("PROV_C_KEY", raising=False)
    monkeypatch.setenv("PROV_B_KEY", "key-b")

    router = CredentialRouter(providers=FAKE_PROVIDERS)
    assert [p.name for p in router.configured_providers()] == ["prov_b"]


def test_chat_uses_first_available_provider_round_robin(monkeypatch):
    _set_all_keys(monkeypatch)
    client = _fake_client("respuesta")
    router = CredentialRouter(providers=FAKE_PROVIDERS, client_factory=lambda k, u: client)

    provider_name, content = router.chat([{"role": "user", "content": "hola"}])
    assert provider_name == "prov_a"
    assert content == "respuesta"


def test_chat_rotates_on_second_call(monkeypatch):
    _set_all_keys(monkeypatch)
    client = _fake_client("respuesta")
    router = CredentialRouter(providers=FAKE_PROVIDERS, client_factory=lambda k, u: client)

    first, _ = router.chat([{"role": "user", "content": "1"}])
    second, _ = router.chat([{"role": "user", "content": "2"}])
    assert first == "prov_a"
    assert second == "prov_b"


def test_rate_limit_triggers_cooldown_and_fallback(monkeypatch):
    _set_all_keys(monkeypatch)

    def factory(api_key, base_url):
        if base_url == FAKE_PROVIDERS[0].base_url:
            return _fake_client(raise_error=_rate_limit_error())
        return _fake_client("respuesta de b")

    router = CredentialRouter(providers=FAKE_PROVIDERS, client_factory=factory)
    provider_name, content = router.chat([{"role": "user", "content": "hola"}])

    assert provider_name == "prov_b"
    assert content == "respuesta de b"
    assert router._is_in_cooldown("prov_a") is True


def test_chat_ensemble_never_repeats_provider(monkeypatch):
    _set_all_keys(monkeypatch)
    client = _fake_client("hallazgo")
    router = CredentialRouter(providers=FAKE_PROVIDERS, client_factory=lambda k, u: client)

    result = router.chat_ensemble(
        scan_messages=[{"role": "user", "content": "scan"}],
        debate_messages_builder=lambda scan_provider, scan_output: [
            {"role": "user", "content": f"revisa esto de {scan_provider}: {scan_output}"}
        ],
    )

    assert result["scan_provider"] != result["debate_provider"]
    assert result["scan_provider"] == "prov_a"
    assert result["debate_provider"] == "prov_b"


def test_no_provider_available_raises(monkeypatch):
    monkeypatch.delenv("PROV_A_KEY", raising=False)
    monkeypatch.delenv("PROV_B_KEY", raising=False)
    monkeypatch.delenv("PROV_C_KEY", raising=False)

    router = CredentialRouter(providers=FAKE_PROVIDERS)
    with pytest.raises(NoProviderAvailableError):
        router.chat([{"role": "user", "content": "hola"}])
