import json
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "agents"))

from llm_router import CredentialRouter, NoProviderAvailableError, Provider  # noqa: E402

PROVIDERS = [
    Provider("prov_a", "https://a.example/v1", "PROV_A_KEY", "model-a", "capaz", family="fam_x"),
    Provider("prov_b", "https://b.example/v1", "PROV_B_KEY", "model-b", "rapido", family="fam_x"),
    Provider("prov_c", "https://c.example/v1", "PROV_C_KEY", "model-c", "rapido", family="fam_y"),
]


def _client(content: str):
    client = MagicMock()
    response = MagicMock()
    response.choices = [MagicMock(message=MagicMock(content=content))]
    client.chat.completions.create.return_value = response
    return client


def _keys(monkeypatch, *names):
    for env in ("PROV_A_KEY", "PROV_B_KEY", "PROV_C_KEY"):
        monkeypatch.delenv(env, raising=False)
    for name in names:
        monkeypatch.setenv(name, "k")


def _router(clients: dict):
    return CredentialRouter(providers=PROVIDERS, client_factory=lambda key, url: clients[url])


def test_chat_skips_excluded_families(monkeypatch):
    _keys(monkeypatch, "PROV_A_KEY", "PROV_B_KEY", "PROV_C_KEY")
    router = _router({p.base_url: _client("ok") for p in PROVIDERS})
    name, _ = router.chat([{"role": "user", "content": "x"}], exclude_families=frozenset({"fam_x"}))
    assert name == "prov_c"


def test_family_and_model_can_be_pinned_from_env(monkeypatch):
    monkeypatch.setenv("PROV_A_FAMILY", "otra_familia")
    monkeypatch.setenv("PROV_A_MODEL", "modelo-fijado")
    assert PROVIDERS[0].model_family == "otra_familia"
    assert PROVIDERS[0].model == "modelo-fijado"


def test_family_is_verified_only_with_pinned_model_and_family(monkeypatch):
    monkeypatch.delenv("PROV_A_MODEL", raising=False)
    monkeypatch.delenv("PROV_A_FAMILY", raising=False)
    auto = Provider("agg", "https://agg/v1", "AGG_KEY", "auto", "volumen", family="fam_z")
    no_family = Provider("nofam", "https://n/v1", "N_KEY", "model-n", "volumen")
    assert PROVIDERS[0].family_verified is True
    assert auto.family_verified is False
    assert no_family.family_verified is False
    assert no_family.model_family == "nofam"


def test_chat_json_rotates_past_a_provider_with_invalid_json(monkeypatch):
    _keys(monkeypatch, "PROV_A_KEY", "PROV_B_KEY")
    router = _router({
        PROVIDERS[0].base_url: _client("esto no es json"),
        PROVIDERS[1].base_url: _client(json.dumps({"ok": True})),
    })
    provider, data = router.chat_json([{"role": "user", "content": "x"}], validator=json.loads)
    assert provider.name == "prov_b"
    assert data == {"ok": True}
    assert router.stats["prov_a"]["invalid_json"] == 1


def test_provider_is_quarantined_after_three_consecutive_invalid_responses(monkeypatch):
    _keys(monkeypatch, "PROV_A_KEY")
    router = _router({PROVIDERS[0].base_url: _client("basura")})
    for _ in range(3):
        with pytest.raises(NoProviderAvailableError):
            router.chat_json([{"role": "user", "content": "x"}], validator=json.loads)
    assert router._is_in_cooldown("prov_a") is True


def test_valid_response_resets_the_invalid_streak(monkeypatch):
    _keys(monkeypatch, "PROV_A_KEY")
    router = _router({PROVIDERS[0].base_url: _client("basura")})
    for _ in range(2):
        with pytest.raises(NoProviderAvailableError):
            router.chat_json([{"role": "user", "content": "x"}], validator=json.loads)
    router._client_factory = lambda key, url: _client("{}")
    router.chat_json([{"role": "user", "content": "x"}], validator=json.loads)
    router._client_factory = lambda key, url: _client("basura")
    with pytest.raises(NoProviderAvailableError):
        router.chat_json([{"role": "user", "content": "x"}], validator=json.loads)
    assert router._is_in_cooldown("prov_a") is False
