"""Rotador de credenciales multi-proveedor LLM.

Todos los proveedores del pool exponen (o pueden tratarse como) un endpoint
OpenAI-compatible (/v1/chat/completions), asi que un unico cliente sirve
para los 7: no hay parsers distintos por proveedor, solo cambia
base_url + api_key + modelo. La rotacion, el cooldown por rate limit y la
exclusion de proveedores (para el patron scan/debate) viven en esta capa,
separados del transporte.
"""

import logging
import os
import time
from dataclasses import dataclass

import openai
from openai import OpenAI

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Provider:
    name: str
    base_url: str
    env_key: str
    default_model: str
    tier: str  # "capaz" | "rapido" | "volumen"


PROVIDERS: list[Provider] = [
    Provider(
        name="nararouter", base_url="https://router.bynara.id/v1",
        env_key="NARAROUTER_API_KEY", default_model="auto", tier="volumen",
    ),
    Provider(
        name="tokenrouter", base_url="https://api.tokenrouter.io/v1",
        env_key="TOKENROUTER_API_KEY", default_model="auto", tier="volumen",
    ),
    Provider(
        name="openrouter", base_url="https://openrouter.ai/api/v1",
        env_key="OPENROUTER_API_KEY", default_model="auto", tier="capaz",
    ),
    Provider(
        name="mistral", base_url="https://api.mistral.ai/v1",
        env_key="MISTRAL_API_KEY", default_model="mistral-large-latest", tier="capaz",
    ),
    Provider(
        name="gemini", base_url="https://generativelanguage.googleapis.com/v1beta/openai/",
        env_key="GEMINI_API_KEY", default_model="gemini-2.0-flash", tier="rapido",
    ),
    Provider(
        name="groq", base_url="https://api.groq.com/openai/v1",
        env_key="GROQ_API_KEY", default_model="llama-3.3-70b-versatile", tier="rapido",
    ),
    Provider(
        name="huggingface", base_url="https://router.huggingface.co/v1",
        env_key="HF_TOKEN", default_model="auto", tier="rapido",
    ),
]

DEFAULT_COOLDOWN_SECONDS = 60
DEFAULT_TIMEOUT_SECONDS = 60


class NoProviderAvailableError(RuntimeError):
    pass


class CredentialRouter:
    """Round-robin sobre el pool de proveedores, con cooldown en 429 y
    exclusion explicita (para garantizar que scan_agent y debate_agent
    de un mismo proyecto nunca usen el mismo proveedor)."""

    def __init__(
        self,
        providers: list[Provider] | None = None,
        cooldown_seconds: float = DEFAULT_COOLDOWN_SECONDS,
        client_factory=None,
    ):
        self._providers = providers if providers is not None else PROVIDERS
        self._cooldown_seconds = cooldown_seconds
        self._cooldown_until: dict[str, float] = {}
        self._rr_index = 0
        self._client_factory = client_factory or (
            lambda api_key, base_url: OpenAI(api_key=api_key, base_url=base_url)
        )

    def configured_providers(self) -> list[Provider]:
        """Proveedores con su API key presente en el entorno, sin filtrar por cooldown."""
        return [p for p in self._providers if os.environ.get(p.env_key)]

    def _is_in_cooldown(self, provider_name: str) -> bool:
        return self._cooldown_until.get(provider_name, 0.0) > time.monotonic()

    def _next_provider(self, exclude: set[str]) -> Provider | None:
        n = len(self._providers)
        for offset in range(n):
            idx = (self._rr_index + offset) % n
            provider = self._providers[idx]
            if (
                provider.name not in exclude
                and os.environ.get(provider.env_key)
                and not self._is_in_cooldown(provider.name)
            ):
                self._rr_index = idx + 1
                return provider
        return None

    def mark_cooldown(self, provider_name: str, seconds: float | None = None) -> None:
        effective_seconds = seconds or self._cooldown_seconds
        self._cooldown_until[provider_name] = time.monotonic() + effective_seconds
        logger.warning("Proveedor %s en cooldown %ss", provider_name, effective_seconds)

    def chat(
        self,
        messages: list[dict],
        exclude: set[str] | None = None,
        model: str | None = None,
        max_attempts: int | None = None,
    ) -> tuple[str, str]:
        """Devuelve (nombre_proveedor, contenido_respuesta). Si un proveedor
        da rate limit, lo pone en cooldown y reintenta con el siguiente
        disponible; otros errores excluyen al proveedor solo para este intento."""
        exclude = set(exclude or set())
        max_attempts = max_attempts or len(self._providers)
        last_error: Exception | None = None

        for _ in range(max_attempts):
            provider = self._next_provider(exclude)
            if provider is None:
                break

            api_key = os.environ[provider.env_key]
            client = self._client_factory(api_key, provider.base_url)
            try:
                response = client.chat.completions.create(
                    model=model or provider.default_model,
                    messages=messages,
                    timeout=DEFAULT_TIMEOUT_SECONDS,
                )
                return provider.name, response.choices[0].message.content
            except openai.RateLimitError as e:
                last_error = e
                self.mark_cooldown(provider.name)
                exclude.add(provider.name)
            except openai.APIError as e:
                last_error = e
                logger.warning("Error de %s: %s", provider.name, e)
                exclude.add(provider.name)

        raise NoProviderAvailableError(
            f"Ningun proveedor LLM disponible tras {max_attempts} intentos "
            f"(ultimo error: {last_error})"
        )

    def chat_ensemble(
        self,
        scan_messages: list[dict],
        debate_messages_builder,
    ) -> dict:
        """Patron scan + debate: dos proveedores distintos garantizados.
        debate_messages_builder(scan_provider, scan_output) -> list[dict]
        """
        scan_provider, scan_output = self.chat(scan_messages)
        debate_messages = debate_messages_builder(scan_provider, scan_output)
        debate_provider, debate_output = self.chat(debate_messages, exclude={scan_provider})
        return {
            "scan_provider": scan_provider,
            "scan_output": scan_output,
            "debate_provider": debate_provider,
            "debate_output": debate_output,
        }
