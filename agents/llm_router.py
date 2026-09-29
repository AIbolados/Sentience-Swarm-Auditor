"""Rotador de credenciales multi-proveedor LLM.

Todos los proveedores del pool exponen (o pueden tratarse como) un endpoint
OpenAI-compatible (/v1/chat/completions), asi que un unico cliente sirve
para los 7: solo cambia base_url + api_key + modelo. La rotacion, el
cooldown por rate limit, la cuarentena por respuestas invalidas y la
exclusion por proveedor o por FAMILIA de modelo viven en esta capa,
separados del transporte.

Familia: el modelo subyacente. Los agregadores con model="auto" (nararouter,
tokenrouter, openrouter, huggingface) pueden enrutar al mismo modelo que otro
proveedor del pool; hasta que se fije <NOMBRE>_MODEL y <NOMBRE>_FAMILY en el
entorno, su familia NO esta verificada y el panel no puede probar diversidad.
"""

import logging
import os
import threading
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
    family: str = ""  # familia del modelo subyacente; "" = desconocida

    @property
    def model(self) -> str:
        return os.environ.get(f"{self.name.upper()}_MODEL") or self.default_model

    @property
    def model_family(self) -> str:
        return os.environ.get(f"{self.name.upper()}_FAMILY") or self.family or self.name

    @property
    def family_verified(self) -> bool:
        declared = os.environ.get(f"{self.name.upper()}_FAMILY") or self.family
        return self.model != "auto" and bool(declared)


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
        family="mistral",
    ),
    Provider(
        name="gemini", base_url="https://generativelanguage.googleapis.com/v1beta/openai/",
        env_key="GEMINI_API_KEY", default_model="gemini-2.0-flash", tier="rapido",
        family="gemini",
    ),
    Provider(
        name="groq", base_url="https://api.groq.com/openai/v1",
        env_key="GROQ_API_KEY", default_model="llama-3.3-70b-versatile", tier="rapido",
        family="llama",
    ),
    Provider(
        name="huggingface", base_url="https://router.huggingface.co/v1",
        env_key="HF_TOKEN", default_model="auto", tier="rapido",
    ),
]

DEFAULT_COOLDOWN_SECONDS = 60
DEFAULT_TIMEOUT_SECONDS = 60
INVALID_STREAK_LIMIT = 3
QUARANTINE_SECONDS = 600


class NoProviderAvailableError(RuntimeError):
    pass


class ProviderResponseError(ValueError):
    """El proveedor respondio 200 pero sin contenido utilizable."""


class CredentialRouter:
    """Round-robin sobre el pool, con cooldown en 429, cuarentena tras
    respuestas invalidas consecutivas y exclusion por nombre o familia."""

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
        self._lock = threading.Lock()  # el grafo audita proyectos en threads concurrentes
        self._invalid_streak: dict[str, int] = {}
        self.stats: dict[str, dict[str, int]] = {}
        self._client_factory = client_factory or (
            lambda api_key, base_url: OpenAI(api_key=api_key, base_url=base_url)
        )

    def configured_providers(self) -> list[Provider]:
        """Proveedores con su API key presente en el entorno, sin filtrar por cooldown."""
        return [p for p in self._providers if os.environ.get(p.env_key)]

    def _is_in_cooldown(self, provider_name: str) -> bool:
        return self._cooldown_until.get(provider_name, 0.0) > time.monotonic()

    def _next_provider(
        self, exclude: set[str], exclude_families: frozenset[str] = frozenset()
    ) -> Provider | None:
        with self._lock:
            n = len(self._providers)
            for offset in range(n):
                idx = (self._rr_index + offset) % n
                provider = self._providers[idx]
                if (
                    provider.name not in exclude
                    and provider.model_family not in exclude_families
                    and os.environ.get(provider.env_key)
                    and not self._is_in_cooldown(provider.name)
                ):
                    self._rr_index = idx + 1
                    return provider
        return None

    def mark_cooldown(self, provider_name: str, seconds: float | None = None) -> None:
        effective_seconds = seconds or self._cooldown_seconds
        with self._lock:
            self._cooldown_until[provider_name] = time.monotonic() + effective_seconds
        logger.warning("Proveedor %s en cooldown %ss", provider_name, effective_seconds)

    def _bump(self, provider_name: str, key: str) -> None:
        with self._lock:
            entry = self.stats.setdefault(
                provider_name,
                {"calls": 0, "rate_limited": 0, "api_errors": 0, "invalid_json": 0},
            )
            entry[key] += 1

    def stats_snapshot(self) -> dict[str, dict[str, int]]:
        with self._lock:
            return {name: dict(entry) for name, entry in self.stats.items()}

    def _call(self, provider: Provider, messages: list[dict], model: str | None = None) -> str:
        client = self._client_factory(os.environ[provider.env_key], provider.base_url)
        self._bump(provider.name, "calls")
        response = client.chat.completions.create(
            model=model or provider.model,
            messages=messages,
            timeout=DEFAULT_TIMEOUT_SECONDS,
        )
        choices = getattr(response, "choices", None) or []
        if not choices:
            raise ProviderResponseError(f"{provider.name}: respuesta sin choices")
        return choices[0].message.content or ""

    def chat(
        self,
        messages: list[dict],
        exclude: set[str] | None = None,
        model: str | None = None,
        max_attempts: int | None = None,
        exclude_families: frozenset[str] = frozenset(),
    ) -> tuple[str, str]:
        """Devuelve (nombre_proveedor, contenido_respuesta). Si un proveedor
        da rate limit, lo pone en cooldown y reintenta con el siguiente
        disponible; otros errores excluyen al proveedor solo para este intento."""
        exclude = set(exclude or set())
        max_attempts = max_attempts or len(self._providers)
        last_error: Exception | None = None

        for _ in range(max_attempts):
            provider = self._next_provider(exclude, exclude_families)
            if provider is None:
                break
            try:
                return provider.name, self._call(provider, messages, model)
            except openai.RateLimitError as e:
                last_error = e
                self._bump(provider.name, "rate_limited")
                self.mark_cooldown(provider.name)
                exclude.add(provider.name)
            except (openai.APIError, ProviderResponseError) as e:
                last_error = e
                self._bump(provider.name, "api_errors")
                logger.warning("Error de %s: %s", provider.name, e)
                exclude.add(provider.name)

        raise NoProviderAvailableError(
            f"Ningun proveedor LLM disponible tras {max_attempts} intentos "
            f"(ultimo error: {last_error})"
        )

    def chat_json(
        self,
        messages: list[dict],
        validator,
        exclude_families: frozenset[str] = frozenset(),
        max_attempts: int | None = None,
    ) -> tuple[Provider, dict]:
        """Como chat(), pero la respuesta debe pasar `validator(texto) -> dict`
        (lanza ValueError si es invalida). Una respuesta invalida rota al
        siguiente proveedor y cuenta para la cuarentena: tras
        INVALID_STREAK_LIMIT invalidas consecutivas el proveedor se aparta
        QUARANTINE_SECONDS. Devuelve (proveedor, datos_validados)."""
        exclude: set[str] = set()
        max_attempts = max_attempts or len(self._providers)
        last_error: Exception | None = None

        for _ in range(max_attempts):
            provider = self._next_provider(exclude, exclude_families)
            if provider is None:
                break
            try:
                content = self._call(provider, messages)
            except openai.RateLimitError as e:
                last_error = e
                self._bump(provider.name, "rate_limited")
                self.mark_cooldown(provider.name)
                exclude.add(provider.name)
                continue
            except (openai.APIError, ProviderResponseError) as e:
                last_error = e
                self._bump(provider.name, "api_errors")
                logger.warning("Error de %s: %s", provider.name, e)
                exclude.add(provider.name)
                continue

            try:
                data = validator(content)
            except ValueError as e:
                last_error = e
                self._bump(provider.name, "invalid_json")
                with self._lock:
                    streak = self._invalid_streak.get(provider.name, 0) + 1
                    self._invalid_streak[provider.name] = streak
                if streak >= INVALID_STREAK_LIMIT:
                    self.mark_cooldown(provider.name, QUARANTINE_SECONDS)
                    with self._lock:
                        self._invalid_streak[provider.name] = 0
                logger.warning("Respuesta invalida de %s: %s", provider.name, e)
                exclude.add(provider.name)
                continue

            with self._lock:
                self._invalid_streak[provider.name] = 0
            return provider, data

        raise NoProviderAvailableError(
            f"Ningun proveedor devolvio una respuesta valida tras {max_attempts} intentos "
            f"(ultimo error: {last_error})"
        )

    def chat_ensemble(
        self,
        scan_messages: list[dict],
        debate_messages_builder,
    ) -> dict:
        """Patron scan + debate: dos proveedores distintos garantizados.
        debate_messages_builder(scan_provider, scan_output) -> list[dict]
        Se conserva para el motor DAST; el analisis de codigo usa el panel.
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
