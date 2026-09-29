"""Deteccion de secretos y redaccion de evidencia.

Dos responsabilidades acopladas a proposito (comparten los mismos patrones,
asi lo que se detecta es exactamente lo que se redacta antes de enviar
evidencia a un LLM o escribirla en un reporte):

- scan_secrets(): recorre los archivos de texto del target y devuelve Findings.
- redact()/read_context()/attach_evidence(): evidencia con secretos enmascarados.

Los archivos .env reales NO se leen nunca: solo se reporta si estan
versionados en git. Las plantillas (.env.example, etc.) si se escanean.
"""

import base64
import json
import logging
import math
import os
import re
import subprocess
from itertools import islice
from pathlib import Path
from typing import NamedTuple, TypedDict

from findings import Finding, make_finding

logger = logging.getLogger(__name__)

MAX_FILE_BYTES = 1_000_000
MAX_LINE_CHARS = 5000
MAX_FINDINGS_PER_FILE = 20
BINARY_SNIFF_BYTES = 4096
ENV_TEMPLATE_SUFFIXES = (".example", ".sample", ".template", ".dist")

PLACEHOLDER_RE = re.compile(
    r"^(?:<[^>]*>|\$\{[^}]*\}|\{\{[^}]*\}\}|x{4,}|\*{4,}|password|secret|token"
    r"|(?:your|my|example|sample|dummy|test|fake|changeme|change_me|replace|todo|placeholder)[\w-]*)$",
    re.IGNORECASE,
)


class _Pattern(NamedTuple):
    rule: str
    regex: re.Pattern
    severity: str
    tier: str
    group: int  # grupo que contiene el secreto (0 = match completo)
    min_entropy: float


class _Hit(NamedTuple):
    start: int
    end: int
    rule: str
    severity: str
    tier: str


# El orden importa: patrones especificos antes que los genericos; los spans
# solapados se descartan (gana el primero).
PATTERNS: tuple[_Pattern, ...] = (
    _Pattern("private-key", re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----"),
        "critical", "deterministic", 0, 0.0),
    _Pattern("anthropic-api-key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}"),
             "critical", "deterministic", 0, 0.0),
    _Pattern("openai-api-key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}"),
             "critical", "deterministic", 0, 3.5),
    _Pattern("aws-access-key-id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
             "critical", "deterministic", 0, 0.0),
    _Pattern("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
             "critical", "deterministic", 0, 0.0),
    _Pattern("stripe-live-key", re.compile(r"\b[sr]k_live_[0-9A-Za-z]{20,}\b"),
             "critical", "deterministic", 0, 0.0),
    _Pattern("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"),
             "high", "deterministic", 0, 0.0),
    _Pattern("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
             "high", "deterministic", 0, 0.0),
    _Pattern("jwt", re.compile(
        r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
        "medium", "heuristic", 0, 0.0),  # regla/severidad segun el rol (ver _classify_jwt)
    _Pattern("db-connection-string", re.compile(
        r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://"
        r"[^\s:@/]+:([^\s@/'\"]+)@"),
        "high", "deterministic", 1, 0.0),
    _Pattern("generic-secret-assignment", re.compile(
        r"""(?i)(?:api[_-]?key|secret|token|passwd|password|pwd)[\w-]*"""
        r"""["']?\s*[:=]\s*["']([^"'\s]{12,})["']"""),
        "medium", "heuristic", 1, 3.0),
)


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    length = len(value)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in (value.count(char) for char in set(value))
    )


def _is_placeholder(value: str) -> bool:
    return bool(PLACEHOLDER_RE.match(value))


def _b64url_json(segment: str) -> dict | None:
    try:
        padded = segment + "=" * (-len(segment) % 4)
        data = json.loads(base64.urlsafe_b64decode(padded.encode()))
    except ValueError:  # incluye binascii.Error y JSONDecodeError
        return None
    return data if isinstance(data, dict) else None


def _classify_jwt(token: str) -> tuple[str, str, str] | None:
    """(regla, severidad, tier) o None si es publico por diseno (Supabase anon)."""
    payload = _b64url_json(token.split(".")[1])
    role = payload.get("role") if payload else None
    if role == "service_role":
        return "supabase-service-role-jwt", "critical", "deterministic"
    if role == "anon":
        return None
    return "jwt", "medium", "heuristic"


def _find_hits(line: str) -> list[_Hit]:
    line = line[:MAX_LINE_CHARS]
    taken: list[tuple[int, int]] = []
    hits: list[_Hit] = []
    for pattern in PATTERNS:
        for match in pattern.regex.finditer(line):
            start, end = match.span(pattern.group)
            if any(s < end and start < e for s, e in taken):
                continue
            value = line[start:end]
            rule, severity, tier = pattern.rule, pattern.severity, pattern.tier
            if pattern.rule == "jwt":
                classified = _classify_jwt(value)
                if classified is None:
                    continue
                rule, severity, tier = classified
            if pattern.rule in ("db-connection-string", "generic-secret-assignment") and (
                _is_placeholder(value)
            ):
                continue
            if pattern.min_entropy and _entropy(value) < pattern.min_entropy:
                continue
            taken.append((start, end))
            hits.append(_Hit(start, end, rule, severity, tier))
    return sorted(hits)


def redact(text: str) -> str:
    """Reemplaza cada secreto detectado por [REDACTED:<regla>]."""
    out = []
    for line in text.split("\n"):
        if len(line) > MAX_LINE_CHARS:
            line = line[:MAX_LINE_CHARS] + "...[truncado]"
        for hit in reversed(_find_hits(line)):
            line = f"{line[:hit.start]}[REDACTED:{hit.rule}]{line[hit.end:]}"
        out.append(line)
    return "\n".join(out)


def is_env_file(name: str) -> bool:
    if name == ".env":
        return True
    return name.startswith(".env.") and not name.endswith(ENV_TEMPLATE_SUFFIXES)


def _is_tracked(root: str, rel: str) -> bool:
    """True si git versiona el archivo. Se desactiva fsmonitor por linea de
    comandos: un .git/config hostil no debe poder ejecutar comandos."""
    try:
        proc = subprocess.run(
            ["git", "-c", "core.fsmonitor=false", "-C", root,
             "ls-files", "--error-unmatch", "--", rel],
            capture_output=True, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0


def _read_text(path: str) -> str | None:
    try:
        if os.path.getsize(path) > MAX_FILE_BYTES:
            return None
        with open(path, "rb") as handle:
            head = handle.read(BINARY_SNIFF_BYTES)
            if b"\0" in head:
                return None
            data = head + handle.read()
    except OSError as e:
        logger.debug("No se pudo leer %s: %s", path, e)
        return None
    return data.decode("utf-8", errors="replace")


class SecretScan(TypedDict):
    findings: list[Finding]
    files_scanned: int
    files_skipped: int


def scan_secrets(root: str, files: list[str]) -> SecretScan:
    findings: list[Finding] = []
    scanned = 0
    skipped = 0
    for rel in files:
        name = os.path.basename(rel)
        if is_env_file(name):
            skipped += 1
            if _is_tracked(root, rel):
                findings.append(make_finding(
                    source="secrets", rule="env-file-tracked", severity="high",
                    tier="deterministic", file=rel, line=None,
                    message=f"Archivo de entorno versionado en el repositorio: {name}",
                    evidence="(contenido no leido por diseno)",
                ))
            continue
        text = _read_text(os.path.join(root, rel))
        if text is None:
            skipped += 1
            continue
        scanned += 1
        per_file = 0
        for lineno, line in enumerate(text.split("\n"), start=1):
            for hit in _find_hits(line):
                findings.append(make_finding(
                    source="secrets", rule=hit.rule, severity=hit.severity,
                    tier=hit.tier, file=rel, line=lineno,
                    message=f"Posible secreto expuesto ({hit.rule})",
                ))
                per_file += 1
            if per_file >= MAX_FINDINGS_PER_FILE:
                logger.warning("%s: tope de %d hallazgos de secretos", rel, MAX_FINDINGS_PER_FILE)
                break
    return SecretScan(findings=findings, files_scanned=scanned, files_skipped=skipped)


def read_context(
    root: str, rel: str, line: int | None, radius: int = 2, max_chars: int = 600
) -> str:
    """Lineas [line-radius, line+radius] del archivo, numeradas y REDACTADAS.
    Devuelve "" si no hay linea, el archivo es un .env, la ruta escapa del
    target (.., symlinks) o no se puede leer."""
    if line is None or line < 1 or is_env_file(os.path.basename(rel)):
        return ""
    try:
        root_path = Path(root).resolve()
        target = (root_path / rel).resolve()
        target.relative_to(root_path)
        first = max(1, line - radius)
        with target.open("r", encoding="utf-8", errors="replace") as handle:
            lines = list(islice(handle, first - 1, line + radius))
    except (OSError, ValueError):
        return ""
    numbered = "\n".join(
        f"{number}: {text.rstrip()[:MAX_LINE_CHARS]}"
        for number, text in enumerate(lines, start=first)
    )
    return redact(numbered)[:max_chars]


def attach_evidence(root: str, findings: list[Finding]) -> None:
    """Completa evidence (redactada) y redacta message en cada hallazgo."""
    for finding in findings:
        finding["message"] = redact(finding["message"])
        if finding["evidence"]:
            continue
        finding["evidence"] = (
            read_context(root, finding["file"], finding["line"]) or finding["message"][:300]
        )
