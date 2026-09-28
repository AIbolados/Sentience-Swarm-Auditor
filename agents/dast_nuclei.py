"""Wrapper de Nuclei para el motor DAST activo (Fase 4).

Nuclei nunca genera payloads "a mano": ejecuta templates YAML curados por
la comunidad (ProjectDiscovery, +14.000 templates) contra un target HTTP.
Este modulo solo invoca el binario con los limites de agresividad que
decide agents/active_scan_guard.py y normaliza su salida para el LLM.

Instalacion (no incluida aqui a proposito, es infraestructura, no codigo
de la app):
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    git clone --depth=1 https://github.com/projectdiscovery/nuclei-templates.git
"""

import json
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)

NUCLEI_BINARY = "nuclei"


class NucleiNotAvailableError(RuntimeError):
    pass


class NucleiScanError(RuntimeError):
    pass


def is_nuclei_available() -> bool:
    return shutil.which(NUCLEI_BINARY) is not None


def _extract_finding(raw: dict) -> dict:
    """Normaliza un resultado crudo de nuclei a los campos relevantes para
    el LLM. Deliberadamente NO incluye request/response completos: pueden
    ser grandes y exponer contenido sensible del target en el reporte."""
    info = raw.get("info", {}) or {}
    return {
        "template_id": raw.get("template-id"),
        "name": info.get("name"),
        "severity": info.get("severity"),
        "tags": info.get("tags"),
        "matched_at": raw.get("matched-at") or raw.get("url"),
        "matcher_name": raw.get("matcher-name"),
        "curl_command": raw.get("curl-command"),
    }


def run_nuclei_scan(
    target: str,
    rate_limit: int,
    concurrency: int,
    max_duration_seconds: int,
    templates_dir: str | None = None,
    tags: list[str] | None = None,
    severity: list[str] | None = None,
) -> list[dict]:
    """Corre nuclei contra target y devuelve los hallazgos normalizados.

    Lista vacia = sin hallazgos, no es un error. Lanza NucleiScanError
    solo si nuclei mismo no pudo ejecutarse (timeout, binario roto, etc).

    Los limites (rate_limit, concurrency, max_duration_seconds) los debe
    fijar el llamador segun ScanAuthorization.limits (mas conservador en
    produccion que en local/staging) - este wrapper no decide agresividad,
    solo la aplica.
    """
    if not is_nuclei_available():
        raise NucleiNotAvailableError(
            "nuclei no esta instalado. Instalalo con: go install "
            "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        )

    with tempfile.TemporaryDirectory(prefix="audit-mcp-nuclei-") as tmp_dir:
        output_path = Path(tmp_dir) / "results.jsonl"

        cmd = [
            NUCLEI_BINARY,
            "-target", target,
            "-jsonl-export", str(output_path),
            "-rate-limit", str(rate_limit),
            "-concurrency", str(concurrency),
            "-silent",
            "-no-interactsh",
        ]
        if templates_dir:
            cmd += ["-templates", templates_dir]
        if tags:
            cmd += ["-tags", ",".join(tags)]
        if severity:
            cmd += ["-severity", ",".join(severity)]

        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=max_duration_seconds)
        except (OSError, subprocess.TimeoutExpired) as e:
            raise NucleiScanError(f"nuclei fallo al ejecutar contra {target}: {e}") from e

        if not output_path.exists():
            return []

        findings = []
        for line in output_path.read_text().strip().splitlines():
            if not line:
                continue
            try:
                findings.append(_extract_finding(json.loads(line)))
            except json.JSONDecodeError:
                logger.warning("Linea invalida en salida de nuclei, se omite: %.200s", line)

        return findings
