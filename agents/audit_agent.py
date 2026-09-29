"""Motor de analisis estatico: discovery -> secretos + ruff + bandit + npm audit.

Todas las herramientas se normalizan a Finding. Regla de honestidad: una
herramienta que no pudo correr NUNCA se confunde con "sin hallazgos": queda
registrada en tools[...] con su estado (unavailable/error/timeout) y baja
la confianza del resultado (ver scoring.score_project).
"""

import json
import logging
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TypedDict

sys.path.insert(0, os.path.dirname(__file__))
from change_detector import commit_hash, has_changed  # noqa: E402
from discovery import IGNORE_DIRS, DiscoveryResult, classify_target  # noqa: E402
from findings import Finding, assign_ids, make_finding  # noqa: E402
from secrets_scan import attach_evidence, scan_secrets  # noqa: E402

logger = logging.getLogger(__name__)

PROJECTS_HOME = Path(os.environ.get("PROJECTS_HOME") or Path.home())
SWARM_HOME = Path(os.environ.get("SWARM_HOME") or Path.home() / "swarm_auditor")
VENV_BIN = SWARM_HOME / "venv" / "bin"

RUFF_SELECT = "E9,F63,F7,F82"  # errores de sintaxis y nombres indefinidos: bugs reales, no estilo
MAX_NPM_MANIFESTS = 5
NPM_SEVERITY = {
    "info": "info", "low": "low", "moderate": "medium", "high": "high", "critical": "critical",
}
BANDIT_SEVERITY = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
_STATUS_RANK = {"ok": 0, "skipped": 1, "unavailable": 2, "timeout": 3, "error": 4}


@dataclass(frozen=True)
class ToolRun:
    status: str  # ok | unavailable | error | timeout
    stdout: str = ""
    detail: str = ""


class StaticResult(TypedDict):
    findings: list[Finding]
    tools: dict[str, str]  # herramienta -> ok | skipped | unavailable | error | timeout
    ok: bool  # False si alguna herramienta aplicable no completo (no persistir el hash)
    files_scanned: int


def _resolve_binary(name: str) -> str | None:
    """Busca el ejecutable en el venv del proceso actual (funciona bajo
    `uv run` y con el MCP lanzado desde el venv), luego el venv legacy del
    swarm, luego el PATH."""
    if os.path.isabs(name):
        return name if os.path.exists(name) else None
    for candidate in (Path(sys.executable).parent / name, VENV_BIN / name):
        if candidate.exists():
            return str(candidate)
    return shutil.which(name)


def run_tool(
    cmd: list[str], cwd: str | None = None, timeout: int = 60, ok_codes: tuple[int, ...] = (0, 1)
) -> ToolRun:
    """Ejecuta una herramienta. Un codigo de salida fuera de ok_codes es
    `error` (ruff/bandit/npm usan 1 para "hay hallazgos", 2+ para fallos)."""
    binary = _resolve_binary(cmd[0])
    if binary is None:
        return ToolRun("unavailable", detail=f"{cmd[0]} no esta instalado")
    try:
        proc = subprocess.run(
            [binary, *cmd[1:]], capture_output=True, text=True, timeout=timeout, cwd=cwd,
        )
    except subprocess.TimeoutExpired:
        return ToolRun("timeout", detail=f"{cmd[0]} excedio {timeout}s")
    except OSError as e:
        return ToolRun("error", detail=str(e))
    if proc.returncode not in ok_codes:
        return ToolRun("error", stdout=proc.stdout, detail=(proc.stderr or "").strip()[:300])
    return ToolRun("ok", stdout=proc.stdout)


def _rel(root: str, filename: str) -> str:
    return os.path.relpath(os.path.abspath(filename), os.path.abspath(root)).replace(os.sep, "/")


def _run_ruff(path: str) -> tuple[list[Finding], str]:
    run = run_tool([
        "ruff", "check", "--isolated", "--no-cache", "--output-format", "json",
        "--select", RUFF_SELECT, path,
    ])
    if run.status != "ok":
        logger.warning("ruff no completo sobre %s: %s %s", path, run.status, run.detail)
        return [], run.status
    try:
        items = json.loads(run.stdout or "[]")
    except json.JSONDecodeError as e:
        logger.warning("ruff devolvio JSON invalido: %s", e)
        return [], "error"
    findings = []
    for item in items:
        code = item.get("code")
        findings.append(make_finding(
            source="ruff", rule=code or "syntax-error",
            severity="medium" if not code or code.startswith("E9") else "low",
            tier="deterministic", file=_rel(path, item.get("filename", "")),
            line=(item.get("location") or {}).get("row"), message=item.get("message", ""),
        ))
    return findings, "ok"


def _run_bandit(path: str) -> tuple[list[Finding], str]:
    exclude = ",".join(f"*/{d}/*" for d in sorted(IGNORE_DIRS))
    run = run_tool(["bandit", "-r", path, "-f", "json", "-q", "-x", exclude])
    if run.status != "ok":
        logger.warning("bandit no completo sobre %s: %s %s", path, run.status, run.detail)
        return [], run.status
    try:
        data = json.loads(run.stdout)
    except json.JSONDecodeError as e:
        logger.warning("bandit devolvio JSON invalido o vacio: %s", e)
        return [], "error"
    findings = []
    for item in data.get("results", []):
        severity = BANDIT_SEVERITY.get(str(item.get("issue_severity", "")).upper(), "low")
        findings.append(make_finding(
            source="bandit", rule=item.get("test_id", "bandit"), severity=severity,
            tier="heuristic", file=_rel(path, item.get("filename", "")),
            line=item.get("line_number"),
            message=f"{item.get('issue_text', '')} ({item.get('test_name', '')})",
        ))
    for item in data.get("errors", []):
        findings.append(make_finding(
            source="bandit", rule="parse-error", severity="low", tier="deterministic",
            file=_rel(path, item.get("filename", "")), line=None,
            message=f"bandit no pudo analizar el archivo: {item.get('reason', '')}",
        ))
    return findings, "ok"


def _parse_npm_audit(stdout: str, manifest_rel: str) -> tuple[list[Finding], str]:
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return [], "error"
    if not isinstance(data, dict):
        return [], "error"
    error = data.get("error")
    if isinstance(error, dict):
        return [], "skipped" if error.get("code") == "ENOLOCK" else "error"
    findings = []
    for name, vuln in (data.get("vulnerabilities") or {}).items():
        titles = [v["title"] for v in vuln.get("via", []) if isinstance(v, dict) and v.get("title")]
        findings.append(make_finding(
            source="npm_audit", rule=f"npm:{name}",
            severity=NPM_SEVERITY.get(str(vuln.get("severity", "")).lower(), "low"),
            tier="deterministic", file=manifest_rel, line=None,
            message=f"{name}: {titles[0] if titles else 'vulnerabilidad transitiva'}",
        ))
    return findings, "ok"


def _run_npm_audit(path: str, manifest_rel: str) -> tuple[list[Finding], str]:
    cwd = os.path.normpath(os.path.join(path, os.path.dirname(manifest_rel)))
    # --registry fijo: un .npmrc del proyecto auditado no debe redirigir la consulta.
    run = run_tool(
        ["npm", "audit", "--json", "--registry=https://registry.npmjs.org/"],
        cwd=cwd, timeout=90,
    )
    if run.status != "ok":
        logger.warning("npm audit no completo en %s: %s %s", cwd, run.status, run.detail)
        return [], run.status
    return _parse_npm_audit(run.stdout, manifest_rel)


def _worst(statuses: list[str]) -> str:
    return max(statuses, key=_STATUS_RANK.__getitem__) if statuses else "ok"


def run_static_checks(path: str, discovery: DiscoveryResult) -> StaticResult:
    findings: list[Finding] = []
    tools: dict[str, str] = {}

    secret_scan = scan_secrets(path, discovery["files"])
    findings += secret_scan["findings"]
    tools["secrets"] = "ok"

    if discovery["is_python"]:
        ruff_findings, tools["ruff"] = _run_ruff(path)
        bandit_findings, tools["bandit"] = _run_bandit(path)
        findings += ruff_findings + bandit_findings

    if discovery["is_node"]:
        manifests = [m for m in discovery["manifests"] if os.path.basename(m) == "package.json"]
        statuses = []
        for manifest in manifests[:MAX_NPM_MANIFESTS]:
            npm_findings, status = _run_npm_audit(path, manifest)
            findings += npm_findings
            statuses.append(status)
        tools["npm_audit"] = _worst(statuses)

    attach_evidence(path, findings)
    return StaticResult(
        findings=assign_ids(findings),
        tools=tools,
        ok=all(status in ("ok", "skipped") for status in tools.values()),
        files_scanned=secret_scan["files_scanned"],
    )


def audit_project(name: str, path: str) -> dict | None:
    """Uso standalone (CLI): compara hash, corre el analisis estatico y
    persiste el hash solo si todas las herramientas aplicables corrieron."""
    changed, current_hash = has_changed(name, path)
    if not changed:
        return None
    discovery = classify_target(path)
    static = run_static_checks(path, discovery)
    if static["ok"]:
        commit_hash(name, current_hash)
    return {
        "classification": discovery["classification"],
        "tools": static["tools"],
        "findings": static["findings"],
    }


def main() -> None:
    reportable_projects = []
    for entry in os.scandir(PROJECTS_HOME):
        if not entry.is_dir() or entry.name.startswith(".") or entry.name in IGNORE_DIRS:
            continue
        audit_result = audit_project(entry.name, entry.path)
        if audit_result:
            reportable_projects.append({
                "name": entry.name,
                "path": entry.path,
                "results": audit_result,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

    if reportable_projects:
        print(json.dumps(reportable_projects, indent=2))


if __name__ == "__main__":
    main()
