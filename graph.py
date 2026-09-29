"""Orquestacion del swarm con LangGraph.

Reemplaza el pipeline secuencial de conductor.py v1 (subprocess -> parseo
de stdout -> siguiente subprocess) por un grafo async: discovery hace
fan-out con Send() y cada proyecto se audita CONCURRENTEMENTE (no uno
tras otro), con un patron scan/debate de dos proveedores LLM distintos
por proyecto (nunca el mismo modelo se revisa a si mismo).
"""

import asyncio
import json
import logging
import operator
import os
import shutil
import sys
from pathlib import Path
from typing import Annotated, TypedDict

from langgraph.graph import END, START, StateGraph
from langgraph.types import Send

sys.path.insert(0, str(Path(__file__).resolve().parent / "agents"))

from active_scan_guard import ScanAuthorization, TargetEnvironment  # noqa: E402
from audit_agent import IGNORE_DIRS, PROJECTS_HOME, run_static_checks  # noqa: E402
from change_detector import commit_hash, has_changed  # noqa: E402
from discovery import classify_target, coverage_from_discovery, summarize_discovery  # noqa: E402
from dast_nuclei import NucleiNotAvailableError, NucleiScanError, run_nuclei_scan  # noqa: E402
from github_source import CloneError, clone_repo_shallow  # noqa: E402
from github_watcher import watch_intelligence  # noqa: E402
from llm_router import CredentialRouter, NoProviderAvailableError  # noqa: E402
from panel import run_panel  # noqa: E402
from report import render_project_section  # noqa: E402
from scoring import score_active_scan, score_project  # noqa: E402

NUCLEI_TEMPLATES_DIR = os.environ.get("NUCLEI_TEMPLATES_DIR")

logger = logging.getLogger(__name__)


class ProjectTask(TypedDict):
    name: str
    path: str
    static_hash: str


class SwarmState(TypedDict):
    project_results: Annotated[list[dict], operator.add]
    github_intel: dict | None
    report_path: str | None


def discover_projects(state: SwarmState):
    tasks = []
    try:
        entries = list(os.scandir(PROJECTS_HOME))
    except OSError as e:
        logger.error("No se pudo escanear PROJECTS_HOME=%s: %s", PROJECTS_HOME, e)
        return []

    for entry in entries:
        if not entry.is_dir() or entry.name.startswith(".") or entry.name in IGNORE_DIRS:
            continue
        changed, current_hash = has_changed(entry.name, entry.path)
        if changed:
            tasks.append(ProjectTask(name=entry.name, path=entry.path, static_hash=current_hash))

    if not tasks:
        logger.info("Sin cambios en ningun proyecto. Sistema en reposo.")
        return []

    return [Send("audit_project", task) for task in tasks]


async def run_project_audit(name: str, path: str, router: CredentialRouter) -> tuple[dict, bool]:
    """Nucleo reusable: discovery -> analisis estatico -> panel de verificacion
    para UN proyecto. Devuelve (result, static_ok). Usado tanto por el grafo
    batch (audit_project_node) como por el MCP server y audit_github_repo.

    Sin hallazgos de severidad media o mayor NO se llama a ningun LLM."""
    discovery = await asyncio.to_thread(classify_target, path)
    static = await asyncio.to_thread(run_static_checks, path, discovery)
    findings = static["findings"]
    panel = await asyncio.to_thread(run_panel, router, findings, name)

    result = {
        "name": name,
        "path": path,
        "discovery": summarize_discovery(discovery),
        "coverage": {
            **coverage_from_discovery(discovery, static["files_scanned"]),
            "limits": static.get("limits", []),
        },
        "tools": static["tools"],
        "findings": findings,
        "panel": {key: value for key, value in panel.items() if key != "consolidated"},
        "consolidated": panel["consolidated"],
    }
    result["score"] = score_project(result)
    # Con el panel degradado (sin cuota, < 2 revisores) los hallazgos quedan sin
    # verificar: no se marca el proyecto como "visto" para reintentarlo luego.
    panel_ok = panel["reviewed"] == 0 or panel["min_size"] >= 2
    return result, static["ok"] and panel_ok


async def audit_project_node(task: ProjectTask, router: CredentialRouter) -> dict:
    result, static_ok = await run_project_audit(task["name"], task["path"], router)
    if static_ok:
        await asyncio.to_thread(commit_hash, task["name"], task["static_hash"])
    return {"project_results": [result]}


async def audit_single_project(path: str, router: CredentialRouter | None = None) -> dict:
    """Audita un proyecto puntual bajo demanda (MCP), ignorando el
    chequeo de 'sin cambios': siempre re-audita cuando se invoca."""
    router = router or CredentialRouter()
    name = Path(path).name
    result, _static_ok = await run_project_audit(name, path, router)
    return result


async def audit_github_repo(
    owner_repo: str, ref: str = "HEAD", router: CredentialRouter | None = None
) -> dict:
    """Clona (shallow, solo lectura) un repo de GitHub y lo audita con el
    mismo pipeline que un proyecto local. GITHUB_TOKEN determina el
    acceso: sin token solo repos publicos, con un token que tenga
    permiso tambien repos privados. El clon se borra siempre al terminar,
    exista o no error, para no dejar codigo de terceros persistiendo en
    disco."""
    router = router or CredentialRouter()
    try:
        local_path = await asyncio.to_thread(clone_repo_shallow, owner_repo, ref)
    except CloneError as e:
        logger.error("No se pudo clonar %s@%s: %s", owner_repo, ref, e)
        return {
            "name": owner_repo,
            "source": {"type": "github", "owner_repo": owner_repo, "ref": ref},
            "error": str(e),
        }

    try:
        safe_name = owner_repo.replace("/", "__")
        result, _static_ok = await run_project_audit(safe_name, local_path, router)
    finally:
        await asyncio.to_thread(shutil.rmtree, local_path, ignore_errors=True)

    result["source"] = {"type": "github", "owner_repo": owner_repo, "ref": ref}
    return result


def build_dast_scan_messages(target: str, findings: list[dict]) -> list[dict]:
    findings_summary = json.dumps(findings, indent=2, default=str)[:4000]
    return [
        {
            "role": "system",
            "content": (
                "Eres un agente de auditoria de seguridad que interpreta resultados "
                "de un escaneo DAST (Nuclei) contra una aplicacion PROPIA del "
                "equipo, ejecutado con autorizacion. Los hallazgos ya fueron "
                "confirmados por una herramienta automatizada (no los inventes ni "
                "los descartes sin evidencia). Responde en espanol, breve:\n"
                "1) Prioriza los hallazgos por severidad real de negocio.\n"
                "2) Senala cuales requieren accion inmediata.\n"
                "3) Senala si algun hallazgo parece un falso positivo dado el "
                "contexto (ej. un banner de version en un entorno de prueba)."
            ),
        },
        {
            "role": "user",
            "content": f"Target: {target}\nHallazgos DAST (JSON):\n{findings_summary}",
        },
    ]


def build_dast_debate_messages(scan_output: str) -> list[dict]:
    return [
        {
            "role": "system",
            "content": (
                "Eres un segundo auditor de seguridad, independiente del primero. "
                "Valida o refuta el analisis anterior de un escaneo DAST. Se "
                "especificamente esceptico: di 'confirmo' o 'riesgo real' para "
                "hallazgos que consideres genuinos, y 'falso positivo' para los "
                "que no. Responde en espanol, breve."
            ),
        },
        {"role": "user", "content": f"Analisis a validar:\n{scan_output}"},
    ]


DEFAULT_DAST_SEVERITY = ["medium", "high", "critical"]


async def run_active_scan(
    target: str,
    environment: str,
    confirm_own_target: bool,
    confirm_production_risk: bool = False,
    router: CredentialRouter | None = None,
    severity: list[str] | None = None,
    tags: list[str] | None = None,
) -> dict:
    """Motor DAST activo (Fase 4): ejecuta Nuclei contra un target
    autorizado y pasa los hallazgos por el mismo patron scan/debate que
    el resto del sistema. Lanza TargetNotAuthorizedError si falta
    confirmacion - esto NUNCA se salta ni tiene un modo "forzar".

    Por defecto filtra a severity medium/high/critical: correr los
    +14.000 templates sin filtrar es lento y genera carga innecesaria
    contra el target sin aportar señal (la mayoria son "info", como
    deteccion de tecnologia). Pasa severity=[] explicitamente para no
    filtrar."""
    router = router or CredentialRouter()

    auth = ScanAuthorization(
        target=target,
        environment=TargetEnvironment(environment),
        confirm_own_target=confirm_own_target,
        confirm_production_risk=confirm_production_risk,
    )
    auth.validate()
    limits = auth.limits
    effective_severity = DEFAULT_DAST_SEVERITY if severity is None else severity

    try:
        findings = await asyncio.to_thread(
            run_nuclei_scan,
            target,
            limits.rate_limit,
            limits.concurrency,
            limits.max_duration_seconds,
            NUCLEI_TEMPLATES_DIR,
            tags,
            effective_severity or None,
        )
    except (NucleiNotAvailableError, NucleiScanError) as e:
        logger.error("Escaneo activo fallo para %s: %s", target, e)
        return {"target": target, "environment": environment, "error": str(e)}

    if not findings:
        return {
            "target": target,
            "environment": environment,
            "findings": [],
            "ensemble": None,
            "score": score_active_scan([], None),
        }

    scan_messages = build_dast_scan_messages(target, findings)

    def debate_builder(_scan_provider: str, scan_output: str) -> list[dict]:
        return build_dast_debate_messages(scan_output)

    try:
        ensemble = await asyncio.to_thread(router.chat_ensemble, scan_messages, debate_builder)
    except NoProviderAvailableError as e:
        logger.error("Sin proveedor LLM disponible para escaneo activo de %s: %s", target, e)
        ensemble = {"error": str(e)}

    return {
        "target": target,
        "environment": environment,
        "findings": findings,
        "ensemble": ensemble,
        "score": score_active_scan(findings, ensemble),
    }


async def watch_github_node(state: SwarmState) -> dict:
    intel = await asyncio.to_thread(watch_intelligence)
    return {"github_intel": intel}


def generate_report_node(state: SwarmState, log_dir: Path) -> dict:
    from datetime import datetime

    projects = state.get("project_results", [])
    github_intel = state.get("github_intel")

    today = datetime.now().strftime("%Y-%m-%d")
    log_dir.mkdir(parents=True, exist_ok=True)
    report_path = log_dir / f"{today}_report.md"

    with open(report_path, "w") as f:
        f.write(f"# Reporte Maestro de Auditoria - {today}\n\n")

        f.write("## Inteligencia Global (GitHub Watcher)\n")
        found_security = False
        if github_intel and "findings" in github_intel:
            for item in github_intel["findings"]:
                if item.get("type") == "security_advisory":
                    severity = (item.get("severity") or "?").upper()
                    f.write(f"- **{severity}**: {item.get('summary')} ({item.get('ecosystem')})\n")
                    found_security = True
        if not found_security:
            f.write("Sin amenazas globales relevantes detectadas.\n")
        f.write("\n")

        f.write("## Estado de Proyectos (panel multi-modelo)\n")
        if not projects:
            f.write("Sin cambios detectados en esta corrida.\n")
        for project in projects:
            f.write(render_project_section(project))

        f.write("\n\n*Reporte generado por audit-mcp")
        f.write(" (LangGraph + panel multi-modelo).*")

    logger.info("Reporte generado en %s", report_path)
    return {"report_path": str(report_path)}


def build_graph(router: CredentialRouter | None = None, log_dir: Path | None = None):
    router = router or CredentialRouter()
    if log_dir is None:
        log_dir = Path(os.environ.get("LOG_DIR") or Path.home() / "auditoria_diaria" / "logs")

    async def audit_project_wrapper(task: ProjectTask) -> dict:
        return await audit_project_node(task, router)

    async def generate_report_wrapper(state: SwarmState) -> dict:
        return generate_report_node(state, log_dir)

    builder = StateGraph(SwarmState)
    builder.add_node("audit_project", audit_project_wrapper)
    builder.add_node("watch_github", watch_github_node)
    builder.add_node("generate_report", generate_report_wrapper)

    builder.add_conditional_edges(START, discover_projects, ["audit_project"])
    builder.add_edge(START, "watch_github")
    builder.add_edge("audit_project", "generate_report")
    builder.add_edge("watch_github", "generate_report")
    builder.add_edge("generate_report", END)

    return builder.compile()
