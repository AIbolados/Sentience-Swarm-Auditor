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
import sys
from pathlib import Path
from typing import Annotated, TypedDict

from langgraph.graph import END, START, StateGraph
from langgraph.types import Send

sys.path.insert(0, str(Path(__file__).resolve().parent / "agents"))

from audit_agent import IGNORE_DIRS, PROJECTS_HOME, run_static_checks  # noqa: E402
from change_detector import commit_hash, has_changed  # noqa: E402
from github_watcher import watch_intelligence  # noqa: E402
from llm_router import CredentialRouter, NoProviderAvailableError  # noqa: E402
from scoring import score_project  # noqa: E402

logger = logging.getLogger(__name__)


class ProjectTask(TypedDict):
    name: str
    path: str
    static_hash: str


class SwarmState(TypedDict):
    project_results: Annotated[list[dict], operator.add]
    github_intel: dict | None
    report_path: str | None


def build_scan_messages(project_name: str, static_findings: dict) -> list[dict]:
    findings_summary = json.dumps(static_findings, indent=2, default=str)[:4000]
    return [
        {
            "role": "system",
            "content": (
                "Eres un agente de auditoria de codigo generado por IA (vibe-coding). "
                "Se te dan hallazgos de herramientas estaticas (ruff/bandit/npm audit). "
                "Responde en espanol, breve y accionable:\n"
                "1) Confirma o descarta cada hallazgo segun la evidencia dada.\n"
                "2) Senala si algun hallazgo sugiere secretos/credenciales expuestas.\n"
                "3) Senala sobreingenieria evidente si la hay.\n"
                "No inventes hallazgos que la evidencia no respalde."
            ),
        },
        {
            "role": "user",
            "content": f"Proyecto: {project_name}\nHallazgos estaticos (JSON):\n{findings_summary}",
        },
    ]


def build_debate_messages(scan_output: str) -> list[dict]:
    return [
        {
            "role": "system",
            "content": (
                "Eres un segundo auditor, independiente del primero. Tu trabajo es "
                "VALIDAR o REFUTAR el analisis anterior, no repetirlo. Se especificamente "
                "esceptico: di explicitamente si algun hallazgo es un falso positivo "
                "('falso positivo', 'no es un riesgo') o si confirmas que es real "
                "('confirmo', 'riesgo real'). Responde en espanol, breve."
            ),
        },
        {"role": "user", "content": f"Analisis a validar:\n{scan_output}"},
    ]


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
    """Nucleo reusable: escaneo estatico + ensemble scan/debate para UN
    proyecto. Devuelve (result, static_ok). Usado tanto por el grafo batch
    (audit_project_node) como por el MCP server para auditar bajo demanda."""
    static_findings, static_ok = await asyncio.to_thread(run_static_checks, path)

    scan_messages = build_scan_messages(name, static_findings)

    def debate_builder(_scan_provider: str, scan_output: str) -> list[dict]:
        return build_debate_messages(scan_output)

    try:
        ensemble = await asyncio.to_thread(router.chat_ensemble, scan_messages, debate_builder)
    except NoProviderAvailableError as e:
        logger.error("Sin proveedor LLM disponible para %s: %s", name, e)
        ensemble = {"error": str(e)}

    result = {
        "name": name,
        "path": path,
        "static": static_findings,
        "ensemble": ensemble,
    }
    result["score"] = score_project(result)
    return result, static_ok


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

        f.write("## Estado de Proyectos (ensemble multi-modelo)\n")
        if not projects:
            f.write("Sin cambios detectados en esta corrida.\n")
        for project in projects:
            score = project.get("score", {})
            ensemble = project.get("ensemble", {})
            readiness = score.get("production_readiness", "NOT_ASSESSED")
            f.write(f"\n### {project['name']}\n")
            f.write(f"- Production readiness: **{readiness}**\n")
            f.write(f"- Engineering health: {score.get('engineering_health', '?')}/100\n")
            f.write(f"- Vibe slop risk: {score.get('vibe_slop_risk', '?')}/100\n")
            f.write(f"- Evidence confidence: {score.get('evidence_confidence', '?')}/100\n")
            if ensemble.get("error"):
                f.write(f"- Ensemble: error ({ensemble['error']})\n")
            else:
                scan_provider = ensemble.get("scan_provider")
                debate_provider = ensemble.get("debate_provider")
                scan_output = ensemble.get("scan_output", "")[:500]
                debate_output = ensemble.get("debate_output", "")[:500]
                f.write(f"- Scan ({scan_provider}): {scan_output}\n")
                f.write(f"- Debate ({debate_provider}): {debate_output}\n")

        f.write("\n\n*Reporte generado por Sentience Swarm Auditor")
        f.write(" (LangGraph + ensemble multi-modelo).*")

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
