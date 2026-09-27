"""Servidor MCP local (stdio) para Sentience Swarm Auditor.

Expone el mismo grafo LangGraph (escaneo estatico + ensemble scan/debate
multi-modelo) como tools invocables bajo demanda desde Claude Code, sin
reemplazar el modo cron/batch existente (conductor.py sigue funcionando
igual para corridas programadas).

Las funciones se definen sueltas (no como metodos decorados) para poder
testearlas por import directo, sin pasar por el protocolo MCP; el
registro como tools es un paso aparte al final del archivo.
"""

import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from mcp.server.mcpserver import MCPServer

load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

sys.path.insert(0, str(Path(__file__).resolve().parent / "agents"))

from graph import audit_single_project, build_graph  # noqa: E402
from llm_router import CredentialRouter  # noqa: E402

_router = CredentialRouter()


async def audit_project(path: str) -> dict:
    """Audita un proyecto puntual: escaneo estatico (ruff/bandit/npm audit)
    mas un ensemble de 2 modelos LLM independientes (scan_agent identifica
    hallazgos, debate_agent de OTRO proveedor los confirma o refuta). No
    ejecuta nada contra un sistema en produccion: solo lee codigo fuente.

    path debe ser una ruta absoluta a un directorio de codigo al que
    tengas acceso de lectura autorizado (propio o de un tercero que te
    dio el codigo para revisar, como cualquier code review)."""
    resolved = Path(path).expanduser().resolve()
    if not resolved.is_dir():
        return {"error": f"No existe el directorio: {resolved}"}
    return await audit_single_project(str(resolved), _router)


async def audit_all_projects() -> dict:
    """Corre el batch completo: escanea PROJECTS_HOME, audita todos los
    proyectos con cambios desde la ultima corrida (fan-out concurrente),
    y genera el reporte .md. Equivalente a la corrida de cron."""
    graph = build_graph(router=_router)
    initial_state = {"project_results": [], "github_intel": None, "report_path": None}
    return await graph.ainvoke(initial_state)


def get_last_report() -> str:
    """Devuelve el contenido del ultimo reporte .md generado (batch o
    corridas anteriores), o un aviso si todavia no hay ninguno."""
    log_dir = Path(os.environ.get("LOG_DIR") or Path.home() / "auditoria_diaria" / "logs")
    if not log_dir.exists():
        return "Sin reportes generados todavia."
    reports = sorted(log_dir.glob("*_report.md"))
    if not reports:
        return "Sin reportes generados todavia."
    return reports[-1].read_text()


mcp = MCPServer("sentience-swarm-auditor")
mcp.add_tool(audit_project)
mcp.add_tool(audit_all_projects)
mcp.add_tool(get_last_report)


if __name__ == "__main__":
    mcp.run()
