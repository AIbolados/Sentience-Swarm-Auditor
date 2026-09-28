"""Servidor MCP local (stdio) para audit-mcp.

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

from active_scan_guard import TargetNotAuthorizedError  # noqa: E402
from github_source import InvalidRepoSpecError  # noqa: E402
from graph import audit_single_project, build_graph, run_active_scan  # noqa: E402
from graph import audit_github_repo as _audit_github_repo_core  # noqa: E402
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


async def audit_github_repo(owner_repo: str, ref: str = "HEAD") -> dict:
    """Clona (shallow, solo lectura) un repo de GitHub y lo audita con el
    mismo pipeline (escaneo estatico + ensemble scan/debate). Nunca
    ejecuta codigo del repo, solo lo analiza; el clon se borra siempre al
    terminar.

    owner_repo: formato 'owner/repo' (ej. 'AIbolados/audit-mcp').
    ref: branch o tag especifico, o 'HEAD' para la rama por defecto.

    El acceso real lo determina GITHUB_TOKEN: sin token, solo repos
    publicos; con un token que tenga permiso sobre el repo (propio, de tu
    organizacion, o de un tercero que te dio acceso), tambien privados."""
    try:
        return await _audit_github_repo_core(owner_repo, ref, _router)
    except InvalidRepoSpecError as e:
        return {"error": str(e)}


async def active_security_scan(
    target: str,
    environment: str,
    confirm_own_target: bool = False,
    confirm_production_risk: bool = False,
    severity: list[str] | None = None,
) -> dict:
    """Motor DAST ACTIVO (Fase 4): ejecuta trafico real (Nuclei, +14.000
    templates curados por la comunidad, nunca payloads improvisados por
    el LLM) contra un target vivo, y pasa los hallazgos por el mismo
    ensemble scan/debate. A diferencia de audit_project/audit_github_repo,
    esto SI puede afectar al sistema objetivo (carga, alertas).

    SOLO usar contra proyectos propios del equipo, nunca contra sistemas
    de terceros sin su autorizacion explicita y por escrito.

    target: URL http(s) del sistema a escanear (ej. http://localhost:3000
        o https://staging.tuapp.com).
    environment: 'local_staging' o 'production'. Determina los limites de
        agresividad (produccion es mucho mas conservador: menos requests
        por segundo, para no degradar el servicio).
    confirm_own_target: DEBE ser True explicitamente. Sin esto, se
        rechaza sin ejecutar nada.
    confirm_production_risk: requerido ADEMAS cuando environment es
        'production' - confirma que corres esto en una ventana aceptada
        por tu equipo, no contra trafico de usuarios reales sin aviso.
    severity: lista de severidades a incluir (ej. ['critical']). Por
        defecto ['medium','high','critical'] - pasa [] para no filtrar
        (mucho mas lento, corre los +14.000 templates).
    """
    try:
        return await run_active_scan(
            target, environment, confirm_own_target, confirm_production_risk,
            _router, severity=severity,
        )
    except (TargetNotAuthorizedError, ValueError) as e:
        return {"error": str(e)}


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


mcp = MCPServer("audit-mcp")
mcp.add_tool(audit_project)
mcp.add_tool(audit_github_repo)
mcp.add_tool(active_security_scan)
mcp.add_tool(audit_all_projects)
mcp.add_tool(get_last_report)


if __name__ == "__main__":
    mcp.run()
