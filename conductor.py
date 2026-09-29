import asyncio
import logging

from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


async def run() -> None:
    from graph import build_graph

    logger.info("Iniciando audit-mcp (LangGraph + panel multi-modelo)...")
    graph = build_graph()
    initial_state = {"project_results": [], "github_intel": None, "report_path": None}
    final_state = await graph.ainvoke(initial_state)

    projects = final_state.get("project_results", [])
    if not projects:
        logger.info("No se detectaron cambios en los proyectos. Sistema en reposo.")
        return

    logger.info("Se auditaron %d proyecto(s)", len(projects))
    for project in projects:
        score = project.get("score", {})
        logger.info(
            "%s -> %s (health=%s, slop_risk=%s)",
            project["name"],
            score.get("production_readiness"),
            score.get("engineering_health"),
            score.get("vibe_slop_risk"),
        )
    logger.info("Reporte generado en: %s", final_state.get("report_path"))


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":
    main()
