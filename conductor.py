import json
import logging
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent
SWARM_HOME = Path(os.environ.get("SWARM_HOME") or Path.home() / "swarm_auditor")
LOG_DIR = Path(os.environ.get("LOG_DIR") or Path.home() / "auditoria_diaria" / "logs")


def run_agent(script_name: str) -> dict | list | None:
    script_path = BASE_DIR / "agents" / script_name
    try:
        result = subprocess.run(
            [sys.executable, str(script_path)],
            capture_output=True, text=True, timeout=300,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        logger.error("No se pudo ejecutar %s: %s", script_name, e)
        return {"error": str(e)}

    if result.returncode != 0:
        logger.error(
            "%s termino con codigo %s: %s",
            script_name, result.returncode, result.stderr.strip(),
        )

    output = result.stdout.strip()
    if not output:
        return None
    try:
        return json.loads(output)
    except json.JSONDecodeError as e:
        logger.error("Salida de %s no es JSON valido (%s). stdout: %.200s", script_name, e, output)
        return {"error": f"invalid_json: {e}"}


def generate_report(github_data, audit_data) -> Path:
    today = datetime.now().strftime("%Y-%m-%d")
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    report_path = LOG_DIR / f"{today}_report.md"

    score = 100
    with open(report_path, "w") as f:
        f.write(f"# Reporte Maestro de Auditoria - {today}\n\n")

        f.write("## Inteligencia Global (GitHub Watcher)\n")
        if github_data and "findings" in github_data:
            found_security = False
            for item in github_data["findings"]:
                if item.get("type") == "security_advisory":
                    severity = (item.get("severity") or "?").upper()
                    f.write(f"- **{severity}**: {item.get('summary')} ({item.get('ecosystem')})\n")
                    found_security = True
            if not found_security:
                f.write("No se detectaron nuevas amenazas globales relevantes hoy.\n")
        else:
            f.write("Sin datos de inteligencia global (ver logs para detalles).\n")
        f.write("\n")

        f.write("## Estado de Proyectos Locales\n")
        f.write("| Proyecto | Riesgos | Puntos |\n")
        f.write("| :--- | :--- | :--- |\n")

        for project in audit_data:
            p_score = 10
            risks = []
            res = project.get("results", {})
            if "bandit" in res and "Issue" in res["bandit"]:
                risks.append("Seguridad")
                p_score -= 5
            if "ruff" in res and res["ruff"]:
                risks.append("Sintaxis")
                p_score -= 3
            npm_audit = res.get("npm_audit")
            if isinstance(npm_audit, dict):
                high = npm_audit.get("metadata", {}).get("vulnerabilities", {}).get("high", 0)
                if high > 0:
                    risks.append("NPM (High)")
                    p_score -= 4

            score -= (10 - p_score)
            risk_label = ", ".join(risks) if risks else "OK"
            f.write(f"| {project['name']} | {risk_label} | {max(0, p_score)}/10 |\n")

        final_score = max(0, score)
        f.write(f"\n\n### HEALTH SCORE GLOBAL: {final_score}/100\n")
        f.write("\n*Reporte generado por Sentience Swarm Auditor.*")

    return report_path


def main() -> None:
    logger.info("Iniciando Swarm Sentience-Ultra...")

    local_findings = run_agent("audit_agent.py")

    if not local_findings:
        logger.info("No se detectaron cambios en los proyectos. Sistema en reposo.")
        return
    if isinstance(local_findings, dict) and "error" in local_findings:
        error_msg = local_findings["error"]
        logger.error("La auditoria local fallo, se aborta esta corrida: %s", error_msg)
        return

    github_findings = run_agent("github_watcher.py")

    report_file = generate_report(github_findings, local_findings)

    logger.info("Se detectaron cambios en %d proyectos", len(local_findings))
    logger.info("Reporte generado en: %s", report_file)

    for project in local_findings:
        logger.info("%s -> ver reporte MD para detalles", project["name"])

    today_ts = datetime.now().strftime("%Y-%m-%d_%H%M")
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    with open(LOG_DIR / f"{today_ts}_audit.json", "w") as f:
        json.dump({"local": local_findings, "github": github_findings}, f, indent=2)


if __name__ == "__main__":
    main()
