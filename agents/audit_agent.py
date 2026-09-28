import json
import logging
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
from change_detector import commit_hash, has_changed  # noqa: E402

logger = logging.getLogger(__name__)

PROJECTS_HOME = Path(os.environ.get("PROJECTS_HOME") or Path.home())
SWARM_HOME = Path(os.environ.get("SWARM_HOME") or Path.home() / "swarm_auditor")
VENV_BIN = SWARM_HOME / "venv" / "bin"

IGNORE_DIRS = {
    ".git", ".npm", ".cache", ".local", ".nvm", "node_modules",
    ".gemini", ".cursor", ".vscode", "venv", ".venv", ".aider",
}


def run_tool(tool_name: str, project_path: str) -> str | None:
    """None = la herramienta no pudo ejecutarse (no instalada, timeout).
    '' = corrio y no encontro nada. Texto no vacio = hallazgo real.
    Nunca confundir "no pude auditar" con "hallazgo de seguridad"."""
    tool_path = VENV_BIN / tool_name
    cmd = [str(tool_path) if tool_path.exists() else tool_name, project_path]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return result.stdout.strip()
    except (OSError, subprocess.TimeoutExpired) as e:
        logger.warning("Fallo ejecutando %s sobre %s: %s", tool_name, project_path, e)
        return None


def debug_suggest(tool_output: str) -> list[str] | None:
    if not tool_output:
        return None
    return tool_output.split("\n")[:3]


def run_static_checks(path: str) -> tuple[dict, bool]:
    """Corre ruff/bandit/npm audit sobre un proyecto. Devuelve (checks, ok):
    ok indica si los chequeos configurados corrieron sin error de ejecucion
    (no indica ausencia de hallazgos). El llamador decide si persiste el
    hash de 'visto' en base a ok."""
    checks: dict = {}
    try:
        files = os.listdir(path)
    except OSError as e:
        logger.error("No se pudo listar %s: %s", path, e)
        return {"error": str(e)}, False

    is_python = any(f.endswith(".py") for f in files) or "requirements.txt" in files
    is_node = "package.json" in files

    ok = True
    if is_python:
        checks["ruff"] = run_tool("ruff", path)
        checks["bandit"] = run_tool("bandit", path)
        if checks["ruff"]:
            checks["debug_fix"] = debug_suggest(checks["ruff"])

    if is_node:
        try:
            res = subprocess.run(
                ["npm", "audit", "--json"], cwd=path,
                capture_output=True, text=True, timeout=30,
            )
            checks["npm_audit"] = json.loads(res.stdout) if res.stdout else "No audit data"
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as e:
            logger.warning("npm audit fallo en %s: %s", path, e)
            checks["npm_audit"] = f"Error running npm audit: {e}"
            ok = False

    return checks, ok


def audit_project(name: str, path: str) -> dict | None:
    """Uso standalone (CLI): compara hash, corre los checks estaticos y
    persiste el hash solo si corrieron sin error."""
    changed, current_hash = has_changed(name, path)
    if not changed:
        return None

    checks, ok = run_static_checks(path)
    if ok:
        commit_hash(name, current_hash)
    return checks


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
