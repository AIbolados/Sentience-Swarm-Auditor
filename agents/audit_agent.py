import os
import json
import subprocess
from datetime import datetime
from pathlib import Path
from change_detector import has_changed

HOME_DIR = "/home/jibol2"
IGNORE_DIRS = {'.git', '.npm', '.cache', '.local', '.nvm', 'node_modules', '.gemini', '.cursor', '.vscode', 'venv', '.aider'}
VENV_BIN = "/home/jibol2/swarm_auditor/venv/bin"

def run_tool(tool_name, project_path):
    cmd = [os.path.join(VENV_BIN, tool_name), project_path]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return result.stdout.strip()
    except Exception as e:
        return f"Error: {str(e)}"

def debug_suggest(error_log):
    # Lógica simplificada de agente debug: extrae la línea del error
    if not error_log or "Error" in error_log: return None
    lines = error_log.split('\n')
    # Retornamos los primeros errores encontrados para análisis
    return lines[:3]

def audit_project(name, path):
    if not has_changed(name, path):
        return None 
    
    checks = {}
    files = os.listdir(path)
    is_python = any(f.endswith(".py") for f in files) or "requirements.txt" in files
    is_node = "package.json" in files
    
    if is_python:
        checks["ruff"] = run_tool("ruff", path)
        checks["bandit"] = run_tool("bandit", path)
        if checks["ruff"]:
            checks["debug_fix"] = debug_suggest(checks["ruff"])
            
    if is_node:
        try:
            # Ejecutamos npm audit de forma segura
            res = subprocess.run(["npm", "audit", "--json"], cwd=path, capture_output=True, text=True, timeout=30)
            checks["npm_audit"] = json.loads(res.stdout) if res.stdout else "No audit data"
        except:
            checks["npm_audit"] = "Error running npm audit"
        
    return checks

def main():
    reportable_projects = []
    for entry in os.scandir(HOME_DIR):
        if entry.is_dir() and not entry.name.startswith('.') and entry.name not in IGNORE_DIRS:
            audit_result = audit_project(entry.name, entry.path)
            if audit_result:
                reportable_projects.append({
                    "name": entry.name,
                    "path": entry.path,
                    "results": audit_result,
                    "timestamp": datetime.now().isoformat()
                })
            
    # Solo imprimimos si hay algo que reportar
    if reportable_projects:
        print(json.dumps(reportable_projects, indent=2))

if __name__ == "__main__":
    main()
