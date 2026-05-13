import subprocess
import json
import os
from datetime import datetime

# Rutas
BASE_DIR = "/home/jibol2/swarm_auditor"
VENV_PYTHON = os.path.join(BASE_DIR, "venv/bin/python3")
LOG_DIR = "/home/jibol2/auditoria_diaria/logs"

def run_agent(script_name):
    script_path = os.path.join(BASE_DIR, "agents", script_name)
    try:
        result = subprocess.run([VENV_PYTHON, script_path], capture_output=True, text=True, timeout=300)
        output = result.stdout.strip()
        if output:
            # Intentar encontrar el inicio del JSON
            json_start = output.find("[") if output.find("[") < output.find("{") and output.find("[") != -1 else output.find("{")
            if json_start != -1:
                return json.loads(output[json_start:])
        return None
    except Exception as e:
        return {"error": str(e)}

def main():
    # 1. Auditoría Local (Silenciosa si no hay cambios)
    local_findings = run_agent("audit_agent.py")
    
    if not local_findings:
        # Silencio total: No hay cambios desde la última vez
        return

    # 2. Si hay hallazgos, buscamos el "Estado del Arte" en GitHub
    github_findings = run_agent("github_watcher.py")
    
    # 3. Presentación de resultados (Modo Herramienta Compartible)
    print(f"\n🚀 [SENTIENCE-SWARM] ALERTA: Cambios detectados en {len(local_findings)} proyectos.\n")
    
    for project in local_findings:
        name = project['name']
        res = project['results']
        print(f"📂 PROYECTO: {name}")
        
        if "debug_fix" in res and res["debug_fix"]:
            print(f"   🔧 AGENTE DEBUG: Se encontraron posibles problemas:")
            for line in res["debug_fix"]:
                print(f"      - {line}")
        
        if "bandit" in res and "Issue" in res["bandit"]:
            print(f"   🛡️ SEGURIDAD: Se detectaron vulnerabilidades potenciales.")
            
        print("-" * 50)

    # 4. Guardar log histórico
    os.makedirs(LOG_DIR, exist_ok=True)
    today = datetime.now().strftime("%Y-%m-%d_%H%M")
    with open(os.path.join(LOG_DIR, f"{today}_audit.json"), 'w') as f:
        json.dump({"local": local_findings, "github": github_findings}, f, indent=2)

if __name__ == "__main__":
    main()
