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
            json_start = output.find("[") if output.find("[") < output.find("{") and output.find("[") != -1 else output.find("{")
            if json_start != -1:
                return json.loads(output[json_start:])
        return None
    except Exception as e:
        return {"error": str(e)}

def generate_report(github_data, audit_data):
    today = datetime.now().strftime("%Y-%m-%d")
    report_path = os.path.join(LOG_DIR, f"{today}_report.md")
    os.makedirs(LOG_DIR, exist_ok=True)
    
    score = 100
    with open(report_path, 'w') as f:
        f.write(f"# 🛡️ Reporte Maestro de Auditoría - {today}\n\n")
        
        # Inteligencia de Seguridad (GitHub Watcher)
        f.write("## 🌍 Inteligencia Global (GitHub Watcher)\n")
        if github_data and "findings" in github_data:
            found_security = False
            for item in github_data["findings"]:
                if item.get("type") == "security_advisory":
                    f.write(f"- ⚠️ **{item.get('severity').upper()}**: {item.get('summary')} ({item.get('ecosystem')})\n")
                    found_security = True
            if not found_security:
                f.write("✅ No se detectaron nuevas amenazas globales relevantes hoy.\n")
        f.write("\n")
        
        # Estado Local
        f.write("## 🏗️ Estado de Proyectos Locales\n")
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
            if "npm_audit" in res and isinstance(res["npm_audit"], dict) and res["npm_audit"].get("metadata", {}).get("vulnerabilities", {}).get("high", 0) > 0:
                risks.append("NPM (High)")
                p_score -= 4
            
            score -= (10 - p_score)
            f.write(f"| {project['name']} | {', '.join(risks) if risks else '✅ OK'} | {max(0, p_score)}/10 |\n")
        
        final_score = max(0, score)
        color = "🟢" if final_score > 80 else "🟡" if final_score > 50 else "🔴"
        f.write(f"\n\n### 📈 HEALTH SCORE GLOBAL: {color} {final_score}/100\n")
        f.write(f"\n*Reporte generado por el Swarm Sentience-Ultra.*")
        
    return report_path

def main():
    print("🚀 Iniciando Swarm Sentience-Ultra...")
    
    # 1. Auditoría Local (Silenciosa si no hay cambios)
    local_findings = run_agent("audit_agent.py")
    
    if not local_findings:
        print("✅ No se detectaron cambios en los proyectos. Sistema en reposo.")
        return

    # 2. Vigilancia de Inteligencia
    github_findings = run_agent("github_watcher.py")
    
    # 3. Generar Reporte MD
    report_file = generate_report(github_findings, local_findings)
    
    # 4. Presentación rápida en consola
    print(f"\n⚠️ SE DETECTARON CAMBIOS EN {len(local_findings)} PROYECTOS")
    print(f"📄 Reporte generado en: {report_file}\n")
    
    for project in local_findings:
        print(f"📂 {project['name']} -> Ver reporte MD para detalles.")

    # 5. Guardar JSON histórico
    today_ts = datetime.now().strftime("%Y-%m-%d_%H%M")
    with open(os.path.join(LOG_DIR, f"{today_ts}_audit.json"), 'w') as f:
        json.dump({"local": local_findings, "github": github_findings}, f, indent=2)

if __name__ == "__main__":
    main()
