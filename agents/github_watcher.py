import requests
import json
from datetime import datetime

def watch_intelligence():
    # Fuentes de inteligencia: GitHub Advisories para Python/Node
    intelligence = {
        "sources": [
            "https://api.github.com/repos/SaadSaddique/Multi-Agent-Code-Review-system",
            "https://api.github.com/repos/advisories?per_page=5"
        ],
        "findings": []
    }
    
    try:
        # 1. Monitorear repo de referencia para nuevas reglas
        repo_info = requests.get(intelligence["sources"][0], timeout=10).json()
        intelligence["findings"].append({
            "type": "reference_repo",
            "name": "Sentience-Code",
            "last_update": repo_info.get("updated_at"),
            "new_stars": repo_info.get("stargazers_count")
        })
        
        # 2. Monitorear Vulnerabilidades Globales Recientes
        advisories = requests.get(intelligence["sources"][1], timeout=10).json()
        if isinstance(advisories, list):
            for adv in advisories:
                intelligence["findings"].append({
                    "type": "security_advisory",
                    "severity": adv.get("severity"),
                    "summary": adv.get("summary"),
                    "ecosystem": adv.get("cvss", {}).get("score_metadata", {}).get("ecosystem", "unknown")
                })
    except Exception as e:
        intelligence["findings"].append({"error": str(e)})
            
    return intelligence

if __name__ == "__main__":
    print(json.dumps(watch_intelligence(), indent=2))
