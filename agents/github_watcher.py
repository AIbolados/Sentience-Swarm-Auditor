import requests
import json
import os

def watch_repos():
    repos = [
        "SaadSaddique/Multi-Agent-Code-Review-system",
        "smirk-dev/CodeReview-AI-Agent"
    ]
    findings = []
    
    for repo in repos:
        try:
            # Simulamos o consultamos la API de GitHub para ver actividad reciente
            api_url = f"https://api.github.com/github-events" # En un caso real usaríamos el repo específico
            # Para este MVP, buscaremos el README o tags de estos repos para "aprender"
            info_url = f"https://api.github.com/repos/{repo}"
            response = requests.get(info_url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                findings.append({
                    "repo": repo,
                    "stars": data.get("stargazers_count"),
                    "last_update": data.get("updated_at"),
                    "description": data.get("description")
                })
        except Exception as e:
            findings.append({"repo": repo, "error": str(e)})
            
    return findings

if __name__ == "__main__":
    results = watch_repos()
    print(json.dumps(results, indent=2))
