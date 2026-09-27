import json
import logging
import os

import requests

logger = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"
REFERENCE_REPO = "SaadSaddique/Multi-Agent-Code-Review-system"
REQUEST_TIMEOUT = 10


def _headers() -> dict:
    headers = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def watch_intelligence() -> dict:
    intelligence = {
        "sources": [
            f"{GITHUB_API}/repos/{REFERENCE_REPO}",
            f"{GITHUB_API}/advisories?per_page=5",
        ],
        "findings": [],
    }
    headers = _headers()

    try:
        url = intelligence["sources"][0]
        repo_info = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT).json()
        intelligence["findings"].append({
            "type": "reference_repo",
            "name": "Sentience-Code",
            "last_update": repo_info.get("updated_at"),
            "new_stars": repo_info.get("stargazers_count"),
        })
    except (requests.RequestException, json.JSONDecodeError) as e:
        logger.warning("No se pudo consultar el repo de referencia: %s", e)
        intelligence["findings"].append({"error": f"reference_repo: {e}"})

    try:
        url = intelligence["sources"][1]
        response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        advisories = response.json()
        if isinstance(advisories, list):
            for adv in advisories:
                first_vuln = (adv.get("vulnerabilities") or [{}])[0]
                ecosystem = first_vuln.get("package", {}).get("ecosystem", "unknown")
                intelligence["findings"].append({
                    "type": "security_advisory",
                    "severity": adv.get("severity"),
                    "summary": adv.get("summary"),
                    "ecosystem": ecosystem,
                })
    except (requests.RequestException, json.JSONDecodeError) as e:
        logger.warning("No se pudieron consultar advisories: %s", e)
        intelligence["findings"].append({"error": f"advisories: {e}"})

    if not os.environ.get("GITHUB_TOKEN"):
        logger.info("GITHUB_TOKEN no configurado: llamadas anonimas, limite 60 req/hora")

    return intelligence


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print(json.dumps(watch_intelligence(), indent=2))
