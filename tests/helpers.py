"""Utilidades de tests: hallazgos de ejemplo y clientes LLM falsos que
responden JSON valido leyendo los <finding> del prompt del panel."""

import json
import re
import sys
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "agents"))

from findings import Finding, make_finding  # noqa: E402

_FINDING_BLOCK = re.compile(
    r'<finding id="(F\d+)"[^>]*>\s*<evidence>\n(.*?)\n</evidence>', re.DOTALL
)


def sample_finding(finding_id: str = "F001", **overrides) -> Finding:
    base = dict(
        source="bandit", rule="B602", severity="high", tier="heuristic",
        file="src/app.py", line=8, message="subprocess con shell=True",
        evidence="8: subprocess.call(cmd, shell=True)",
    )
    base.update(overrides)
    finding = make_finding(**base)
    finding["id"] = finding_id
    return finding


def make_static_result(findings=None, ok=True, tools=None) -> dict:
    return {
        "findings": findings or [],
        "tools": tools or {"secrets": "ok"},
        "ok": ok,
        "files_scanned": 1,
        "limits": [],
    }


def verdict_client(verdict="real", confidence=0.9, reason="motivo de prueba", quote=None):
    """Cliente OpenAI falso. Responde un veredicto por cada <finding> del
    prompt, citando la primera linea de la evidencia mostrada (o `quote`)."""
    client = MagicMock()

    def create(**kwargs):
        user_prompt = kwargs["messages"][-1]["content"]
        verdicts = []
        for finding_id, evidence in _FINDING_BLOCK.findall(user_prompt):
            first_line = evidence.strip().splitlines()[0].strip()
            verdicts.append({
                "id": finding_id, "verdict": verdict, "confidence": confidence,
                "reason": reason, "evidence_quote": first_line if quote is None else quote,
            })
        response = MagicMock()
        response.choices = [MagicMock(message=MagicMock(content=json.dumps({"verdicts": verdicts})))]
        return response

    client.chat.completions.create.side_effect = create
    return client


def text_client(content: str):
    client = MagicMock()
    response = MagicMock()
    response.choices = [MagicMock(message=MagicMock(content=content))]
    client.chat.completions.create.return_value = response
    return client
