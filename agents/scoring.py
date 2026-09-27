"""Rubric de scoring por proyecto.

Mismo lenguaje de auditoria que audit-mcp (4 dimensiones inspiradas en
vibe-coding-shit-detector), para que un hallazgo se clasifique igual en
ambos productos aunque corran en runtimes distintos.
"""

from typing import TypedDict


class Score(TypedDict):
    engineering_health: int  # 0-100, mas alto = mejor
    vibe_slop_risk: int  # 0-100, mas alto = peor (brecha entre lo que hay y lo que deberia haber)
    evidence_confidence: int  # 0-100, cuanto confiar en este resultado
    production_readiness: str  # NOT_ASSESSED | BLOCKED | CONDITIONAL | READY


def _debate_confirms_risk(debate_output: str | None) -> bool:
    if not debate_output:
        return False
    lowered = debate_output.lower()
    confirm_keywords = ("confirmo", "confirmado", "riesgo real", "vulnerabilidad real")
    return any(kw in lowered for kw in confirm_keywords)


def _debate_refutes_scan(debate_output: str | None) -> bool:
    if not debate_output:
        return False
    lowered = debate_output.lower()
    refute_keywords = ("falso positivo", "no es un riesgo", "no aplica", "descartado")
    return any(kw in lowered for kw in refute_keywords)


def score_project(result: dict) -> Score:
    static = result.get("static", {}) or {}
    ensemble = result.get("ensemble", {}) or {}

    has_security_issue = bool(static.get("bandit"))
    has_syntax_issue = bool(static.get("ruff"))
    ensemble_failed = bool(ensemble.get("error"))
    debate_output = ensemble.get("debate_output")

    confirmed = _debate_confirms_risk(debate_output)
    refuted = _debate_refutes_scan(debate_output)

    engineering_health = 100
    if has_syntax_issue:
        engineering_health -= 20
    if has_security_issue:
        engineering_health -= 30
    engineering_health = max(0, engineering_health)

    vibe_slop_risk = 0
    if has_security_issue and refuted:
        vibe_slop_risk += 10  # el hallazgo estatico probablemente era ruido
    elif has_security_issue and not confirmed and not ensemble_failed:
        vibe_slop_risk += 20  # hallazgo sin corroborar por el debate
    if has_syntax_issue:
        vibe_slop_risk += 10
    vibe_slop_risk = min(100, vibe_slop_risk)

    evidence_confidence = 30 if ensemble_failed else 100

    if has_security_issue and confirmed:
        production_readiness = "BLOCKED"
    elif ensemble_failed:
        production_readiness = "NOT_ASSESSED"
    elif has_security_issue or has_syntax_issue:
        production_readiness = "CONDITIONAL"
    else:
        production_readiness = "READY"

    return Score(
        engineering_health=engineering_health,
        vibe_slop_risk=vibe_slop_risk,
        evidence_confidence=evidence_confidence,
        production_readiness=production_readiness,
    )
