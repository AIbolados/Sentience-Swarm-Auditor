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
    reasons: list[str]  # limitaciones y motivos legibles (cobertura, panel, disputas)


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


def score_active_scan(findings: list[dict], ensemble: dict | None) -> Score:
    """Rubric para resultados del motor DAST activo (Fase 4). Distinto de
    score_project porque la entrada es una lista de hallazgos con
    severidad explicita del template (nuclei), no output de linters."""
    ensemble = ensemble or {}
    critical_or_high = [
        f for f in findings if (f.get("severity") or "").lower() in ("critical", "high")
    ]
    ensemble_failed = bool(ensemble.get("error"))
    debate_output = ensemble.get("debate_output")
    confirmed = _debate_confirms_risk(debate_output)
    refuted = _debate_refutes_scan(debate_output)

    engineering_health = max(0, 100 - min(100, len(findings) * 5))

    vibe_slop_risk = 0
    if critical_or_high and confirmed:
        vibe_slop_risk = 60
    elif critical_or_high and not refuted and not ensemble_failed:
        vibe_slop_risk = 40

    evidence_confidence = 30 if ensemble_failed else 100

    if critical_or_high and confirmed:
        production_readiness = "BLOCKED"
    elif ensemble_failed:
        production_readiness = "NOT_ASSESSED"
    elif findings:
        production_readiness = "CONDITIONAL"
    else:
        production_readiness = "READY"

    return Score(
        engineering_health=engineering_health,
        vibe_slop_risk=vibe_slop_risk,
        evidence_confidence=evidence_confidence,
        production_readiness=production_readiness,
        reasons=[],
    )


SEVERITY_WEIGHT = {"critical": 40, "high": 25, "medium": 10, "low": 3, "info": 0}
STATUS_FACTOR = {
    "confirmed": 1.0, "unreviewed": 1.0, "disputed": 0.6, "unverified": 0.6, "dismissed": 0.0,
}
SECURITY_SOURCES = {"secrets", "bandit", "npm_audit"}
_HIGH = 3  # SEVERITY_ORDER["high"]


def _coverage_gaps(coverage: dict, tools: dict) -> list[str]:
    gaps = []
    if coverage.get("unanalyzed_languages"):
        gaps.append(
            "Lenguajes sin analizador (solo escaneo de secretos): "
            + ", ".join(coverage["unanalyzed_languages"])
        )
    if coverage.get("partial_languages"):
        gaps.append(
            "Analisis parcial (solo dependencias, sin analisis de codigo): "
            + ", ".join(coverage["partial_languages"])
        )
    if coverage.get("unaudited_automation"):
        gaps.append(
            "Automatizaciones sin motor de procesos (contenido no auditado): "
            + ", ".join(coverage["unaudited_automation"][:5])
        )
    gaps.extend(coverage.get("limits") or [])
    if set(tools) <= {"secrets"}:
        gaps.append("Ningun analizador de codigo aplico (solo escaneo de secretos)")
    failed = sorted(name for name, status in tools.items() if status != "ok")
    if failed:
        gaps.append(
            "Herramientas que no completaron: " + ", ".join(f"{n} ({tools[n]})" for n in failed)
        )
    if coverage.get("truncated"):
        gaps.append("Arbol truncado: no se analizaron todos los archivos")
    return gaps


def score_project(result: dict) -> Score:
    """Scoring determinista desde hallazgos consolidados + cobertura + estado
    del panel. Ya no interpreta texto libre de un LLM."""
    from findings import SEVERITY_ORDER

    findings = result.get("findings") or []
    consolidated = result.get("consolidated") or {}
    coverage = result.get("coverage") or {}
    tools = result.get("tools") or {}
    panel = result.get("panel") or {}

    def status_of(finding: dict) -> str:
        return (consolidated.get(finding["id"]) or {}).get("status", "unreviewed")

    open_findings = [f for f in findings if status_of(f) != "dismissed"]
    penalty = sum(
        SEVERITY_WEIGHT[f["severity"]] * STATUS_FACTOR[status_of(f)] for f in open_findings
    )
    engineering_health = max(0, 100 - int(round(penalty)))

    gaps = _coverage_gaps(coverage, tools)
    panel_needed = (panel.get("reviewed") or 0) > 0
    panel_reasons = []
    if panel_needed and panel.get("min_size", 0) < 2:
        panel_reasons.append("Panel con menos de 2 revisores: hallazgos sin verificar")
    elif panel_needed and not panel.get("diverse"):
        panel_reasons.append(
            "Diversidad de modelos no verificada (fije <PROVEEDOR>_MODEL y <PROVEEDOR>_FAMILY)"
        )
    if panel.get("overflow"):
        panel_reasons.append(f"{panel['overflow']} hallazgos quedaron fuera del limite del panel")

    has_disputed = any(status_of(f) in ("disputed", "unverified") for f in findings)
    reasons = list(gaps) + panel_reasons
    if has_disputed:
        reasons.append("Hay hallazgos en disputa o sin verificar: requieren revision humana")

    open_security = [
        f for f in open_findings
        if f["source"] in SECURITY_SOURCES and SEVERITY_ORDER[f["severity"]] >= 2
    ]
    vibe_slop_risk = min(100, 15 * len(open_security) + 10 * len(gaps))

    confidence = 100
    if panel_needed and panel.get("min_size", 0) < 2:
        confidence -= 40
    elif panel_needed and not panel.get("diverse"):
        confidence -= 20
    if any(status != "ok" for status in tools.values()):
        confidence -= 15
    if coverage.get("unanalyzed_languages") or coverage.get("partial_languages"):
        confidence -= 15
    if coverage.get("unaudited_automation"):
        confidence -= 10
    if coverage.get("truncated") or coverage.get("limits"):
        confidence -= 10
    if set(tools) <= {"secrets"}:
        confidence -= 15
    if has_disputed:
        confidence -= 10
    evidence_confidence = max(10, confidence)

    confirmed_high = any(
        status_of(f) == "confirmed" and SEVERITY_ORDER[f["severity"]] >= _HIGH for f in findings
    )
    if coverage.get("files_scanned", 0) == 0:
        production_readiness = "NOT_ASSESSED"
        reasons.append("Target vacio o ilegible: no se analizo ningun archivo")
    elif confirmed_high:
        production_readiness = "BLOCKED"
    elif open_findings or reasons:
        production_readiness = "CONDITIONAL"
    else:
        production_readiness = "READY"

    return Score(
        engineering_health=engineering_health,
        vibe_slop_risk=vibe_slop_risk,
        evidence_confidence=evidence_confidence,
        production_readiness=production_readiness,
        reasons=reasons,
    )
