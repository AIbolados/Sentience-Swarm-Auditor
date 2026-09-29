"""Tipos compartidos del pipeline de auditoria: el hallazgo normalizado.

Todas las fuentes (secretos, ruff, bandit, npm audit) producen el mismo
Finding, para que el panel de modelos y el scoring razonen sobre UNA forma
de dato y no sobre el texto libre de cada herramienta.
"""

from typing import TypedDict

SEVERITY_ORDER: dict[str, int] = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
TIERS = ("deterministic", "heuristic")


class Finding(TypedDict):
    id: str  # "F001"; estable solo dentro de una corrida (lo asigna assign_ids)
    source: str  # "secrets" | "ruff" | "bandit" | "npm_audit"
    rule: str  # "aws-access-key-id" | "B602" | "F821" | "npm:lodash" ...
    severity: str  # critical | high | medium | low | info
    tier: str  # "deterministic": alta precision; "heuristic": puede ser falso positivo
    file: str  # ruta relativa al target
    line: int | None
    message: str
    evidence: str  # fragmento de codigo YA REDACTADO (ver secrets_scan.redact)


def make_finding(
    *,
    source: str,
    rule: str,
    severity: str,
    tier: str,
    file: str,
    line: int | None,
    message: str,
    evidence: str = "",
) -> Finding:
    if severity not in SEVERITY_ORDER:
        raise ValueError(f"severidad desconocida: {severity!r}")
    if tier not in TIERS:
        raise ValueError(f"tier desconocido: {tier!r}")
    return Finding(
        id="", source=source, rule=rule, severity=severity, tier=tier,
        file=file, line=line, message=message, evidence=evidence,
    )


def assign_ids(findings: list[Finding]) -> list[Finding]:
    """Ordena por severidad (desc), archivo y linea, y asigna ids F001..."""
    ordered = sorted(
        findings,
        key=lambda f: (-SEVERITY_ORDER[f["severity"]], f["file"], f["line"] or 0, f["rule"]),
    )
    for index, finding in enumerate(ordered, start=1):
        finding["id"] = f"F{index:03d}"
    return ordered
