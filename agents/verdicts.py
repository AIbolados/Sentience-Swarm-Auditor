"""Parseo estricto y consolidacion de veredictos del panel de modelos.

Logica pura, sin I/O. Principios (ver invariantes del plan):
- Un voto real/falso_positivo solo cuenta si cita un fragmento EXACTO de la
  evidencia mostrada y tiene confianza suficiente; si no, es abstencion.
- dismissed exige >= 2 votos FP y 0 votos real (sin disidencia).
- Un hallazgo determinista de severidad >= high nunca queda dismissed.
- Un falso negativo es peor que un falso positivo: ante la duda, `disputed`.
"""

import json
from typing import TypedDict

from findings import SEVERITY_ORDER, Finding

VERDICTS = ("real", "false_positive", "uncertain")
MIN_VOTE_CONFIDENCE = 0.5
MIN_QUOTE_CHARS = 4
MAX_REASON_CHARS = 240
MIN_QUORUM = 2
MAX_JSON_SCAN_ATTEMPTS = 8


class Vote(TypedDict):
    provider: str
    family: str
    verdict: str  # real | false_positive | uncertain (uncertain = abstencion)
    confidence: float
    reason: str
    grounded: bool
    verified: bool  # la familia del revisor esta verificada (modelo y familia fijados)


class Consolidated(TypedDict):
    status: str  # confirmed | disputed | dismissed | unverified | unreviewed
    votes: list[Vote]


def _find_payload(text: str) -> dict:
    """Primer objeto JSON con la clave 'verdicts' (tolera prosa y bloques markdown)."""
    decoder = json.JSONDecoder()
    start = text.find("{")
    attempts = 0
    while start != -1 and attempts < MAX_JSON_SCAN_ATTEMPTS:
        attempts += 1
        try:
            value, _ = decoder.raw_decode(text[start:])
        except json.JSONDecodeError:
            value = None
        if isinstance(value, dict) and "verdicts" in value:
            return value
        start = text.find("{", start + 1)
    raise ValueError("la respuesta no contiene un objeto JSON con 'verdicts'")


def parse_verdict_payload(text: str) -> dict[str, dict]:
    """Valida la forma y devuelve {finding_id: veredicto}. Lanza ValueError."""
    verdicts = _find_payload(text).get("verdicts")
    if not isinstance(verdicts, list):
        raise ValueError("'verdicts' no es una lista")
    parsed: dict[str, dict] = {}
    for item in verdicts:
        if not isinstance(item, dict):
            raise ValueError("un veredicto no es un objeto")
        finding_id = item.get("id")
        verdict = str(item.get("verdict", "")).strip().lower()
        if not isinstance(finding_id, str) or verdict not in VERDICTS:
            raise ValueError(f"veredicto invalido: {str(item)[:120]}")
        try:
            confidence = float(item.get("confidence", 0.0))
        except (TypeError, ValueError):
            raise ValueError("confidence no numerica") from None
        parsed.setdefault(finding_id, {
            "verdict": verdict,
            "confidence": min(1.0, max(0.0, confidence)),
            "reason": str(item.get("reason", ""))[:MAX_REASON_CHARS],
            "evidence_quote": str(item.get("evidence_quote", "")),
        })
    return parsed


def _normalize(text: str) -> str:
    return " ".join(text.split())


def is_grounded(quote: str, shown_evidence: str) -> bool:
    normalized = _normalize(quote)
    return len(normalized) >= MIN_QUOTE_CHARS and normalized in _normalize(shown_evidence)


def build_votes(
    provider: str,
    family: str,
    parsed: dict[str, dict],
    shown_evidence: dict[str, str],
    verified: bool = True,
) -> dict[str, Vote]:
    """Un Vote por hallazgo mostrado. `shown_evidence` es el texto EXACTO
    (ya escapado) que vio el modelo: contra eso se verifica la cita."""
    votes: dict[str, Vote] = {}
    for finding_id, evidence in shown_evidence.items():
        item = parsed.get(finding_id)
        if item is None:
            votes[finding_id] = Vote(
                provider=provider, family=family, verdict="uncertain", confidence=0.0,
                reason="sin veredicto para este hallazgo", grounded=False, verified=verified,
            )
            continue
        grounded = is_grounded(item["evidence_quote"], evidence)
        verdict, reason = item["verdict"], item["reason"]
        if verdict != "uncertain" and not grounded:
            verdict, reason = "uncertain", f"voto descartado: cita no verificable ({reason})"
        elif verdict != "uncertain" and item["confidence"] < MIN_VOTE_CONFIDENCE:
            verdict, reason = "uncertain", f"voto descartado: confianza baja ({reason})"
        votes[finding_id] = Vote(
            provider=provider, family=family, verdict=verdict,
            confidence=item["confidence"], reason=reason[:MAX_REASON_CHARS], grounded=grounded,
            verified=verified,
        )
    return votes


def _is_high_precision(finding: Finding) -> bool:
    return (
        finding["tier"] == "deterministic"
        and SEVERITY_ORDER[finding["severity"]] >= SEVERITY_ORDER["high"]
    )


def consolidate_finding(
    finding: Finding, votes: list[Vote], responding: int | None
) -> Consolidated:
    """`responding` = revisores que respondieron para el lote de este hallazgo;
    None = el hallazgo no se envio al panel."""
    n_real = sum(1 for v in votes if v["verdict"] == "real")
    n_fp = sum(1 for v in votes if v["verdict"] == "false_positive")

    if _is_high_precision(finding):
        status = "disputed" if n_fp >= 2 else "confirmed"
    elif responding is None:
        status = "unreviewed"
    elif responding < MIN_QUORUM or n_real + n_fp == 0:
        status = "unverified"
    elif n_real >= 2:
        status = "confirmed"
    elif n_fp >= 2 and n_real == 0:
        # Descartar exige >= 2 familias VERIFICADAS distintas: votos de agregadores
        # "auto" pueden venir del mismo modelo y no cuentan como independientes.
        fp_families = {
            v["family"] for v in votes
            if v["verdict"] == "false_positive" and v.get("verified", True)
        }
        status = "dismissed" if len(fp_families) >= 2 else "disputed"
    else:
        status = "disputed"
    return Consolidated(status=status, votes=votes)
