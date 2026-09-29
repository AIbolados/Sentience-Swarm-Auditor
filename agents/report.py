"""Render de la seccion por proyecto del reporte .md. Solo muestra
mensajes/reglas ya redactados: nunca evidencia cruda."""

MAX_LISTED = 15
STATUS_TITLES = (
    ("confirmed", "Confirmados"),
    ("disputed", "En disputa (revision humana)"),
    ("unverified", "Sin verificar"),
    ("unreviewed", "Sin revision del panel (severidad baja)"),
)


def _one_line(text: str, limit: int = 200) -> str:
    return " ".join(str(text).split())[:limit]


def _location(finding: dict) -> str:
    return finding["file"] + (f":{finding['line']}" if finding["line"] else "")


def _panel_line(panel: dict) -> str:
    if not panel.get("reviewed"):
        return "- Panel: no requerido (sin hallazgos de severidad media o mayor)"
    diversity = "diversidad verificada" if panel.get("diverse") else "diversidad NO verificada"
    line = f"- Panel: {panel.get('min_size', 0)} revisor(es) por lote, {diversity}"
    if panel.get("error"):
        line += f" — {_one_line(panel['error'])}"
    return line


def render_project_section(project: dict) -> str:
    score = project.get("score") or {}
    discovery = project.get("discovery") or {}
    findings = project.get("findings") or []
    consolidated = project.get("consolidated") or {}

    languages = ", ".join(
        f"{lang}: {count}" for lang, count in sorted((discovery.get("languages") or {}).items())
    ) or "sin codigo detectado"
    lines = [
        f"\n### {project['name']}",
        f"- Production readiness: **{score.get('production_readiness', 'NOT_ASSESSED')}**",
        f"- Engineering health: {score.get('engineering_health', '?')}/100",
        f"- Vibe slop risk: {score.get('vibe_slop_risk', '?')}/100",
        f"- Evidence confidence: {score.get('evidence_confidence', '?')}/100",
        f"- Clasificacion: {discovery.get('classification', '?')} ({languages})",
    ]
    lines += [f"- Limitacion: {_one_line(reason)}" for reason in score.get("reasons") or []]
    lines.append(_panel_line(project.get("panel") or {}))

    def status_of(finding: dict) -> str:
        return (consolidated.get(finding["id"]) or {}).get("status", "unreviewed")

    for status, title in STATUS_TITLES:
        items = [f for f in findings if status_of(f) == status]
        if not items:
            continue
        lines.append(f"- {title} ({len(items)}):")
        for finding in items[:MAX_LISTED]:
            lines.append(
                f"  - [{finding['severity'].upper()}] {_location(finding)} "
                f"`{finding['rule']}` {_one_line(finding['message'])}"
            )
        if len(items) > MAX_LISTED:
            lines.append(f"  - ... y {len(items) - MAX_LISTED} mas")

    dismissed = [f for f in findings if status_of(f) == "dismissed"]
    if dismissed:
        lines.append(
            f"- Descartados por el panel ({len(dismissed)}) — razon registrada para auditoria:"
        )
        for finding in dismissed[:MAX_LISTED]:
            reasons = "; ".join(
                vote["reason"] for vote in consolidated[finding["id"]]["votes"]
                if vote["verdict"] == "false_positive"
            )
            lines.append(f"  - {_location(finding)} `{finding['rule']}`: {_one_line(reasons)}")
    return "\n".join(lines) + "\n"
