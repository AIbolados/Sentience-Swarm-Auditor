# CLAUDE.md — audit-mcp

## 1. Contexto de negocio (por qué existe este proyecto)

Este proyecto nace de una oportunidad laboral en **Arcadia**. Situación real detectada:

- Arcadia tiene automatizaciones corriendo en producción **sin revisión** de nadie.
- Las áreas del negocio usan IA para automatizar y desarrollar **sin ser expertas** — "vibe coding" y automatización sin ingeniería detrás.
- Consecuencia directa: **sobreingeniería**, procesos redundantes, deuda técnica invisible, y riesgo acumulado (seguridad, mantenibilidad, cumplimiento) que nadie ha medido.
- No existe hoy ningún mecanismo de auditoría interna sobre esto.

`audit-mcp` es la herramienta que resuelve ese vacío: un servidor MCP que audita **tanto procesos de negocio automatizados como código/proyectos construidos con IA**, sin asumir de antemano qué stack usa el área auditada (n8n, Zapier, Make, Python, Node, agentes custom, etc.).

Este repo se construye como pieza de portafolio para la postulación — hoy **no hay acceso real a los sistemas de Arcadia**. Por eso el diseño debe ser genérico: capaz de auditar cualquier repo/export que se le apunte, no algo hardcodeado a un stack específico.

## 2. Rol de Claude Code en este proyecto

Actuar como ingeniero senior construyendo una herramienta de auditoría **profesional, escalable y a producción real desde la v1** — no un demo, no un prototipo desechable. Cero margen de error en la lógica de detección: un falso negativo en una auditoría de seguridad es peor que no auditar.

Postura de diseño: **escéptico por defecto**. La herramienta parte de la premisa de que lo auditado probablemente tiene sobreingeniería, huecos de seguridad y nadie que lo entienda del todo. El output debe ser accionable para alguien no-técnico (dueño de área) y preciso para alguien técnico (Ignacio/equipo dev).

## 3. Qué hace `audit-mcp`

Dos motores de auditoría bajo un mismo servidor MCP:

### 3.1 Motor de auditoría de procesos
Compara el proceso **ejecutado** contra el **esperado** (conformance checking) y detecta:
- Pasos huérfanos / no documentados
- Aprobaciones saltadas
- Loops o ramas anómalas
- Duplicación de lógica entre automatizaciones (sobreingeniería)
- Puntos únicos de falla

Lógica de referencia (a portar/adaptar en TS, sin dependencia de Python):
- [`process-intelligence-solutions/pm4py`](https://github.com/process-intelligence-solutions/pm4py) — librería de referencia en conformance checking. Se usa como **referencia conceptual del algoritmo**, no como dependencia (evitar runtime Python en Cloudflare Workers).

### 3.2 Motor de auditoría de código/proyectos IA
Audita código generado por IA (vibe-coding) buscando:
- Secretos/credenciales expuestas (API keys, tokens, connection strings)
- Vulnerabilidades comunes en código IA: inyección, CORS mal configurado, auth faltante, RLS de Supabase mal aplicado, JWT débil, permisos excesivos en CI/CD
- Señales de sobreingeniería: abstracciones sin uso, dependencias innecesarias, arquitectura desproporcionada al problema
- Madurez/production-readiness: ¿puede alguien nuevo trabajar en esto sin el historial de chat que lo generó? ("Repository Amnesia Test")

Repos base de referencia:
- [`crazyrabbitLTC/mcp-code-review-server`](https://github.com/crazyrabbitLTC/mcp-code-review-server) (⭐34/🍴23) — mejor esqueleto de protocolo MCP + multi-LLM ya resuelto. **Partir de este.**
- [`ApacheWang/vibe-audit`](https://github.com/ApacheWang/vibe-audit) y [`mahsumaktas/vibe-guard`](https://github.com/mahsumaktas/vibe-guard) — set de reglas de seguridad específicas para código IA (secrets, injection, auth, config, CORS, deps). Portar sus checks.
- [`dulanjy/vibe-coding-shit-detector`](https://github.com/dulanjy/vibe-coding-shit-detector) — rúbrica de scoring (Engineering Health / Vibe Slop Risk / Evidence Confidence / Production Readiness). Usar como modelo del output final.

### 3.3 Fase de discovery (previa a ambos motores)
Antes de auditar, el MCP **detecta qué está recibiendo**:
1. Escanea el input (repo git, carpeta, export JSON/YAML)
2. Clasifica: ¿es código fuente? ¿es un export de workflow (n8n/Zapier/Make)? ¿es un agente/bot? ¿mezcla de ambos?
3. Rutea al motor correspondiente (proceso, código, o ambos si el repo contiene automatizaciones + código)

Esto es necesario porque **no se sabe aún qué stack de automatización usa cada área de Arcadia** — la herramienta no puede asumirlo.

## 4. Arquitectura y stack

> **Decisión tomada (2026-09-28):** el diseño original TypeScript/Node +
> Cloudflare Workers descrito más abajo era una idea preliminar, nunca
> implementada. El proyecto oficial es el que corre hoy en producción de
> facto: **Python + LangGraph + MCP SDK oficial**, en el repo
> `github.com/AIbolados/audit-mcp`, rama `main`. No hay plan de fusión ni
> migración a TS — esto reemplaza esa idea.

- **Runtime:** Python 3.10+.
- **Orquestación:** LangGraph (`graph.py`) — fan-out concurrente por proyecto (`Send()`), nunca secuencial. Ensemble scan/debate: dos proveedores LLM distintos por hallazgo, uno nunca revisa su propio análisis.
- **MCP SDK:** `mcp[cli]` (oficial, paquete `mcp` de PyPI) — `mcp.server.mcpserver.MCPServer`.
- **Modo de transporte:** local/stdio, conectado directo a Claude Code (`mcp_server.py`). Tools expuestas: `audit_project`, `audit_github_repo`, `active_security_scan`, `audit_all_projects`, `get_last_report`. Sin plan de deploy remoto (HTTP/SSE) por ahora — si surge la necesidad, se evalúa en su momento.
- **Rotación de credenciales LLM:** `agents/llm_router.py`, round-robin sobre 7 proveedores OpenAI-compatible (NaraRouter, TokenRouter, OpenRouter, Mistral, Gemini, Groq, HuggingFace) con cooldown en 429.
- **Motor DAST activo:** `agents/dast_nuclei.py` + guardrail estricto en `agents/active_scan_guard.py` (nunca corre sin `confirm_own_target=True`, límites de agresividad distintos en producción).
- **Persistencia actual:** archivos — `state.json` (hashes de control de cambios) + reportes `.md` en `LOG_DIR`. Persistencia en Supabase (schema `audit` compartido con `feasibility-mcp`/`reverse-mcp`) sigue siendo un gap pendiente del roadmap, no implementado todavía.
- **Gestor de paquetes:** `uv` (`pyproject.toml` + `uv.lock`).
- **Lint/test:** `ruff check .` + `pytest` (`uv run ruff check .`, `uv run pytest`).
- **Nunca**: credenciales hardcodeadas — todo vía `.env` (no versionado) + `.env.example` versionado con placeholders. Verificado sin excepciones en la auditoría del 2026-09-28.

## 5. Roadmap / fases de construcción

**Hecho (rama `main` actual):**
1. ✅ Setup del server MCP base (`mcp_server.py`, SDK oficial `mcp[cli]`)
2. ✅ Motor de auditoría de código IA: escaneo estático (ruff/bandit/npm audit) + ensemble LLM scan/debate (`agents/audit_agent.py`, `graph.py`)
3. ✅ Capa de scoring/rúbrica unificada — Engineering Health, Vibe Slop Risk, Evidence Confidence, Production Readiness (`agents/scoring.py`)
4. ✅ Auditoría de repos remotos de GitHub (`audit_github_repo`, clone shallow + cleanup garantizado)
5. ✅ Motor DAST activo con guardrail (`active_security_scan`)

**Pendiente:**
6. ⬜ Motor de discovery: clasificar el input recibido (código fuente vs. export de workflow n8n/Zapier/Make vs. mixto) antes de rutear al motor correspondiente
7. ⬜ Motor de auditoría de **procesos** (conformance checking, inspirado en `pm4py`) — hoy solo existe el motor de código, no el de procesos de negocio automatizados
8. ⬜ Persistencia en Supabase (schema `audit`)
9. ⬜ Alinear nombres de tools MCP expuestas con el vocabulario del roadmap original si aplica (`discover_target`, `audit_process`, `get_audit_report`) — hoy los nombres son los de la sección 4 (`audit_project`, etc.)

## 6. Definición de éxito

El MCP debe poder apuntarse a un repo cualquiera (incluyendo uno propio de Ignacio) y devolver un informe de auditoría con: hallazgos priorizados por severidad, evidencia concreta (no genérica), y un score de madurez/riesgo — utilizable tal cual para mostrar a Arcadia como caso de uso real, no hipotético.
