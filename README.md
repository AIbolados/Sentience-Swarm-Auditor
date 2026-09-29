# 🛡️ audit-mcp

> **Nota de transición:** este repo (ex-Sentience-Swarm-Auditor, Python +
> LangGraph) y el `audit-mcp` original en TypeScript son, por ahora, dos
> proyectos con el mismo nombre y proposito. Se fusionaran cuando se
> retome el trabajo localmente. Este es el motor mas avanzado (swarm real
> + ensemble multi-modelo), pensado como base de esa fusion.

Sistema de auditoría multi-agente. Orquesta con LangGraph un flujo
discovery → análisis estático (secretos, Ruff, Bandit, npm audit) → panel de
verificación multi-modelo (hasta 3 familias de modelo, votación ciega) →
scoring determinista, para auditar proyectos completos en paralelo. Ver
`docs/superpowers/plans/` para el diseño y `scripts/eval_panel.py` para medir
el panel con proveedores reales (requiere claves; opcionales `<NOMBRE>_MODEL`,
`<NOMBRE>_FAMILY` y `AUDIT_SEND_CODE=0` para no enviar código a los LLM). Corre por cron/batch **o** bajo
demanda como servidor MCP conectado a Claude Code.

## 🚀 Características
- **Swarm real con LangGraph:** discovery hace fan-out por proyecto y
  todos se auditan CONCURRENTEMENTE, no uno a uno.
- **Ensemble multi-modelo:** cada proyecto pasa por un `scan_agent` y un
  `debate_agent` de proveedores LLM distintos (nunca el mismo modelo se
  revisa a sí mismo). Rotación de credenciales entre 7 proveedores
  OpenAI-compatible (NaraRouter, TokenRouter, OpenRouter, Mistral,
  Gemini, Groq, HuggingFace), con cooldown automático en rate limit.
- **Scoring compartido con el audit-mcp en TypeScript:** Engineering
  Health, Vibe Slop Risk, Evidence Confidence, Production Readiness
  (mismo rubric en ambos, para cuando se fusionen).
- **Watcher:** vigila GitHub Advisories para amenazas globales.
- **Zero-Noise:** si un proyecto no cambió desde la última corrida
  exitosa, no se re-audita.
- **MCP server local (stdio):** invocable bajo demanda desde Claude Code
  (`audit_project`, `audit_github_repo`, `audit_all_projects`,
  `get_last_report`).
- **Auditoría de repos remotos de GitHub:** `audit_github_repo(owner/repo)`
  clona (shallow, solo lectura, nunca ejecuta código del repo) y audita
  con el mismo pipeline. `GITHUB_TOKEN` determina el acceso: sin token
  solo públicos, con un token con permiso también privados (propios o de
  tu organización/equipo).
- **Motor DAST activo (Fase 4):** `active_security_scan(target, environment,
  confirm_own_target, confirm_production_risk)` ejecuta
  [Nuclei](https://github.com/projectdiscovery/nuclei) (+14.000 templates
  curados, nunca payloads improvisados por el LLM) contra un target vivo,
  con el mismo patrón scan/debate. **Requiere confirmación explícita**:
  sin `confirm_own_target=True` se rechaza sin ejecutar nada; contra
  `production` exige además `confirm_production_risk=True` y aplica
  límites de agresividad mucho más conservadores (menos requests/segundo)
  para no degradar el servicio.

## 📦 Instalación
1. Copia el repo a la máquina.
2. Copia `.env.example` a `.env` y completa las variables que necesites
   (rutas por defecto: `~/swarm_auditor`, `$HOME`,
   `~/auditoria_diaria/logs`; al menos 2 API keys de proveedores LLM
   para que el patrón scan/debate funcione).
3. Modo batch/cron: `bash swarm.sh` (requiere
   [`uv`](https://docs.astral.sh/uv/) instalado).
4. Modo MCP (uso interactivo desde Claude Code): agrega el servidor
   apuntando a `uv run python mcp_server.py` en este directorio.

## 📂 Estructura
- `/agents`: lógica de los agentes (`discovery.py`, `secrets_scan.py`, `panel.py`,
  `verdicts.py`, `findings.py`, `report.py`, `audit_agent.py`, `github_watcher.py`,
  `change_detector.py`, `llm_router.py`, `scoring.py`, `github_source.py`,
  `active_scan_guard.py`, `dast_nuclei.py`).
- `graph.py`: grafo LangGraph (discovery, audit_project, audit_github_repo,
  run_active_scan, scoring, reporte).
- `mcp_server.py`: servidor MCP que expone el grafo como tools.
- `conductor.py`: entrypoint del modo batch/cron.
- `/tests`: tests con `pytest`.
- `LOG_DIR` (env var): historial de reportes `.md`.
- `SWARM_HOME/state.json`: hashes de proyectos (control de cambios).

## 🛠️ Requisitos
- Python 3.10+
- [`uv`](https://docs.astral.sh/uv/) como gestor de paquetes
- Node.js (opcional, para proyectos JS con `npm audit`)
- Token de GitHub (opcional, recomendado) en `.env` para evitar el rate
  limit de 60 req/hora en llamadas anónimas al watcher, y necesario para
  auditar repos privados con `audit_github_repo`
- Al menos 2 API keys del pool de proveedores LLM (ver `.env.example`)
- Para el motor DAST activo (opcional, solo si usás `active_security_scan`):
  [`nuclei`](https://github.com/projectdiscovery/nuclei)
  (`go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`)
  y sus templates (`git clone --depth=1
  https://github.com/projectdiscovery/nuclei-templates.git`, ruta
  configurable con `NUCLEI_TEMPLATES_DIR`)

## 🧪 Desarrollo
```bash
uv sync --extra dev
uv run pytest
uv run ruff check .
```

## ⚠️ Motor DAST activo: uso responsable
`active_security_scan` ejecuta tráfico real contra un target. Está
pensado exclusivamente para **evaluar la seguridad de proyectos propios
del equipo**, nunca contra sistemas de terceros sin su autorización
explícita y por escrito — eso sería acceso no autorizado, no auditoría.
El guardrail (`agents/active_scan_guard.py`) no tiene forma de saltarse:
sin `confirm_own_target=True` se rechaza antes de tocar la red.
