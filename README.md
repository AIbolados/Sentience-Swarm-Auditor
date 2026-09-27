# 🛡️ audit-mcp

> **Nota de transición:** este repo (ex-Sentience-Swarm-Auditor, Python +
> LangGraph) y el `audit-mcp` original en TypeScript son, por ahora, dos
> proyectos con el mismo nombre y proposito. Se fusionaran cuando se
> retome el trabajo localmente. Este es el motor mas avanzado (swarm real
> + ensemble multi-modelo), pensado como base de esa fusion.

Sistema de auditoría multi-agente. Orquesta con LangGraph un ensemble
multi-modelo (scan + debate, dos proveedores LLM independientes) para
auditar proyectos completos en paralelo, además del escaneo estático
tradicional (Ruff, Bandit, npm audit). Corre por cron/batch **o** bajo
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
  (`audit_project`, `audit_all_projects`, `get_last_report`).

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
- `/agents`: lógica de los agentes (`audit_agent.py`, `github_watcher.py`,
  `change_detector.py`, `llm_router.py`, `scoring.py`).
- `graph.py`: grafo LangGraph (discovery, audit_project, scoring, reporte).
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
  limit de 60 req/hora en llamadas anónimas al watcher
- Al menos 2 API keys del pool de proveedores LLM (ver `.env.example`)

## 🧪 Desarrollo
```bash
uv sync --extra dev
uv run pytest
uv run ruff check .
```

## 🗺️ Roadmap
Pendiente (Fase 4, diseño aparte por su sensibilidad): motor de
pentesting activo (DAST) para evaluar vulnerabilidades por inyección
contra proyectos propios del equipo — con guardrail explícito de
confirmación de target propio, nunca contra sistemas de terceros sin
autorización.
