# 🛡️ Sentience Swarm Auditor

Sistema de auditoría multi-agente para desarrolladores. Escanea tus proyectos localmente cada mañana (o bajo demanda), detecta cambios y genera reportes de salud (seguridad, calidad y debugging).

## 🚀 Características
- **Zero-Noise:** Si no hay cambios en tus archivos, el sistema no hace nada.
- **Swarm de Agentes:**
    - **Watcher:** Vigila GitHub para aprender nuevas reglas.
    - **Auditor:** Escanea Python (Ruff, Bandit, Radon) y Node.js (NPM Audit).
    - **Debugger:** Propone correcciones inmediatas si detecta errores de sintaxis.
- **Portable:** Todo reside en una carpeta.

## 📦 Instalación
1. Copia el repo a la máquina.
2. Copia `.env.example` a `.env` y completa las variables que necesites (por
   defecto usa `~/swarm_auditor`, `$HOME` y `~/auditoria_diaria/logs`).
3. Ejecuta `bash swarm.sh` (requiere [`uv`](https://docs.astral.sh/uv/) instalado).
4. (Opcional) Agenda `swarm.sh` en cron o en `~/.config/autostart/` para automatizar.

## 📂 Estructura
- `/agents`: Lógica de los agentes especializados (`audit_agent.py`,
  `github_watcher.py`, `change_detector.py`).
- `/tests`: Tests con `pytest`.
- `LOG_DIR` (env var): historial de auditorías realizadas.
- `SWARM_HOME/state.json`: base de datos de hashes (control de cambios).
- `conductor.py`: orquestador principal.

## 🛠️ Requisitos
- Python 3.10+
- [`uv`](https://docs.astral.sh/uv/) como gestor de paquetes
- Node.js (opcional, para proyectos JS con `npm audit`)
- Token de GitHub (opcional, recomendado) en `.env` para evitar el rate
  limit de 60 req/hora en llamadas anónimas al watcher

## 🧪 Desarrollo
```bash
uv sync --extra dev
uv run pytest
uv run ruff check .
```

## 🗺️ Roadmap (v2)
Ver plan de evolución hacia orquestación con LangGraph, ensemble
multi-modelo (rotación de credenciales entre proveedores) y auditoría en
paralelo de todos los proyectos a la vez — en discusión, no implementado
todavía en este repo.
