# 🛡️ Sentience Swarm Auditor

Sistema de auditoría multi-agente para desarrolladores. Escanea tus proyectos localmente cada mañana (o bajo demanda), detecta cambios y genera reportes de salud (seguridad, calidad y debugging).

## 🚀 Características
- **Zero-Noise:** Si no hay cambios en tus archivos, el sistema no hace nada.
- **Swarm de Agentes:**
    - **Watcher:** Vigila GitHub para aprender nuevas reglas.
    - **Auditor:** Escanea Python (Ruff, Bandit, Radon) y Node.js (NPM Audit).
    - **Debugger:** Propone correcciones inmediatas si detecta errores de sintaxis.
- **Portable:** Todo reside en una carpeta.

## 📦 Instalación (Compartir)
Para usarlo en otro PC:
1. Copia la carpeta `swarm_auditor`.
2. Ejecuta `bash swarm_auditor/swarm.sh`.
3. (Opcional) Agrega el `.desktop` a `~/.config/autostart/` para automatizar.

## 📂 Estructura
- `/agents`: Lógica de los agentes especializados.
- `/logs`: Historial de auditorías realizadas.
- `state.json`: Base de datos de hashes (control de cambios).
- `conductor.py`: Orquestador principal.

## 🛠️ Requisitos
- Python 3.10+
- Node.js (opcional, para proyectos JS)

---
*Generado por Gemini CLI Agent*
