# Motor de discovery — diseño

**Fecha:** 2026-09-28
**Estado:** aprobado en conversación, pendiente de plan de implementación
**Roadmap:** punto 6 de `CLAUDE.md` sección 5

## Contexto y problema

Hoy `audit-mcp` audita exclusivamente código fuente (`audit_project`, `audit_github_repo`, `audit_all_projects`). No existe forma de distinguir si un target es código, un export de una herramienta de automatización (n8n/Zapier/Make), o una mezcla de ambos. Esto contradice la premisa base del proyecto (`CLAUDE.md` sección 3.3): "no se sabe qué stack de automatización usa cada área de Arcadia — la herramienta no puede asumirlo".

Sin discovery:
- Un export de automatización pasado a `audit_project` se escanea con ruff/bandit/npm audit sin encontrar nada útil, y se gasta una llamada al ensemble LLM sobre datos irrelevantes.
- No hay señal de que un repo mixto (código + automatización) tiene componentes de automatización sin auditar.
- El motor de procesos (punto 7 del roadmap, no implementado) no tiene un punto de entrada que le indique qué formato está mirando.

## Objetivo de esta fase

Clasificar el target ANTES de auditar y rutear el comportamiento según el resultado. **No implementa auditoría de procesos** (eso es el punto 7, separado) — solo detecta y reporta qué hay, evitando trabajo inútil (static checks + LLM) cuando no hay código que auditar.

## Decisiones (resueltas en brainstorming, no reabrir sin razón nueva)

1. **Integración: embebida**, no como tool standalone. `audit_project`, `audit_github_repo` y `audit_all_projects` cambian de comportamiento automáticamente; no hay un `discover_target` invocable por separado en esta fase.
2. **Formatos reconocidos en v1:** n8n, Zapier, Make, y `automation_unknown` (JSON/YAML con forma de workflow que no matchea ningún patrón conocido — nunca se ignora silenciosamente).
3. **Target 100% automatización → short-circuit.** No corre `run_static_checks` ni `router.chat_ensemble`. No tiene sentido gastar tokens de LLM analizando código que no existe.
4. **Clasificación heurística, sin LLM.** Coherente con el patrón ya existente en el proyecto (static tools primero, LLM solo interpreta después — ver `run_static_checks` en `agents/audit_agent.py`). Determinístico, testeable, no depende de que haya un proveedor LLM disponible.

## Arquitectura

Nuevo módulo `agents/discovery.py`. Se engancha en `run_project_audit()` (`graph.py`), el único punto compartido por los tres flujos de auditoría de código (`audit_project`, `audit_github_repo`, batch vía `audit_project_node`).

### Tipos

```python
class AutomationMatch(TypedDict):
    format: str          # "n8n" | "zapier" | "make" | "automation_unknown"
    file: str             # ruta relativa al target
    workflow_name: str | None

class DiscoveryResult(TypedDict):
    classification: str   # "code" | "automation" | "mixed" | "empty"
    is_python: bool
    is_node: bool
    automation: list[AutomationMatch]
```

### Función principal

`classify_target(path: str) -> DiscoveryResult`

- Recorre el target: nivel superior + 1 nivel de profundidad, respetando `IGNORE_DIRS` (reusado de `agents/audit_agent.py`, no duplicado).
- `is_python` / `is_node`: misma lógica que ya existe en `run_static_checks` (presencia de `.py`/`requirements.txt`/`pyproject.toml`, o `package.json`), extraída a una función compartida para no duplicar código entre `discovery.py` y `audit_agent.py`.
- Para cada archivo `.json`/`.yaml`/`.yml` encontrado, intenta parsearlo y lo pasa por los detectores de firma, en este orden:
  - `_is_n8n(data)`: tiene clave `nodes` (lista) y `connections` (dict)
  - `_is_zapier(data)`: tiene clave `zaps`, o (`trigger` + `steps`)
  - `_is_make(data)`: tiene clave `flow`, o `blueprint` con `modules`
  - si no matchea ninguna pero tiene forma de workflow (alguna de: `steps`, `trigger`, `actions`, `workflow`) → `automation_unknown`
  - si no tiene forma de workflow → se ignora (es un JSON/YAML de config normal, no un hallazgo de discovery)
- `classification` se deriva así:
  - `is_python or is_node`, sin `automation` → `"code"`
  - `automation` no vacío, sin `is_python`/`is_node` → `"automation"`
  - ambos → `"mixed"`
  - ninguno → `"empty"`

### Manejo de errores

Un archivo que no parsea (JSON corrupto, binario con extensión falsa) se **ignora para ese archivo específico** y no aborta la clasificación del resto del target — mismo criterio que ya usa `run_static_checks` para no confundir "no pude leer esto" con un hallazgo real.

## Integración en `graph.py`

`run_project_audit(name, path, router)` llama a `classify_target(path)` como primer paso:

- **`classification == "automation"`:** short-circuit. No llama a `run_static_checks` ni `router.chat_ensemble`. Devuelve:
  ```python
  {
      "name": name,
      "path": path,
      "discovery": discovery_result,
      "score": score_automation_detected(discovery_result),
  }
  ```
  `score_automation_detected` (nuevo, en `agents/scoring.py`) devuelve un `Score` con `production_readiness = "NOT_ASSESSED"` y una nota de que el motor de procesos no está implementado todavía.

- **`classification in ("code", "mixed", "empty")`:** sigue el pipeline actual sin cambios de comportamiento (static checks + ensemble), pero el `discovery_result` se agrega siempre al resultado final bajo la clave `"discovery"`. Para `"mixed"`, esto deja constancia de qué automatizaciones se detectaron sin auditar, aunque el código sí se audite normalmente.

Este cambio afecta a los tres callers (`audit_project` MCP tool, `audit_github_repo`, batch) porque todos pasan por `run_project_audit`. No hace falta tocar `mcp_server.py`.

## Reporte (`generate_report_node`)

Cada bloque de proyecto en el `.md` generado agrega una línea de clasificación (`Clasificación: code|automation|mixed|empty`) y, si `discovery.automation` no está vacío, lista formato + archivo de cada automatización detectada. No cambia el formato de las secciones existentes de score/ensemble para el caso `"code"`.

## Testing

`tests/test_discovery.py`, casos:
- Repo solo-Python → `"code"`, `is_python=True`
- Repo solo-Node → `"code"`, `is_node=True`
- Repo mixto (Python + JSON de n8n) → `"mixed"`, ambos campos pobladas
- Export puro n8n → `"automation"`, `format="n8n"`
- Export puro Zapier → `"automation"`, `format="zapier"`
- Export puro Make → `"automation"`, `format="make"`
- JSON con forma de workflow no reconocida → `"automation"`, `format="automation_unknown"`
- Carpeta vacía → `"empty"`
- JSON corrupto presente junto a código válido → no tumba la clasificación, se ignora ese archivo

`tests/test_graph.py` (extender): caso de `run_project_audit` con target de automatización pura verifica que NO se llama a `run_static_checks` ni a `router.chat_ensemble` (mock/spy), y que el resultado trae `score.production_readiness == "NOT_ASSESSED"`.

## Fuera de alcance (explícitamente, para esta fase)

- Auditar el CONTENIDO de las automatizaciones detectadas (eso es el motor de procesos, punto 7 del roadmap — depende de este discovery pero es un proyecto separado).
- Tool standalone `discover_target` invocable independientemente (ver decisión 1 — se puede agregar después si se necesita clasificar sin auditar).
- Detección vía LLM para formatos desconocidos (fallback posible a futuro si aparecen falsos negativos frecuentes en `automation_unknown`; no se justifica ahora — YAGNI).
