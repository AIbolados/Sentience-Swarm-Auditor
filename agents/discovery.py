"""Discovery: mapea el target ANTES de auditarlo.

Un unico recorrido del arbol (recursivo, sin seguir symlinks, con topes de
profundidad y cantidad de archivos) produce: la lista de archivos, los
lenguajes presentes, los manifiestos, las automatizaciones detectadas
(n8n/Zapier/Make/desconocido) y la COBERTURA: que se va a analizar y que no.

Diferencia clave con el diseno del 2026-09-28: NO hay short-circuit. Una
clasificacion equivocada ya no puede ocultar un secreto, porque el escaneo
de secretos corre siempre sobre todo el arbol; la clasificacion solo decide
que analizadores adicionales aplican y que limitaciones se reportan.
"""

import json
import logging
import os
from typing import TypedDict

try:
    import yaml
except ImportError:  # pyyaml es dependencia; degrada a solo-JSON si falta
    yaml = None

logger = logging.getLogger(__name__)

IGNORE_DIRS = {
    ".git", ".npm", ".cache", ".local", ".nvm", "node_modules",
    ".gemini", ".cursor", ".vscode", "venv", ".venv", ".aider",
    "__pycache__", ".tox", ".mypy_cache", ".ruff_cache", ".pytest_cache",
    "dist", "build", "target", "vendor", ".next", ".terraform",
}

MAX_DEPTH = 8
MAX_FILES = 5000
MAX_PARSE_BYTES = 1_000_000
MAX_PARSE_FILES = 300

CODE_EXTENSIONS: dict[str, str] = {
    ".py": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".go": "go", ".java": "java", ".kt": "kotlin", ".rs": "rust", ".rb": "ruby",
    ".php": "php", ".cs": "csharp", ".c": "c", ".cpp": "cpp", ".swift": "swift",
    ".sh": "shell", ".sql": "sql", ".tf": "terraform",
}

# Lenguaje -> herramientas con las que hoy se analiza.
ANALYZERS: dict[str, tuple[str, ...]] = {
    "python": ("ruff", "bandit"),
    "javascript": ("npm_audit",),
    "typescript": ("npm_audit",),
}
# Analizadores que NO inspeccionan el codigo (solo dependencias).
PARTIAL_ANALYSIS = {"javascript", "typescript"}

PY_MANIFESTS = {"requirements.txt", "pyproject.toml", "Pipfile", "setup.py"}
MANIFEST_NAMES = PY_MANIFESTS | {
    "package.json", "go.mod", "Cargo.toml", "pom.xml", "build.gradle",
    "Gemfile", "composer.json", "Dockerfile",
}
STRUCTURED_SUFFIXES = {".json", ".yaml", ".yml"}
NON_WORKFLOW_FILENAMES = {
    "package.json", "package-lock.json", "composer.json", "composer.lock",
    "tsconfig.json", "jsconfig.json", "pyrightconfig.json", ".eslintrc.json",
    "deno.json", "renovate.json", "docker-compose.yml", "docker-compose.yaml",
    "pnpm-lock.yaml", "mkdocs.yml",
}
# Claves que delatan configuracion conocida (CI, OpenAPI, compose...), no un workflow de negocio.
NON_WORKFLOW_KEYS = {
    "openapi", "swagger", "jobs", "services", "paths", "compilerOptions",
    "dependencies", "scripts", "pool", "stages", "script", "on",
}
WORKFLOW_HINT_KEYS = {
    "steps", "trigger", "triggers", "actions", "workflow", "workflows", "nodes", "connections",
}

_PARSE_ERRORS: tuple[type[BaseException], ...] = (OSError, ValueError, RecursionError) + (
    (yaml.YAMLError,) if yaml else ()
)


class AutomationMatch(TypedDict):
    format: str  # n8n | zapier | make | automation_unknown
    file: str
    workflow_name: str | None
    confidence: str  # high | low


class DiscoveryResult(TypedDict):
    classification: str  # code | automation | mixed | empty
    is_python: bool
    is_node: bool
    languages: dict[str, int]
    manifests: list[str]
    automation: list[AutomationMatch]
    files: list[str]
    truncated: bool


def _walk(root: str) -> tuple[list[str], bool]:
    files: list[str] = []
    truncated = False
    stack: list[tuple[str, int]] = [(root, 0)]
    while stack:
        current, depth = stack.pop()
        try:
            with os.scandir(current) as iterator:
                entries = sorted(iterator, key=lambda entry: entry.name)
        except OSError as e:
            logger.warning("No se pudo listar %s: %s", current, e)
            continue
        for entry in entries:
            if entry.is_symlink():
                continue
            if entry.is_dir(follow_symlinks=False):
                if entry.name in IGNORE_DIRS:
                    continue
                if depth + 1 > MAX_DEPTH:
                    truncated = True
                    continue
                stack.append((entry.path, depth + 1))
            elif entry.is_file(follow_symlinks=False):
                if len(files) >= MAX_FILES:
                    return sorted(files), True
                files.append(os.path.relpath(entry.path, root).replace(os.sep, "/"))
    return sorted(files), truncated


def _load_structured(path: str):
    try:
        if os.path.getsize(path) > MAX_PARSE_BYTES:
            return None
        with open(path, encoding="utf-8", errors="replace") as handle:
            text = handle.read()
        if path.lower().endswith(".json"):
            return json.loads(text)
        return yaml.safe_load(text) if yaml else None
    except _PARSE_ERRORS as e:
        logger.debug("Archivo estructurado ilegible %s: %s", path, e)
        return None


def _detect_format(data: dict) -> tuple[str, str, str | None] | None:
    """(formato, confianza, nombre) o None si no parece un workflow."""
    name = data["name"] if isinstance(data.get("name"), str) else None

    nodes = data.get("nodes")
    if (
        isinstance(nodes, list)
        and isinstance(data.get("connections"), dict)
        and any(isinstance(n, dict) and "n8n" in str(n.get("type", "")) for n in nodes)
    ):
        return "n8n", "high", name

    zaps = data.get("zaps")
    if isinstance(zaps, list):
        first = zaps[0] if zaps and isinstance(zaps[0], dict) else {}
        title = first.get("title")
        return "zapier", "high", title if isinstance(title, str) else name

    flow = data.get("flow")
    blueprint = data.get("blueprint")
    if not flow and isinstance(blueprint, dict):
        flow = blueprint.get("flow")
    if isinstance(flow, list) and any(isinstance(m, dict) and "module" in m for m in flow):
        return "make", "high", name

    keys = set(data)
    if not keys & NON_WORKFLOW_KEYS and len(keys & WORKFLOW_HINT_KEYS) >= 2:
        return "automation_unknown", "low", name
    return None


def _detect_automation(root: str, files: list[str]) -> tuple[list[AutomationMatch], bool]:
    candidates = [
        rel for rel in files
        if os.path.splitext(rel)[1].lower() in STRUCTURED_SUFFIXES
        and os.path.basename(rel) not in NON_WORKFLOW_FILENAMES
    ]
    matches: list[AutomationMatch] = []
    for rel in candidates[:MAX_PARSE_FILES]:
        data = _load_structured(os.path.join(root, rel))
        if not isinstance(data, dict):
            continue
        detected = _detect_format(data)
        if detected:
            fmt, confidence, name = detected
            matches.append(AutomationMatch(
                format=fmt, file=rel, workflow_name=name, confidence=confidence,
            ))
    return matches, len(candidates) > MAX_PARSE_FILES


def classify_target(path: str) -> DiscoveryResult:
    files, truncated = _walk(path)
    languages: dict[str, int] = {}
    manifests: list[str] = []
    for rel in files:
        base = os.path.basename(rel)
        language = CODE_EXTENSIONS.get(os.path.splitext(base)[1].lower())
        if language:
            languages[language] = languages.get(language, 0) + 1
        if base in MANIFEST_NAMES:
            manifests.append(rel)

    is_python = languages.get("python", 0) > 0 or any(
        os.path.basename(m) in PY_MANIFESTS for m in manifests
    )
    is_node = any(os.path.basename(m) == "package.json" for m in manifests)
    automation, parse_truncated = _detect_automation(path, files)

    has_code = bool(languages) or is_python or is_node
    if has_code and automation:
        classification = "mixed"
    elif has_code:
        classification = "code"
    elif automation:
        classification = "automation"
    else:
        classification = "empty"

    return DiscoveryResult(
        classification=classification, is_python=is_python, is_node=is_node,
        languages=languages, manifests=manifests, automation=automation,
        files=files, truncated=truncated or parse_truncated,
    )


def coverage_from_discovery(discovery: DiscoveryResult, files_scanned: int) -> dict:
    """Que se analiza y que NO. Nunca se calla una limitacion."""
    languages = discovery["languages"]
    return {
        "analyzed_languages": sorted(lang for lang in languages if lang in ANALYZERS),
        "unanalyzed_languages": sorted(lang for lang in languages if lang not in ANALYZERS),
        "partial_languages": sorted(lang for lang in languages if lang in PARTIAL_ANALYSIS),
        "unaudited_automation": [
            f"{m['format']}:{m['file']}" for m in discovery["automation"]
        ][:10],
        "truncated": discovery["truncated"],
        "files_total": len(discovery["files"]),
        "files_scanned": files_scanned,
    }


def summarize_discovery(discovery: DiscoveryResult) -> dict:
    """Version para reportes/MCP: sin la lista completa de archivos."""
    summary = {k: v for k, v in discovery.items() if k != "files"}
    summary["files_total"] = len(discovery["files"])
    return summary
