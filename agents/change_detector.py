import hashlib
import json
import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

SWARM_HOME = Path(os.environ.get("SWARM_HOME") or Path.home() / "swarm_auditor")
STATE_FILE = SWARM_HOME / "state.json"

IGNORED_SUBDIRS = {".git", "node_modules", "__pycache__", "venv", ".venv"}


def get_dir_hash(directory: str) -> str:
    hash_func = hashlib.md5()
    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in IGNORED_SUBDIRS]
        for name in sorted(files):
            filepath = os.path.join(root, name)
            try:
                with open(filepath, "rb") as f:
                    while chunk := f.read(8192):
                        hash_func.update(chunk)
            except OSError as e:
                logger.debug("No se pudo leer %s: %s", filepath, e)
    return hash_func.hexdigest()


def _load_state() -> dict:
    if not STATE_FILE.exists():
        return {}
    try:
        return json.loads(STATE_FILE.read_text())
    except (OSError, json.JSONDecodeError) as e:
        logger.warning("state.json corrupto o ilegible (%s), se reinicia", e)
        return {}


def has_changed(project_name: str, project_path: str) -> tuple[bool, str]:
    """Compara el hash actual contra el guardado. NO persiste el nuevo hash:
    eso es responsabilidad de commit_hash(), llamado solo tras auditar con exito.
    """
    current_hash = get_dir_hash(project_path)
    state = _load_state()
    old_hash = state.get(project_name)
    return current_hash != old_hash, current_hash


def commit_hash(project_name: str, current_hash: str) -> None:
    """Persiste el hash como 'visto'. Llamar solo despues de que la
    auditoria del proyecto termino sin errores, para que un fallo a mitad
    de camino se reintente en la siguiente corrida.
    """
    state = _load_state()
    state[project_name] = current_hash
    SWARM_HOME.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2))


if __name__ == "__main__":
    changed, h = has_changed("test", str(SWARM_HOME))
    print(changed, h)
