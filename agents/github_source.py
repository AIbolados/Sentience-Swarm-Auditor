"""Trae codigo de un repo de GitHub para auditarlo localmente.

Solo clona (git clone --depth=1): nunca ejecuta codigo del repo. git
clone no corre hooks del repo clonado (los hooks post-clone son locales
al .git nuevo, y estan vacios). El directorio temporal resultante debe
borrarse siempre por el llamador (ver audit_github_repo en graph.py),
incluso si la auditoria falla a mitad de camino.
"""

import logging
import os
import re
import shutil
import subprocess
import tempfile

logger = logging.getLogger(__name__)

# owner/repo: sin protocolo, sin espacios, sin '..' que permita escapar
# del formato esperado. GitHub mismo restringe nombres a alfanumericos,
# guion, guion bajo y punto.
OWNER_REPO_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,99})/[A-Za-z0-9._-]{1,100}$")
CLONE_TIMEOUT_SECONDS = 120


class InvalidRepoSpecError(ValueError):
    pass


class CloneError(RuntimeError):
    pass


def _validate_owner_repo(owner_repo: str) -> str:
    if not OWNER_REPO_PATTERN.match(owner_repo):
        raise InvalidRepoSpecError(
            f"Formato invalido, se espera 'owner/repo' (sin protocolo ni espacios): {owner_repo!r}"
        )
    return owner_repo


def _validate_ref(ref: str) -> str:
    # Un ref que empiece con '-' podria interpretarse como un flag de
    # git (argument injection) en vez de un nombre de branch/tag.
    if ref.startswith("-"):
        raise InvalidRepoSpecError(f"ref invalido: {ref!r}")
    return ref


def _git_env_with_token(token: str | None) -> dict:
    """Inyecta el header Authorization via variables de configuracion de
    git (GIT_CONFIG_COUNT/KEY/VALUE, soportado desde git 2.31) en vez de
    ponerlo en la URL o como argumento de linea de comandos, para que el
    token no quede visible en `ps aux` de otros usuarios del sistema.

    Preserva cualquier GIT_CONFIG_* que ya exista en el entorno (por
    ejemplo, remapeos de URL o ajustes de credenciales que el sistema
    anfitrion ya inyecte) agregando la entrada al siguiente indice libre
    en vez de sobreescribir desde 0."""
    env = os.environ.copy()
    if not token:
        return env

    try:
        existing_count = int(env.get("GIT_CONFIG_COUNT", "0"))
    except ValueError:
        existing_count = 0

    env[f"GIT_CONFIG_KEY_{existing_count}"] = "http.extraHeader"
    env[f"GIT_CONFIG_VALUE_{existing_count}"] = f"Authorization: Bearer {token}"
    env["GIT_CONFIG_COUNT"] = str(existing_count + 1)
    return env


def _repo_url(owner_repo: str) -> str:
    return f"https://github.com/{owner_repo}.git"


def clone_repo_shallow(owner_repo: str, ref: str = "HEAD") -> str:
    """Clona un repo de GitHub (shallow, --depth=1) a un directorio
    temporal nuevo y devuelve su ruta absoluta.

    El token en GITHUB_TOKEN determina el acceso real: sin token solo
    funciona con repos publicos (y sujeto al rate limit anonimo); con un
    token que tenga permiso sobre el repo (propio, de tu org, o de un
    tercero que te dio acceso), tambien funciona con repos privados.

    Nota: en entornos detras de un proxy de red que fuerza su propio
    mecanismo de autenticacion hacia github.com (ej. reescritura de URL
    SSH->HTTPS con credenciales inyectadas), un clone HTTPS anonimo puede
    fallar aunque el repo sea publico. En una maquina normal sin ese
    proxy, HTTPS + GITHUB_TOKEN via header funciona directo.

    El llamador es responsable de borrar el directorio devuelto
    (shutil.rmtree) en un finally cuando termine de usarlo.
    """
    owner_repo = _validate_owner_repo(owner_repo)
    ref = _validate_ref(ref)
    token = os.environ.get("GITHUB_TOKEN")
    url = _repo_url(owner_repo)

    tmp_dir = tempfile.mkdtemp(prefix="audit-mcp-clone-")

    cmd = ["git", "clone", "--depth=1", "--single-branch"]
    if ref and ref != "HEAD":
        cmd += ["--branch", ref]
    cmd += [url, tmp_dir]

    try:
        result = subprocess.run(
            cmd,
            env=_git_env_with_token(token),
            capture_output=True, text=True, timeout=CLONE_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise CloneError(f"No se pudo clonar {owner_repo}: {e}") from e

    if result.returncode != 0:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise CloneError(f"git clone fallo para {owner_repo}@{ref}: {result.stderr.strip()}")

    return tmp_dir
