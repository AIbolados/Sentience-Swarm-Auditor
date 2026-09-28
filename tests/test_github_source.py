import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "agents"))

import github_source  # noqa: E402


@pytest.mark.parametrize(
    "owner_repo",
    ["AIbolados/audit-mcp", "octocat/Hello-World", "a/b", "user.name/repo_name-2"],
)
def test_validate_owner_repo_accepts_valid_formats(owner_repo):
    assert github_source._validate_owner_repo(owner_repo) == owner_repo


@pytest.mark.parametrize(
    "owner_repo",
    [
        "https://github.com/owner/repo",
        "owner/repo/extra",
        "owner repo",
        "owner",
        "",
        "../../etc/passwd",
    ],
)
def test_validate_owner_repo_rejects_invalid_formats(owner_repo):
    with pytest.raises(github_source.InvalidRepoSpecError):
        github_source._validate_owner_repo(owner_repo)


def test_validate_ref_rejects_flag_like_values():
    with pytest.raises(github_source.InvalidRepoSpecError):
        github_source._validate_ref("--upload-pack=malicious")


def test_validate_ref_accepts_normal_branch_name():
    assert github_source._validate_ref("main") == "main"


def test_git_env_without_token_is_passthrough(monkeypatch):
    """Sin token, la funcion no debe agregar ni modificar nada del
    entorno actual (independiente de que el sandbox ya traiga sus
    propias variables GIT_CONFIG_* seteadas por otra herramienta)."""
    import os

    baseline = dict(os.environ)
    env = github_source._git_env_with_token(None)
    assert env == baseline


def test_git_env_with_token_injects_auth_header_via_config(monkeypatch):
    monkeypatch.delenv("GIT_CONFIG_COUNT", raising=False)
    env = github_source._git_env_with_token("secret-token-123")
    assert env["GIT_CONFIG_COUNT"] == "1"
    assert env["GIT_CONFIG_KEY_0"] == "http.extraHeader"
    assert "secret-token-123" in env["GIT_CONFIG_VALUE_0"]


def test_git_env_with_token_preserves_existing_git_config(monkeypatch):
    """Bug real encontrado en sandbox: el entorno ya trae GIT_CONFIG_COUNT=3
    (remapeos SSH->HTTPS, credenciales). Sobreescribir desde 0 rompia esa
    configuracion existente; debe agregarse al final."""
    monkeypatch.setenv("GIT_CONFIG_COUNT", "2")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "credential.interactive")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "false")
    monkeypatch.setenv("GIT_CONFIG_KEY_1", "url.https://github.com/.insteadOf")
    monkeypatch.setenv("GIT_CONFIG_VALUE_1", "git@github.com:")

    env = github_source._git_env_with_token("secret-token-123")

    assert env["GIT_CONFIG_COUNT"] == "3"
    assert env["GIT_CONFIG_KEY_0"] == "credential.interactive"
    assert env["GIT_CONFIG_VALUE_0"] == "false"
    assert env["GIT_CONFIG_KEY_1"] == "url.https://github.com/.insteadOf"
    assert env["GIT_CONFIG_KEY_2"] == "http.extraHeader"
    assert "secret-token-123" in env["GIT_CONFIG_VALUE_2"]


@pytest.fixture
def local_git_repo(tmp_path):
    """Un repo git real con un commit, servido por su ruta de archivo,
    para probar clone_repo_shallow sin depender de red."""
    repo_dir = tmp_path / "fake-remote"
    repo_dir.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repo_dir, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo_dir, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo_dir, check=True)
    (repo_dir / "main.py").write_text("print('hola')")
    subprocess.run(["git", "add", "."], cwd=repo_dir, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "inicial"], cwd=repo_dir, check=True)
    return repo_dir


def test_clone_repo_shallow_clones_real_repo(local_git_repo, monkeypatch):
    monkeypatch.setattr(github_source, "_repo_url", lambda owner_repo: str(local_git_repo))

    cloned_path = github_source.clone_repo_shallow("owner/repo")
    try:
        assert (Path(cloned_path) / "main.py").exists()
        assert (Path(cloned_path) / "main.py").read_text() == "print('hola')"
    finally:
        import shutil

        shutil.rmtree(cloned_path, ignore_errors=True)


def test_clone_repo_shallow_cleans_up_on_failure(monkeypatch, tmp_path):
    nonexistent = tmp_path / "does-not-exist"
    monkeypatch.setattr(github_source, "_repo_url", lambda owner_repo: str(nonexistent))

    created_dirs = []
    original_mkdtemp = github_source.tempfile.mkdtemp

    def tracking_mkdtemp(*args, **kwargs):
        d = original_mkdtemp(*args, **kwargs)
        created_dirs.append(d)
        return d

    monkeypatch.setattr(github_source.tempfile, "mkdtemp", tracking_mkdtemp)

    with pytest.raises(github_source.CloneError):
        github_source.clone_repo_shallow("owner/repo")

    assert created_dirs
    assert not Path(created_dirs[0]).exists()


def test_clone_repo_shallow_rejects_invalid_spec_before_touching_disk(tmp_path, monkeypatch):
    def fail_if_called(**kw):
        pytest.fail("no deberia crear tmp dir para un spec invalido")

    monkeypatch.setattr(github_source.tempfile, "mkdtemp", fail_if_called)
    with pytest.raises(github_source.InvalidRepoSpecError):
        github_source.clone_repo_shallow("../escape")
