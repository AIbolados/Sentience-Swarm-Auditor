import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "agents"))

import github_source  # noqa: E402
import graph  # noqa: E402
from helpers import make_static_result, sample_finding, verdict_client  # noqa: E402
from llm_router import CredentialRouter, Provider  # noqa: E402

FAKE_PROVIDERS = [
    Provider("prov_a", "https://a.example/v1", "PROV_A_KEY", "model-a", "capaz"),
    Provider("prov_b", "https://b.example/v1", "PROV_B_KEY", "model-b", "rapido"),
]


def _fake_llm_client(content: str):
    client = MagicMock()
    response = MagicMock()
    response.choices = [MagicMock(message=MagicMock(content=content))]
    client.chat.completions.create.return_value = response
    return client


@pytest.fixture
def local_git_repo(tmp_path):
    repo_dir = tmp_path / "fake-remote"
    repo_dir.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repo_dir, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo_dir, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo_dir, check=True)
    (repo_dir / "main.py").write_text("print('hola')")
    subprocess.run(["git", "add", "."], cwd=repo_dir, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "inicial"], cwd=repo_dir, check=True)
    return repo_dir


@pytest.mark.asyncio
async def test_audit_github_repo_clones_audits_and_cleans_up(local_git_repo, monkeypatch):
    monkeypatch.setattr(github_source, "_repo_url", lambda owner_repo: str(local_git_repo))
    monkeypatch.setenv("PROV_A_KEY", "key-a")
    monkeypatch.setenv("PROV_B_KEY", "key-b")
    monkeypatch.setattr(graph, "run_static_checks", lambda path, discovery: make_static_result([sample_finding()]))

    client = verdict_client("real")
    router = CredentialRouter(providers=FAKE_PROVIDERS, client_factory=lambda k, u: client)

    cloned_paths = []
    original_clone = github_source.clone_repo_shallow

    def tracking_clone(owner_repo, ref="HEAD"):
        path = original_clone(owner_repo, ref)
        cloned_paths.append(path)
        return path

    monkeypatch.setattr(graph, "clone_repo_shallow", tracking_clone)

    result = await graph.audit_github_repo("someowner/somerepo", router=router)

    assert result["name"] == "someowner__somerepo"
    assert result["source"] == {"type": "github", "owner_repo": "someowner/somerepo", "ref": "HEAD"}
    assert result["panel"]["min_size"] == 2
    assert "score" in result

    assert cloned_paths
    assert not Path(cloned_paths[0]).exists(), "el clon debe borrarse siempre al terminar"


@pytest.mark.asyncio
async def test_audit_github_repo_clone_failure_returns_error(monkeypatch, tmp_path):
    nonexistent = tmp_path / "does-not-exist"
    monkeypatch.setattr(github_source, "_repo_url", lambda owner_repo: str(nonexistent))

    router = CredentialRouter(providers=FAKE_PROVIDERS)
    result = await graph.audit_github_repo("owner/repo", router=router)

    assert "error" in result
    assert result["source"]["owner_repo"] == "owner/repo"


@pytest.mark.asyncio
async def test_audit_github_repo_invalid_spec_never_touches_disk():
    router = CredentialRouter(providers=FAKE_PROVIDERS)
    with pytest.raises(github_source.InvalidRepoSpecError):
        await graph.audit_github_repo("../escape", router=router)
