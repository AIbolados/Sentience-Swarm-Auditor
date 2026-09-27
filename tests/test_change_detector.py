import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "agents"))

import change_detector  # noqa: E402


def test_has_changed_true_on_first_run(tmp_path, monkeypatch):
    monkeypatch.setattr(change_detector, "SWARM_HOME", tmp_path)
    monkeypatch.setattr(change_detector, "STATE_FILE", tmp_path / "state.json")

    project = tmp_path / "proj"
    project.mkdir()
    (project / "a.py").write_text("print(1)")

    changed, current_hash = change_detector.has_changed("proj", str(project))
    assert changed is True
    assert current_hash


def test_commit_hash_then_no_change(tmp_path, monkeypatch):
    monkeypatch.setattr(change_detector, "SWARM_HOME", tmp_path)
    monkeypatch.setattr(change_detector, "STATE_FILE", tmp_path / "state.json")

    project = tmp_path / "proj"
    project.mkdir()
    (project / "a.py").write_text("print(1)")

    changed, current_hash = change_detector.has_changed("proj", str(project))
    assert changed is True

    change_detector.commit_hash("proj", current_hash)

    changed_again, _ = change_detector.has_changed("proj", str(project))
    assert changed_again is False


def test_failed_audit_does_not_commit_hash(tmp_path, monkeypatch):
    """Bug fix: si la auditoria falla, el proyecto debe re-auditarse
    en la siguiente corrida en vez de marcarse como 'visto'."""
    monkeypatch.setattr(change_detector, "SWARM_HOME", tmp_path)
    monkeypatch.setattr(change_detector, "STATE_FILE", tmp_path / "state.json")

    project = tmp_path / "proj"
    project.mkdir()
    (project / "a.py").write_text("print(1)")

    changed, _ = change_detector.has_changed("proj", str(project))
    assert changed is True
    # Simula que audit_project fallo y nunca llamo a commit_hash.

    changed_again, _ = change_detector.has_changed("proj", str(project))
    assert changed_again is True
