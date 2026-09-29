import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "agents"))

import audit_agent  # noqa: E402
from discovery import classify_target  # noqa: E402

AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"


def _vulnerable_src_layout(root: Path) -> None:
    (root / "src").mkdir()
    (root / "src" / "app.py").write_text(
        "import os\n"
        "import subprocess\n\n"
        f'AWS_KEY = "{AWS_KEY}"\n\n\n'
        "def run(cmd):\n"
        "    subprocess.call(cmd, shell=True)\n"
        "    os.system(cmd)\n"
    )


def _static(root: Path) -> dict:
    return audit_agent.run_static_checks(str(root), classify_target(str(root)))


def test_run_tool_reports_missing_binary_as_unavailable():
    run = audit_agent.run_tool(["herramienta-que-no-existe"])
    assert run.status == "unavailable"


def test_run_tool_reports_unexpected_exit_code_as_error():
    run = audit_agent.run_tool([sys.executable, "-c", "import sys; sys.exit(2)"])
    assert run.status == "error"


def test_run_tool_ok_returns_stdout():
    run = audit_agent.run_tool([sys.executable, "-c", "print('hola')"])
    assert (run.status, run.stdout.strip()) == ("ok", "hola")


def test_src_layout_finds_secret_and_bandit_issue(tmp_path):
    """Regresion de la auditoria del 2026-09-29: antes daba {} y READY."""
    _vulnerable_src_layout(tmp_path)
    result = _static(tmp_path)

    rules = {(f["source"], f["rule"]) for f in result["findings"]}
    assert ("secrets", "aws-access-key-id") in rules
    assert any(source == "bandit" and rule.startswith("B60") for source, rule in rules)
    assert result["tools"] == {"secrets": "ok", "ruff": "ok", "bandit": "ok"}
    assert result["ok"] is True
    assert result["files_scanned"] == 1


def test_evidence_is_redacted_and_ids_are_assigned(tmp_path):
    _vulnerable_src_layout(tmp_path)
    result = _static(tmp_path)

    assert [f["id"] for f in result["findings"]] == [
        f"F{i:03d}" for i in range(1, len(result["findings"]) + 1)
    ]
    assert AWS_KEY not in json.dumps(result)
    secret = next(f for f in result["findings"] if f["source"] == "secrets")
    assert "[REDACTED:aws-access-key-id]" in secret["evidence"]


def test_ruff_reports_syntax_errors(tmp_path):
    (tmp_path / "bad.py").write_text("def broken(:\n    pass\n")
    findings, status = audit_agent._run_ruff(str(tmp_path))
    assert status == "ok"
    assert findings and all(f["source"] == "ruff" for f in findings)


def test_bandit_clean_project_is_ok_and_empty(tmp_path):
    (tmp_path / "ok.py").write_text("def add(a, b):\n    return a + b\n")
    assert audit_agent._run_bandit(str(tmp_path)) == ([], "ok")


def test_missing_bandit_lowers_ok_but_secrets_still_run(tmp_path, monkeypatch):
    _vulnerable_src_layout(tmp_path)
    real_resolve = audit_agent._resolve_binary
    monkeypatch.setattr(
        audit_agent, "_resolve_binary", lambda name: None if name == "bandit" else real_resolve(name)
    )
    result = _static(tmp_path)

    assert result["tools"]["bandit"] == "unavailable"
    assert result["ok"] is False
    assert any(f["rule"] == "aws-access-key-id" for f in result["findings"])


def test_automation_only_target_runs_secrets_and_no_code_tools(tmp_path):
    (tmp_path / "flow.json").write_text(json.dumps({
        "name": "wf",
        "nodes": [{"type": "n8n-nodes-base.httpRequest", "parameters": {"key": AWS_KEY}}],
        "connections": {},
    }))
    result = _static(tmp_path)

    assert result["tools"] == {"secrets": "ok"}
    assert [f["rule"] for f in result["findings"]] == ["aws-access-key-id"]


NPM_SAMPLE = json.dumps({
    "vulnerabilities": {
        "lodash": {
            "name": "lodash", "severity": "high",
            "via": [{"title": "Prototype Pollution", "url": "https://example.test/adv"}],
        },
        "minimist": {"name": "minimist", "severity": "moderate", "via": ["lodash"]},
    }
})


def test_parse_npm_audit_maps_severities():
    findings, status = audit_agent._parse_npm_audit(NPM_SAMPLE, "package.json")
    assert status == "ok"
    by_rule = {f["rule"]: f for f in findings}
    assert by_rule["npm:lodash"]["severity"] == "high"
    assert by_rule["npm:lodash"]["message"].startswith("lodash: Prototype Pollution")
    assert by_rule["npm:minimist"]["severity"] == "medium"
    assert by_rule["npm:minimist"]["file"] == "package.json"


def test_parse_npm_audit_without_lockfile_is_skipped_not_error():
    payload = json.dumps({"error": {"code": "ENOLOCK", "summary": "sin lockfile"}})
    assert audit_agent._parse_npm_audit(payload, "package.json") == ([], "skipped")


def test_parse_npm_audit_invalid_json_is_error():
    assert audit_agent._parse_npm_audit("no es json", "package.json") == ([], "error")


def test_node_project_runs_npm_audit_per_manifest(tmp_path, monkeypatch):
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "index.js").write_text("console.log(1)\n")
    calls = []

    def fake_run_tool(cmd, cwd=None, timeout=60, ok_codes=(0, 1)):
        calls.append((cmd[0], cwd))
        return audit_agent.ToolRun("ok", NPM_SAMPLE)

    monkeypatch.setattr(audit_agent, "run_tool", fake_run_tool)
    result = _static(tmp_path)

    assert calls == [("npm", str(tmp_path))]
    assert result["tools"] == {"secrets": "ok", "npm_audit": "ok"}
    assert {f["rule"] for f in result["findings"]} == {"npm:lodash", "npm:minimist"}
