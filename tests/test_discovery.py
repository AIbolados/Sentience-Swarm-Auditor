import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "agents"))

import discovery  # noqa: E402
from discovery import classify_target, coverage_from_discovery, summarize_discovery  # noqa: E402

N8N = json.dumps({"name": "Sync CRM", "nodes": [{"type": "n8n-nodes-base.httpRequest"}], "connections": {}})
ZAPIER = json.dumps({"zaps": [{"title": "Alta de cliente"}]})
MAKE = json.dumps({"name": "Escenario", "flow": [{"id": 1, "module": "gateway:CustomWebHook"}]})


def _write(root: Path, rel: str, content: str = "") -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def test_python_src_layout_is_detected(tmp_path):
    _write(tmp_path, "src/pkg/mod.py", "x = 1\n")
    result = classify_target(str(tmp_path))
    assert result["classification"] == "code"
    assert result["is_python"] is True
    assert result["languages"] == {"python": 1}


def test_node_project_is_detected_via_package_json(tmp_path):
    _write(tmp_path, "package.json", "{}")
    _write(tmp_path, "src/index.js", "console.log(1)\n")
    result = classify_target(str(tmp_path))
    assert result["is_node"] is True
    assert result["languages"] == {"javascript": 1}
    assert "package.json" in result["manifests"]


def test_go_only_repo_is_code_but_not_python_or_node(tmp_path):
    _write(tmp_path, "cmd/main.go", "package main\n")
    result = classify_target(str(tmp_path))
    assert result["classification"] == "code"
    assert (result["is_python"], result["is_node"]) == (False, False)
    assert result["languages"] == {"go": 1}


def test_n8n_export_two_levels_deep(tmp_path):
    _write(tmp_path, "workflows/n8n/sync.json", N8N)
    result = classify_target(str(tmp_path))
    assert result["classification"] == "automation"
    [match] = result["automation"]
    assert match == {
        "format": "n8n", "file": "workflows/n8n/sync.json",
        "workflow_name": "Sync CRM", "confidence": "high",
    }


def test_zapier_and_make_exports(tmp_path):
    _write(tmp_path, "zap.json", ZAPIER)
    _write(tmp_path, "make.json", MAKE)
    formats = {m["format"]: m for m in classify_target(str(tmp_path))["automation"]}
    assert formats["zapier"]["workflow_name"] == "Alta de cliente"
    assert formats["make"]["workflow_name"] == "Escenario"


def test_unknown_workflow_shape_needs_two_hint_keys_and_is_low_confidence(tmp_path):
    _write(tmp_path, "custom.json", json.dumps({"trigger": {}, "steps": []}))
    _write(tmp_path, "solo_steps.json", json.dumps({"steps": []}))
    result = classify_target(str(tmp_path))
    assert [(m["file"], m["format"], m["confidence"]) for m in result["automation"]] == [
        ("custom.json", "automation_unknown", "low")
    ]


def test_ci_and_api_specs_are_not_automation(tmp_path):
    _write(tmp_path, "azure.json", json.dumps({"trigger": ["main"], "steps": [], "pool": {}}))
    _write(tmp_path, "openapi.json", json.dumps({"openapi": "3.0.0", "paths": {}, "actions": []}))
    _write(tmp_path, "package.json", json.dumps({"nodes": [], "connections": {}}))
    assert classify_target(str(tmp_path))["automation"] == []


def test_mixed_repo(tmp_path):
    _write(tmp_path, "app/main.py", "x = 1\n")
    _write(tmp_path, "exports/flow.json", N8N)
    assert classify_target(str(tmp_path))["classification"] == "mixed"


def test_empty_directory(tmp_path):
    result = classify_target(str(tmp_path))
    assert result["classification"] == "empty"
    assert result["files"] == []


def test_corrupt_json_is_ignored_without_breaking_classification(tmp_path):
    _write(tmp_path, "main.py", "x = 1\n")
    _write(tmp_path, "broken.json", "{no es json")
    result = classify_target(str(tmp_path))
    assert result["classification"] == "code"
    assert result["automation"] == []


def test_ignored_dirs_and_symlinks_are_not_followed(tmp_path):
    _write(tmp_path, "main.py", "x = 1\n")
    _write(tmp_path, "node_modules/dep/index.js", "1\n")
    os.symlink(tmp_path, tmp_path / "loop")
    result = classify_target(str(tmp_path))
    assert result["files"] == ["main.py"]


def test_file_cap_marks_truncated(tmp_path, monkeypatch):
    monkeypatch.setattr(discovery, "MAX_FILES", 3)
    for i in range(5):
        _write(tmp_path, f"f{i}.py", "x = 1\n")
    result = classify_target(str(tmp_path))
    assert len(result["files"]) == 3
    assert result["truncated"] is True


def test_depth_cap_marks_truncated(tmp_path, monkeypatch):
    monkeypatch.setattr(discovery, "MAX_DEPTH", 1)
    _write(tmp_path, "x.py", "1\n")
    _write(tmp_path, "a/y.py", "1\n")
    _write(tmp_path, "a/b/z.py", "1\n")
    result = classify_target(str(tmp_path))
    assert sorted(result["files"]) == ["a/y.py", "x.py"]
    assert result["truncated"] is True


def test_coverage_reports_what_is_not_analyzed(tmp_path):
    _write(tmp_path, "a.py", "x = 1\n")
    _write(tmp_path, "b.go", "package main\n")
    _write(tmp_path, "c.ts", "export {}\n")
    _write(tmp_path, "wf.json", N8N)
    coverage = coverage_from_discovery(classify_target(str(tmp_path)), files_scanned=4)
    assert coverage["analyzed_languages"] == ["python", "typescript"]
    assert coverage["unanalyzed_languages"] == ["go"]
    assert coverage["partial_languages"] == ["typescript"]
    assert coverage["unaudited_automation"] == ["n8n:wf.json"]
    assert coverage["files_scanned"] == 4


def test_summarize_drops_the_file_list(tmp_path):
    _write(tmp_path, "a.py", "x = 1\n")
    summary = summarize_discovery(classify_target(str(tmp_path)))
    assert "files" not in summary
    assert summary["files_total"] == 1


def test_build_vendor_and_dist_directories_are_not_ignored(tmp_path):
    for name in ("build", "vendor", "dist"):
        _write(tmp_path, f"{name}/config.js", "x\n")
    assert set(classify_target(str(tmp_path))["files"]) == {
        "build/config.js", "vendor/config.js", "dist/config.js",
    }


def test_vue_and_svelte_count_as_partially_analyzed_javascript(tmp_path):
    _write(tmp_path, "App.vue", "<template></template>\n")
    result = classify_target(str(tmp_path))
    assert result["languages"] == {"javascript": 1}
