import base64
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "agents"))

import secrets_scan  # noqa: E402
from secrets_scan import read_context, redact, scan_secrets  # noqa: E402

# Construida en runtime: el repo no contiene literales con forma de clave real.
AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"


def _scan(tmp_path, name, content):
    (tmp_path / name).write_text(content)
    return scan_secrets(str(tmp_path), [name])


def _jwt(payload: dict) -> str:
    def enc(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")

    return f"{enc({'alg': 'HS256', 'typ': 'JWT'})}.{enc(payload)}.{'s' * 20}"


def test_detects_aws_access_key_with_line_number(tmp_path):
    result = _scan(tmp_path, "app.py", f'import os\nKEY = "{AWS_KEY}"\n')
    [finding] = result["findings"]
    assert finding["rule"] == "aws-access-key-id"
    assert finding["severity"] == "critical"
    assert finding["tier"] == "deterministic"
    assert (finding["file"], finding["line"]) == ("app.py", 2)
    assert result["files_scanned"] == 1


def test_placeholders_are_not_findings(tmp_path):
    content = (
        'DATABASE_URL = "postgres://user:<password>@host/db"\n'
        'password = "changeme-changeme"\n'
    )
    assert _scan(tmp_path, "settings.py", content)["findings"] == []


def test_real_connection_string_is_flagged(tmp_path):
    content = 'DB = "postgres://admin:S3cr3tPassw0rd!@db.internal:5432/app"\n'
    [finding] = _scan(tmp_path, "settings.py", content)["findings"]
    assert finding["rule"] == "db-connection-string"
    assert finding["severity"] == "high"


def test_high_entropy_generic_assignment_is_heuristic(tmp_path):
    [finding] = _scan(tmp_path, "cfg.py", 'api_key = "xK9fT2qLm8ZpR4vB"\n')["findings"]
    assert finding["rule"] == "generic-secret-assignment"
    assert finding["tier"] == "heuristic"


def test_low_entropy_generic_assignment_is_ignored(tmp_path):
    assert _scan(tmp_path, "cfg.py", 'token = "aaaaaaaaaaaaaaaa"\n')["findings"] == []


def test_supabase_service_role_jwt_is_critical(tmp_path):
    [finding] = _scan(tmp_path, "cfg.js", f'const k = "{_jwt({"role": "service_role"})}"\n')["findings"]
    assert finding["rule"] == "supabase-service-role-jwt"
    assert finding["severity"] == "critical"


def test_supabase_anon_jwt_is_public_by_design(tmp_path):
    assert _scan(tmp_path, "cfg.js", f'const k = "{_jwt({"role": "anon"})}"\n')["findings"] == []


def test_redact_removes_the_secret_value():
    redacted = redact(f'KEY = "{AWS_KEY}"')
    assert AWS_KEY not in redacted
    assert "[REDACTED:aws-access-key-id]" in redacted


def test_tracked_env_file_is_flagged_without_reading_its_content(tmp_path):
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    (tmp_path / ".env").write_text("SECRET_TOKEN=valor-que-no-debe-leerse-123456\n")
    subprocess.run(["git", "add", ".env"], cwd=tmp_path, check=True)

    result = scan_secrets(str(tmp_path), [".env"])

    assert [f["rule"] for f in result["findings"]] == ["env-file-tracked"]
    assert "valor-que-no-debe-leerse" not in json.dumps(result)


def test_untracked_env_file_outside_git_is_ignored_and_unread(tmp_path):
    (tmp_path / ".env").write_text(f"KEY={AWS_KEY}\n")
    result = scan_secrets(str(tmp_path), [".env"])
    assert result["findings"] == []
    assert result["files_scanned"] == 0


def test_env_example_is_scanned_normally(tmp_path):
    result = _scan(tmp_path, ".env.example", f"AWS_KEY={AWS_KEY}\n")
    assert [f["rule"] for f in result["findings"]] == ["aws-access-key-id"]


def test_binary_and_oversize_files_are_skipped(tmp_path, monkeypatch):
    (tmp_path / "blob.bin").write_bytes(b"\x00\x01" + AWS_KEY.encode())
    (tmp_path / "big.txt").write_text(AWS_KEY * 10)
    monkeypatch.setattr(secrets_scan, "MAX_FILE_BYTES", 10)
    result = scan_secrets(str(tmp_path), ["blob.bin", "big.txt"])
    assert result["findings"] == []
    assert result["files_scanned"] == 0
    assert result["files_skipped"] == 2


def test_read_context_redacts_and_numbers_lines(tmp_path):
    (tmp_path / "a.py").write_text(f'x = 1\nKEY = "{AWS_KEY}"\ny = 2\n')
    context = read_context(str(tmp_path), "a.py", 2)
    assert context.startswith("1: x = 1")
    assert AWS_KEY not in context
    assert "[REDACTED:aws-access-key-id]" in context


def test_read_context_blocks_path_escape(tmp_path):
    project = tmp_path / "proj"
    project.mkdir()
    (tmp_path / "outside.txt").write_text("fuera del target")
    assert read_context(str(project), "../outside.txt", 1) == ""


def test_read_context_never_reads_env_files(tmp_path):
    (tmp_path / ".env").write_text("A=1\nB=2\n")
    assert read_context(str(tmp_path), ".env", 1) == ""


def test_real_credentials_with_common_prefixes_are_not_placeholders(tmp_path):
    content = (
        'DB = "postgres://admin:mysecretpass@db.prod:5432/app"\n'
        'password = "testing-Prod-9f8e7d6c"\n'
    )
    rules = [f["rule"] for f in _scan(tmp_path, "cfg.py", content)["findings"]]
    assert "db-connection-string" in rules
    assert "generic-secret-assignment" in rules


def test_private_key_body_is_never_in_evidence(tmp_path):
    body = "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW"
    (tmp_path / "deploy.key").write_text(
        f"-----BEGIN OPENSSH PRIVATE KEY-----\n{body}\n{body}\n-----END OPENSSH PRIVATE KEY-----\n"
    )
    context = read_context(str(tmp_path), "deploy.key", 1)
    assert body not in context
    assert "[REDACTED:private-key]" in context


def test_redact_masks_base64_lines_even_without_the_header():
    blob = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj"
    assert blob not in redact(f"12: {blob}")


def test_secret_after_column_5000_is_detected(tmp_path):
    line = "x" * 6000 + f' "{AWS_KEY}"'
    [finding] = _scan(tmp_path, "bundle.js", line + "\n")["findings"]
    assert finding["rule"] == "aws-access-key-id"


def test_deterministic_secret_survives_the_heuristic_cap_and_cap_is_reported(tmp_path, monkeypatch):
    monkeypatch.setattr(secrets_scan, "MAX_FINDINGS_PER_FILE", 2)
    generic = "".join(f'api_key{i} = "xK9fT2qLm8ZpR4v{i}Bq"\n' for i in range(5))
    result = _scan(tmp_path, "cfg.py", generic + f'KEY = "{AWS_KEY}"\n')

    rules = [f["rule"] for f in result["findings"]]
    assert "aws-access-key-id" in rules
    assert rules.count("generic-secret-assignment") == 2
    assert any("tope de 2" in limit for limit in result["limits"])


def test_oversized_text_file_is_reported_as_a_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(secrets_scan, "MAX_FILE_BYTES", 10)
    (tmp_path / "big.txt").write_text("a" * 100)
    result = scan_secrets(str(tmp_path), ["big.txt"])
    assert any("big.txt" in limit for limit in result["limits"])
