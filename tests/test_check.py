"""Regression tests for repository checks."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from yaraast.check import check_passes, check_path, discover_rule_files
from yaraast.cli.main import cli
from yaraast.diagnostics import Severity
from yaraast.project_config import ProjectConfig


def test_check_discovers_excludes_and_reports_unused_strings(tmp_path: Path) -> None:
    rules = tmp_path / "rules"
    vendor = rules / "vendor"
    vendor.mkdir(parents=True)
    (rules / "sample.yar").write_text(
        'rule sample {\n strings:\n  $unused = "hello"\n condition:\n  true\n}\n',
        encoding="utf-8",
    )
    (vendor / "ignored.yar").write_text("not valid", encoding="utf-8")
    (tmp_path / "yaraast.toml").write_text(
        'exclude = ["rules/vendor/**"]\n[policy]\nforbid-unused-strings = true\n',
        encoding="utf-8",
    )
    config = ProjectConfig.load(tmp_path)

    assert discover_rule_files(rules, config) == (rules / "sample.yar",)
    result = check_path(rules, config)

    assert any(item.diagnostic_id == "YARA103" for item in result.diagnostics)
    assert all(item.source_path != "rules/vendor/ignored.yar" for item in result.diagnostics)


def test_check_cli_emits_json_and_honors_fail_on(tmp_path: Path) -> None:
    rule = tmp_path / "sample.yar"
    rule.write_text(
        'rule sample {\n strings:\n  $unused = "hello"\n condition:\n  true\n}\n',
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        cli, ["check", str(tmp_path), "--format", "json", "--fail-on", "warning"]
    )

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["diagnostics"][0]["diagnostic_id"] == "YARA103"


def test_check_passes_default_gate_for_warnings() -> None:
    from yaraast.diagnostics import Diagnostic, DiagnosticResult

    result = DiagnosticResult(
        (Diagnostic("YARA103", Severity.WARNING, "policy", "warning", "a.yar", 1, 1, 1, 1),)
    )
    assert check_passes(result, ProjectConfig(Path(".")))


def test_check_applies_metadata_limits_and_production_test_policy(tmp_path: Path) -> None:
    (tmp_path / "rules").mkdir()
    (tmp_path / "rules/sample.yar").write_text(
        'rule sample { meta: status = "production" strings: $r = /abcdef/ condition: $r }\n',
        encoding="utf-8",
    )
    (tmp_path / "yaraast.toml").write_text(
        """
[metadata]
required = ["id", "status"]
allowed-status = ["production"]
[policy]
max-regex-length = 3
require-tests-for-production = true
""",
        encoding="utf-8",
    )

    result = check_path(tmp_path)
    diagnostic_ids = {item.diagnostic_id for item in result.diagnostics}

    assert {"YARA201", "YARA301", "YARA501", "YARA502"} <= diagnostic_ids


def test_check_applies_local_suppression_only_when_reason_is_present(tmp_path: Path) -> None:
    (tmp_path / "sample.yar").write_text(
        "// yaraast: ignore YARA103 -- intentionally unused fixture string\n"
        'rule sample { strings: $unused = "hello" condition: true }\n',
        encoding="utf-8",
    )
    (tmp_path / "yaraast.toml").write_text(
        "[policy]\nforbid-unused-strings = true\n", encoding="utf-8"
    )

    result = check_path(tmp_path)

    assert not any(item.diagnostic_id == "YARA103" for item in result.diagnostics)
