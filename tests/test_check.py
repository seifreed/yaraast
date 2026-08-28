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

    result = CliRunner().invoke(cli, ["check", str(tmp_path), "--format", "json", "--fail-on", "warning"])

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["diagnostics"][0]["diagnostic_id"] == "YARA103"


def test_check_passes_default_gate_for_warnings() -> None:
    from yaraast.diagnostics import Diagnostic, DiagnosticResult

    result = DiagnosticResult((Diagnostic("YARA103", Severity.WARNING, "policy", "warning", "a.yar", 1, 1, 1, 1),))
    assert check_passes(result, ProjectConfig(Path(".")))
