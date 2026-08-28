"""Regression tests for baseline and suppression filtering."""

from __future__ import annotations

from datetime import date, timedelta
import json
from pathlib import Path

from click.testing import CliRunner

from yaraast.baseline import Baseline
from yaraast.check import apply_suppressions
from yaraast.cli.main import cli
from yaraast.diagnostics import Diagnostic, DiagnosticResult, Severity
from yaraast.project_config import ProjectConfig, Suppression


def _diagnostic() -> Diagnostic:
    return Diagnostic(
        "YARA103", Severity.WARNING, "policy", "unused", "rules/a.yar", 1, 1, 1, 2, rule_name="a"
    )


def test_baseline_round_trip_filters_known_fingerprints(tmp_path: Path) -> None:
    result = DiagnosticResult((_diagnostic(),))
    path = tmp_path / "baseline.json"
    Baseline.from_result(result).write(path, result.diagnostics)

    loaded = Baseline.load(path)

    assert loaded.filter(result).diagnostics == ()
    assert json.loads(path.read_text(encoding="utf-8"))["schema_version"] == 1


def test_expired_suppression_does_not_hide_diagnostic() -> None:
    diagnostic = _diagnostic()
    result = DiagnosticResult((diagnostic,))
    config = ProjectConfig(
        Path("."),
        suppressions=(
            Suppression("YARA103", "temporary", rule="a", expires=date.today() - timedelta(days=1)),
        ),
    )

    assert config.suppressions[0].active() is False
    assert apply_suppressions(result, config).diagnostics == (diagnostic,)


def test_active_suppression_hides_matching_rule_diagnostic() -> None:
    diagnostic = _diagnostic()
    config = ProjectConfig(
        Path("."),
        suppressions=(Suppression("YARA103", "temporary", rule="a"),),
    )

    assert apply_suppressions(DiagnosticResult((diagnostic,)), config).diagnostics == ()


def test_baseline_create_command_writes_current_diagnostics(tmp_path: Path) -> None:
    (tmp_path / "sample.yar").write_text(
        'rule sample {\n strings:\n  $unused = "hello"\n condition:\n  true\n}\n',
        encoding="utf-8",
    )
    output = tmp_path / "baseline.json"

    result = CliRunner().invoke(cli, ["baseline", "create", str(tmp_path), "-o", str(output)])

    assert result.exit_code == 0
    assert Baseline.load(output).fingerprints
