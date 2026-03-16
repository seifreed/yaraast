"""Additional tests for semantic/optimize CLI service helpers."""

from __future__ import annotations

from pathlib import Path

import pytest
from rich.console import Console

from yaraast.ast.base import Location
from yaraast.cli import optimize_reporting as orpt
from yaraast.cli.optimize_services import OptimizationAnalysis
from yaraast.cli.semantic_services import (
    _add_file_to_issues,
    _create_validation_context,
    _exit_with_appropriate_code,
)
from yaraast.types.semantic_validator_core import ValidationError


def test_add_file_to_issues_creates_location_when_missing(tmp_path: Path) -> None:
    issue = ValidationError("broken")
    file_path = tmp_path / "rule.yar"

    _add_file_to_issues([issue], file_path)

    assert issue.location is not None
    assert issue.location.file == str(file_path)
    assert issue.location.line == 1
    assert issue.location.column == 1


def test_create_validation_context_builds_real_parser_and_validator() -> None:
    context = _create_validation_context()

    assert context["parser"].__class__.__name__ == "Parser"
    assert context["validator"].__class__.__name__ == "SemanticValidator"


def test_add_file_to_issues_updates_existing_location_file(tmp_path: Path) -> None:
    issue = ValidationError("broken", location=Location(line=9, column=2, file=None))
    file_path = tmp_path / "existing.yar"

    _add_file_to_issues([issue], file_path)

    assert issue.location is not None
    assert issue.location.file == str(file_path)
    assert issue.location.line == 9
    assert issue.location.column == 2


def test_exit_with_appropriate_code_uses_error_exit() -> None:
    with pytest.raises(SystemExit) as exc:
        _exit_with_appropriate_code(1, 0, False)

    assert exc.value.code == 1


def test_optimize_reporting_emits_reporting_messages() -> None:
    console = Console(record=True, width=120)
    analysis = OptimizationAnalysis(total_issues=12, critical_issues=3)

    orpt.display_parse_failure(console)
    orpt.display_analysis(console, "Before", analysis)
    orpt.display_changes(console, [f"change {i}" for i in range(12)])
    orpt.display_no_changes(console)
    orpt.display_improvement(console, 12.5)
    orpt.display_write_start(console, "optimized.yar")
    orpt.display_write_success(console, "optimized.yar")

    output = console.export_text()
    assert "Failed to parse YARA file" in output
    assert "Before:" in output
    assert "Total issues: 12" in output
    assert "Critical issues: 3" in output
    assert "Applied 12 optimizations" in output
    assert "... and 2 more" in output
    assert "No optimizations needed" in output
    assert "Performance improved by 12.5%" in output
    assert "Writing optimized rules to optimized.yar" in output
    assert "Optimized YARA file written to optimized.yar" in output
