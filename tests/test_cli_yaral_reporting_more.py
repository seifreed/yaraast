"""More tests for YARA-L reporting helpers (no mocks)."""

from __future__ import annotations

from types import SimpleNamespace

import click
import pytest

from yaraast.cli import yaral_reporting as yr


class _Issue:
    def __init__(self, severity: str, message: str, section: str) -> None:
        self.severity = severity
        self.message = message
        self.section = section

    def __str__(self) -> str:
        return f"[{self.section}] {self.message}"


def test_yaral_validation_results_json_and_text(capsys) -> None:
    ast = SimpleNamespace(rules=[1, 2])
    errors = [_Issue("error", "bad condition", "condition")]
    warnings = [_Issue("warning", "weak pattern", "events")]

    yr.display_validation_results("f.yaral", ast, errors, warnings, strict=False, output_json=True)
    out_json = capsys.readouterr().out
    assert '"file": "f.yaral"' in out_json
    assert '"valid": false' in out_json.lower()

    yr.display_validation_results("f.yaral", ast, [], [], strict=False, output_json=False)
    out_ok = capsys.readouterr().out
    assert "YARA-L file is valid (2 rules)" in out_ok

    yr.display_validation_results("f.yaral", ast, errors, warnings, strict=False, output_json=False)
    captured = capsys.readouterr()
    assert "Validation Warnings" in captured.out
    assert "Validation Errors" in captured.err
    assert "has 1 errors and 1 warnings" in captured.err

    with pytest.raises(click.Abort):
        yr.display_validation_results("f.yaral", ast, [], warnings, strict=True, output_json=False)


def test_yaral_reporting_misc_helpers(tmp_path, capsys) -> None:
    out_file = tmp_path / "generated.yaral"
    yr.write_output(str(out_file), "rule x {}", "saved")
    assert out_file.read_text() == "rule x {}"
    assert "saved" in capsys.readouterr().out

    yr.write_output(None, "inline", "ignored")
    assert "inline" in capsys.readouterr().out

    yr.display_parse_mode(enhanced=True)
    yr.display_parse_mode(enhanced=False)
    yr.display_parse_success(3)
    yr.display_generate_success(2)

    stats = SimpleNamespace(
        rules_optimized=1,
        conditions_simplified=2,
        events_optimized=3,
        redundant_checks_removed=4,
        indexes_suggested=5,
        time_windows_optimized=6,
    )
    yr.display_optimize_preview(stats)
    yr.display_optimize_stats(stats)
    yr.display_semantic_compare(True)
    yr.display_semantic_compare(False)
    yr.display_structural_compare(["diff1", "diff2"])
    yr.display_structural_compare([])

    validator = SimpleNamespace(
        VALID_UDM_FIELDS={"principal": ["user", "ip", "host", "id", "name", "email"]}
    )
    yr.display_info(examples=True, fields=False, functions=False, validator=validator)
    yr.display_info(examples=False, fields=True, functions=False, validator=validator)
    yr.display_info(examples=False, fields=False, functions=True, validator=validator)
    yr.display_info(examples=False, fields=False, functions=False, validator=validator)

    out = capsys.readouterr().out
    assert "Using enhanced YARA-L parser" in out
    assert "Using standard YARA-L parser" in out
    assert "Successfully parsed 3 rules" in out
    assert "Optimization Preview" in out
    assert "Optimization Statistics" in out
    assert "semantically equivalent" in out
    assert "semantically different" in out
    assert "Files have differences" in out
    assert "same structure" in out
    assert "Example YARA-L Rules" in out
    assert "Valid UDM Field Namespaces" in out
    assert "Available Aggregation Functions" in out
    assert "YARA-L Support Status" in out
