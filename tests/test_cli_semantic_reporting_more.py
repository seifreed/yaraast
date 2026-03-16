"""More tests for semantic reporting helpers."""

from __future__ import annotations

from pathlib import Path

from yaraast.ast.base import Location
from yaraast.cli import semantic_reporting as sr
from yaraast.types.semantic_validator_core import ValidationError, ValidationResult


def _build_result(*, valid: bool, with_warning: bool = False) -> ValidationResult:
    result = ValidationResult(is_valid=valid)
    if not valid:
        err = ValidationError(
            "bad call",
            location=Location(line=2, column=3, file="sample.yar"),
            suggestion="fix it",
        )
        result.errors.append(err)
    if with_warning:
        warn = ValidationError(
            "suspicious",
            location=Location(line=5, column=1, file="sample.yar"),
            severity="warning",
            suggestion="review",
        )
        result.warnings.append(warn)
    return result


def test_semantic_reporting_error_paths_and_summary(capsys) -> None:
    path = Path("sample.yar")

    sr.display_validation_start(path, quiet=False)
    sr.display_parse_failure(path)
    sr.display_processing_error(path, RuntimeError("boom"))

    out_err = capsys.readouterr()
    assert "Validating sample.yar" in out_err.out
    assert "Failed to parse sample.yar" in out_err.err
    assert "Error processing sample.yar: boom" in out_err.err

    sr.display_summary(total_files=2, total_errors=1, total_warnings=3)
    out = capsys.readouterr().out
    assert "Validated 2 file(s)" in out
    assert "Found 1 errors" in out
    assert "Found 3 warnings" in out


def test_semantic_reporting_text_and_json_outputs(tmp_path: Path, capsys) -> None:
    path = Path("rule.yar")

    ok = _build_result(valid=True, with_warning=False)
    sr.display_text_results(path, ok, show_warnings=True, show_suggestions=True, quiet=False)
    assert "All checks passed" in capsys.readouterr().out

    warn_only = _build_result(valid=True, with_warning=True)
    sr.display_text_results(path, warn_only, show_warnings=True, show_suggestions=True, quiet=False)
    output = capsys.readouterr().out
    assert "Valid with 1 warnings" in output
    assert "Suggestion: review" in output

    bad = _build_result(valid=False, with_warning=True)
    sr.display_text_results(path, bad, show_warnings=False, show_suggestions=True, quiet=False)
    captured = capsys.readouterr()
    assert "bad call" in captured.err
    assert "Suggestion: fix it" in captured.out
    assert ": 1 errors" in captured.out

    results = [
        {
            "file": "rule.yar",
            "is_valid": False,
            "errors": [
                {
                    "message": "bad",
                    "location": {"file": "rule.yar", "line": 7, "column": 8},
                    "suggestion": "repair",
                },
            ],
            "warnings": [
                {
                    "message": "warn",
                    "location": {"file": "rule.yar", "line": 9, "column": 1},
                    "suggestion": "inspect",
                },
            ],
        },
    ]

    txt_path = tmp_path / "semantic.txt"
    json_path = tmp_path / "semantic.json"

    sr.write_output_file(txt_path, results, format="text")
    text_content = txt_path.read_text(encoding="utf-8")
    assert "ERROR: bad" in text_content
    assert "WARNING: warn" in text_content
    assert "Location: rule.yar:7:8" in text_content
    assert "Suggestion: repair" in text_content

    sr.write_output_file(json_path, results, format="json")
    assert '"file": "rule.yar"' in json_path.read_text(encoding="utf-8")

    sr.emit_json_results(results)
    assert '"is_valid": false' in capsys.readouterr().out.lower()
