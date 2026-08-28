"""Regression tests for the unified diagnostic contract and reporters."""

from __future__ import annotations

import json

from yaraast.diagnostics import Diagnostic, DiagnosticResult, Severity, SourceFix
from yaraast.reporters import (
    JsonReporter,
    JunitReporter,
    NdjsonReporter,
    SarifReporter,
    TextReporter,
)


def _result() -> DiagnosticResult:
    return DiagnosticResult(
        (
            Diagnostic(
                "YARA103",
                Severity.WARNING,
                "policy",
                "String is unused",
                "rules/a.yar",
                4,
                3,
                4,
                12,
                rule_name="sample",
                suggestion="Remove it",
                fix=SourceFix(4, 3, 4, 12, ""),
            ),
        )
    )


def test_diagnostic_fingerprint_is_independent_of_line() -> None:
    first = _result().diagnostics[0]
    moved = Diagnostic(
        first.diagnostic_id,
        first.severity,
        first.category,
        first.message,
        first.source_path,
        40,
        first.start_column,
        40,
        first.end_column,
        rule_name=first.rule_name,
    )

    assert first.fingerprint == moved.fingerprint
    assert first.to_dict()["fix"]["replacement"] == ""


def test_reporters_emit_machine_readable_formats() -> None:
    result = _result()

    assert "YARA103" in TextReporter().render(result)
    assert json.loads(JsonReporter().render(result))["counts"]["warning"] == 1
    assert json.loads(NdjsonReporter().render(result))["diagnostic_id"] == "YARA103"
    assert json.loads(SarifReporter().render(result))["version"] == "2.1.0"
    assert "testsuite" in JunitReporter().render(result)
