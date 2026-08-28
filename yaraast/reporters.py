"""Stdlib reporters for the diagnostic schema."""

from __future__ import annotations

from collections.abc import Iterable
import json
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

from yaraast.diagnostics import Diagnostic, DiagnosticResult, Severity


class Reporter:
    """Base reporter that can render or write a diagnostic result."""

    def render(self, result: DiagnosticResult) -> str:
        """Render a result as text."""
        raise NotImplementedError

    def write(self, result: DiagnosticResult, path: str | Path) -> None:
        """Write a rendered result to a UTF-8 file."""
        Path(path).write_text(self.render(result), encoding="utf-8")


class TextReporter(Reporter):
    """Render one diagnostic per line for terminals and logs."""

    def render(self, result: DiagnosticResult) -> str:
        lines = []
        for diagnostic in result.diagnostics:
            line = (
                f"{diagnostic.source_path}:{diagnostic.start_line}:"
                f"{diagnostic.start_column}: {diagnostic.severity.value}: "
                f"{diagnostic.diagnostic_id}: {diagnostic.message}"
            )
            if diagnostic.suggestion:
                line += f" ({diagnostic.suggestion})"
            lines.append(line)
        return "\n".join(lines)


class JsonReporter(Reporter):
    """Render the complete diagnostic result as JSON."""

    def render(self, result: DiagnosticResult) -> str:
        return json.dumps(result.to_dict(), indent=2, sort_keys=True) + "\n"


class NdjsonReporter(Reporter):
    """Render one diagnostic object per JSON line."""

    def render(self, result: DiagnosticResult) -> str:
        return "".join(
            json.dumps(diagnostic.to_dict(), sort_keys=True) + "\n"
            for diagnostic in result.diagnostics
        )


class SarifReporter(Reporter):
    """Render SARIF 2.1.0 results."""

    def render(self, result: DiagnosticResult) -> str:
        rules = _sarif_rules(result.diagnostics)
        payload = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "yaraast", "rules": rules}},
                    "results": [_sarif_result(item) for item in result.diagnostics],
                }
            ],
        }
        return json.dumps(payload, indent=2, sort_keys=True) + "\n"


class JunitReporter(Reporter):
    """Render diagnostics as a JUnit test suite."""

    def render(self, result: DiagnosticResult) -> str:
        suite = ElementTree.Element(
            "testsuite",
            {
                "name": "yaraast",
                "tests": str(len(result.diagnostics)),
                "failures": str(len(result.errors)),
            },
        )
        for diagnostic in result.diagnostics:
            case = ElementTree.SubElement(
                suite,
                "testcase",
                {"classname": diagnostic.source_path, "name": diagnostic.diagnostic_id},
            )
            if diagnostic.severity is Severity.ERROR:
                failure = ElementTree.SubElement(case, "failure", {"message": diagnostic.message})
                failure.text = diagnostic.message
            elif diagnostic.severity is Severity.WARNING:
                warning = ElementTree.SubElement(case, "system-out")
                warning.text = diagnostic.message
        return ElementTree.tostring(suite, encoding="unicode") + "\n"


REPORTERS: dict[str, type[Reporter]] = {
    "text": TextReporter,
    "json": JsonReporter,
    "ndjson": NdjsonReporter,
    "sarif": SarifReporter,
    "junit": JunitReporter,
}


def _sarif_rules(diagnostics: Iterable[Diagnostic]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    rules = []
    for diagnostic in diagnostics:
        if diagnostic.diagnostic_id in seen:
            continue
        seen.add(diagnostic.diagnostic_id)
        rule: dict[str, Any] = {
            "id": diagnostic.diagnostic_id,
            "shortDescription": {"text": diagnostic.message},
        }
        if diagnostic.help_uri:
            rule["helpUri"] = diagnostic.help_uri
        rules.append(rule)
    return rules


def _sarif_result(diagnostic: Diagnostic) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ruleId": diagnostic.diagnostic_id,
        "level": _sarif_level(diagnostic.severity),
        "message": {"text": diagnostic.message},
        "fingerprints": {"yaraast/v1": diagnostic.fingerprint},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": diagnostic.source_path},
                    "region": {
                        "startLine": diagnostic.start_line,
                        "startColumn": diagnostic.start_column,
                        "endLine": diagnostic.end_line,
                        "endColumn": diagnostic.end_column,
                    },
                }
            }
        ],
    }
    if diagnostic.suggestion:
        result["message"]["text"] += f" ({diagnostic.suggestion})"
    if diagnostic.fix:
        result["fixes"] = [
            {
                "description": {"text": diagnostic.suggestion or "Apply fix"},
                "artifactChanges": [
                    {
                        "artifactLocation": {"uri": diagnostic.source_path},
                        "replacements": [
                            {
                                "deletedRegion": {
                                    "startLine": diagnostic.fix.start_line,
                                    "startColumn": diagnostic.fix.start_column,
                                    "endLine": diagnostic.fix.end_line,
                                    "endColumn": diagnostic.fix.end_column,
                                },
                                "insertedContent": {"text": diagnostic.fix.replacement},
                            }
                        ],
                    }
                ],
            }
        ]
    return result


def _sarif_level(severity: Severity) -> str:
    if severity is Severity.ERROR:
        return "error"
    if severity is Severity.WARNING:
        return "warning"
    return "note"
