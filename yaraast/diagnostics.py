"""Stable diagnostics shared by analyzers and reporters."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
import hashlib
from typing import Any


class Severity(StrEnum):
    """Diagnostic severities understood by all reporters."""

    ERROR = "error"
    WARNING = "warning"
    INFO = "info"
    NOTE = "note"


def compute_fingerprint(
    diagnostic_id: str,
    source_path: str,
    structural_key: str,
) -> str:
    """Create a line-independent fingerprint for a diagnostic."""
    value = "\x1f".join((diagnostic_id, source_path, structural_key))
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


@dataclass(frozen=True)
class SourceFix:
    """Replacement over a source range."""

    start_line: int
    start_column: int
    end_line: int
    end_column: int
    replacement: str

    def to_dict(self) -> dict[str, Any]:
        """Return the JSON-compatible fix representation."""
        return {
            "start_line": self.start_line,
            "start_column": self.start_column,
            "end_line": self.end_line,
            "end_column": self.end_column,
            "replacement": self.replacement,
        }


@dataclass(frozen=True)
class Diagnostic:
    """One stable, location-aware analysis diagnostic."""

    diagnostic_id: str
    severity: Severity
    category: str
    message: str
    source_path: str
    start_line: int
    start_column: int
    end_line: int
    end_column: int
    rule_name: str | None = None
    rule_id: str | None = None
    dialect: str = "yara"
    target: str | None = None
    fingerprint: str = ""
    help_uri: str | None = None
    suggestion: str | None = None
    fix: SourceFix | None = None

    def __post_init__(self) -> None:
        """Normalize enum values and fill the stable fingerprint."""
        if not isinstance(self.severity, Severity):
            object.__setattr__(self, "severity", Severity(self.severity))
        if not self.fingerprint:
            subject = self.rule_id or self.rule_name or self.message
            object.__setattr__(
                self,
                "fingerprint",
                compute_fingerprint(self.diagnostic_id, self.source_path, subject),
            )

    def to_dict(self) -> dict[str, Any]:
        """Return the version-one wire representation."""
        return {
            "diagnostic_id": self.diagnostic_id,
            "severity": self.severity.value,
            "category": self.category,
            "message": self.message,
            "source_path": self.source_path,
            "start_line": self.start_line,
            "start_column": self.start_column,
            "end_line": self.end_line,
            "end_column": self.end_column,
            "rule_name": self.rule_name,
            "rule_id": self.rule_id,
            "dialect": self.dialect,
            "target": self.target,
            "fingerprint": self.fingerprint,
            "help_uri": self.help_uri,
            "suggestion": self.suggestion,
            "fix": self.fix.to_dict() if self.fix else None,
        }


@dataclass(frozen=True)
class DiagnosticResult:
    """Collection of diagnostics produced by one check operation."""

    diagnostics: tuple[Diagnostic, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        object.__setattr__(self, "diagnostics", tuple(self.diagnostics))

    @property
    def errors(self) -> tuple[Diagnostic, ...]:
        """Return error diagnostics."""
        return tuple(item for item in self.diagnostics if item.severity is Severity.ERROR)

    @property
    def warnings(self) -> tuple[Diagnostic, ...]:
        """Return warning diagnostics."""
        return tuple(item for item in self.diagnostics if item.severity is Severity.WARNING)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible result."""
        counts = {severity.value: 0 for severity in Severity}
        for diagnostic in self.diagnostics:
            counts[diagnostic.severity.value] += 1
        return {
            "diagnostics": [diagnostic.to_dict() for diagnostic in self.diagnostics],
            "counts": counts,
        }
