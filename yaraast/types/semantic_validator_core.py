"""Core types for semantic validation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from yaraast.ast.base import Location


@dataclass
class ValidationError:
    """Rich validation error with location information."""

    message: str
    location: Location | None = None
    error_type: str = "semantic"
    severity: str = "error"
    suggestion: str | None = None

    def __str__(self) -> str:
        if self.location:
            return f"{self.location.file}:{self.location.line}:{self.location.column}: {self.severity}: {self.message}"
        return f"{self.severity}: {self.message}"

    def to_dict(self) -> dict[str, Any]:
        result = {
            "message": self.message,
            "error_type": self.error_type,
            "severity": self.severity,
        }
        if self.location:
            result["location"] = {
                "file": self.location.file,
                "line": self.location.line,
                "column": self.location.column,
            }
        if self.suggestion:
            result["suggestion"] = self.suggestion
        return result


@dataclass
class ValidationResult:
    """Result of semantic validation."""

    is_valid: bool = True
    errors: list[ValidationError] = field(default_factory=list)
    warnings: list[ValidationError] = field(default_factory=list)

    def add_error(
        self,
        message: str,
        location: Location | None = None,
        suggestion: str | None = None,
    ) -> None:
        error = ValidationError(message, location, "semantic", "error", suggestion)
        self.errors.append(error)
        self.is_valid = False

    def add_warning(
        self,
        message: str,
        location: Location | None = None,
        suggestion: str | None = None,
    ) -> None:
        warning = ValidationError(message, location, "semantic", "warning", suggestion)
        self.warnings.append(warning)

    def combine(self, other: ValidationResult) -> None:
        self.errors.extend(other.errors)
        self.warnings.extend(other.warnings)
        if not other.is_valid:
            self.is_valid = False

    @property
    def total_issues(self) -> int:
        return len(self.errors) + len(self.warnings)
