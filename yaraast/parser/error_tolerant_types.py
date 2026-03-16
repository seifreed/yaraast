"""Types and formatting helpers for the error-tolerant parser."""

from __future__ import annotations

from dataclasses import dataclass, field

from yaraast.ast.base import YaraFile


@dataclass
class ParserError:
    """Represents a parsing error."""

    message: str
    line: int
    column: int
    context: str = ""
    severity: str = "error"

    def format_error(self) -> str:
        """Format the error for display."""
        if self.context:
            return f"Line {self.line}:{self.column}: {self.message}\n  {self.context}"
        return f"Line {self.line}:{self.column}: {self.message}"


@dataclass
class ParseResult:
    """Result of error-tolerant parsing."""

    ast: YaraFile
    errors: list[ParserError] = field(default_factory=list)
    warnings: list[ParserError] = field(default_factory=list)


def format_parser_errors(errors: list[ParserError]) -> str:
    """Format a collection of parser errors for display."""
    if not errors:
        return "No errors"

    lines: list[str] = []
    for error in errors:
        lines.append(f"{error.severity.upper()}: {error.message}")
        lines.append(f"  at line {error.line}, column {error.column}")
        if error.context:
            lines.append(f"  > {error.context}")
            lines.append(f"    {' ' * error.column}^")
        lines.append("")
    return "\n".join(lines)
