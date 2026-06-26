"""Types for the error-tolerant parser."""

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
