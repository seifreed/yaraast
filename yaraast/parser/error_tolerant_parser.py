"""Error-tolerant YARA parser facade."""

from __future__ import annotations

from typing import Any

from yaraast.ast.base import YaraFile
from yaraast.ast.rules import Import, Include, Rule
from yaraast.errors import ParseError, YaraASTError
from yaraast.parser.error_tolerant_flow import parse_with_recovery
from yaraast.parser.error_tolerant_recovery import (
    create_rule_from_body,
    parse_condition,
    parse_import_line,
    parse_include_line,
)
from yaraast.parser.error_tolerant_types import ParserError, ParseResult, format_parser_errors
from yaraast.parser.parser import Parser


class ErrorTolerantParser(Parser):
    """Parser that can recover from syntax errors and continue parsing."""

    def __init__(self, text: str | None = None) -> None:
        super().__init__()
        self.errors: list[ParserError] = []
        self.recovered_rules: list[Rule] = []
        self.lines: list[str] = []
        self._source_text = text

    def parse(self, text: str | None = None) -> ParseResult:
        """Parse YARA text with error recovery."""
        if text is None:
            text = self._source_text
        else:
            self._source_text = text
        if text is None:
            msg = "No text provided to parse"
            raise ParseError(msg)

        self.errors = []
        self.recovered_rules = []
        self.lines = text.splitlines()
        # Try normal parsing first
        try:
            ast = super().parse(text)
        except (YaraASTError, ValueError):
            # If normal parsing fails, try error-tolerant parsing
            ast = self._parse_with_recovery(text)
            return ParseResult(ast=ast, errors=list(self.errors), warnings=[])
        return ParseResult(ast=ast, errors=[], warnings=[])

    def _parse_with_recovery(self, text: str) -> YaraFile:
        """Parse with error recovery strategies."""
        return parse_with_recovery(self)

    def _parse_import_line(self, line: str, line_num: int) -> Import | None:
        """Parse an import statement."""
        return parse_import_line(self, line, line_num)

    def _parse_include_line(self, line: str, line_num: int) -> Include | None:
        """Parse an include statement."""
        return parse_include_line(self, line, line_num)

    def _create_rule_from_body(
        self, name: str, tags: list[str], body_lines: list[str], start_line: int = 0
    ) -> Rule:
        """Create a Rule object from parsed body lines."""
        return create_rule_from_body(self, name, tags, body_lines, start_line)

    def _parse_condition(
        self,
        condition_text: str | None = None,
        line_num: int | None = None,
        raw_line: str | None = None,
    ) -> Any:
        """Parse a condition expression (simplified)."""
        if condition_text is None:
            return super()._parse_condition()
        return parse_condition(self, condition_text, line_num, raw_line)

    def _add_error(self, message: str, line: int, column: int, severity: str = "error") -> None:
        """Add a parsing error."""
        context = ""
        if 0 <= line < len(self.lines):
            context = self.lines[line]

        error = ParserError(
            message=message,
            line=line + 1,  # 1-based line numbers
            column=column,
            context=context,
            severity=severity,
        )
        self.errors.append(error)

    def get_errors(self) -> list[ParserError]:
        """Get all parsing errors."""
        return list(self.errors)

    def get_recovered_rules(self) -> list[Rule]:
        """Get rules that were successfully recovered."""
        return list(self.recovered_rules)

    def has_errors(self) -> bool:
        """Check if any errors occurred."""
        return len(self.errors) > 0

    def format_errors(self) -> str:
        """Format errors for display."""
        return format_parser_errors(self.errors)
