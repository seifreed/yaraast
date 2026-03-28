"""Error-tolerant YARA parser facade."""

from __future__ import annotations

from typing import Any

from yaraast.ast.base import YaraFile
from yaraast.ast.meta import Meta
from yaraast.ast.rules import Import, Include, Rule
from yaraast.ast.strings import PlainString
from yaraast.lexer.lexer_errors import LexerError
from yaraast.parser.error_tolerant_flow import (
    collect_rule_body,
    extract_rule_header,
    parse_rule_with_recovery,
    parse_with_recovery,
)
from yaraast.parser.error_tolerant_recovery import (
    create_rule_from_body,
    parse_condition,
    parse_import_line,
    parse_include_line,
    parse_meta_line,
    parse_section_content,
    parse_string_line,
    set_recovered_location,
)
from yaraast.parser.error_tolerant_types import ParserError, ParseResult, format_parser_errors
from yaraast.parser.parser import Parser, ParserError as BaseParserError


class ErrorTolerantParser(Parser):
    """Parser that can recover from syntax errors and continue parsing."""

    def __init__(self) -> None:
        super().__init__()
        self.errors: list[ParserError] = []
        self.recovered_rules: list[Rule] = []
        self.lines: list[str] = []

    def parse(self, text: str) -> ParseResult:
        """Parse YARA text with error recovery."""
        self.errors = []
        self.recovered_rules = []
        self.lines = text.splitlines()
        # Try normal parsing first
        try:
            ast = super().parse(text)
        except (ValueError, TypeError, AttributeError, BaseParserError, LexerError):
            # If normal parsing fails, try error-tolerant parsing
            ast = self._parse_with_recovery(text)
            return ParseResult(ast=ast, errors=self.errors, warnings=[])
        return ParseResult(ast=ast, errors=[], warnings=[])

    def parse_with_errors(self, text: str) -> tuple[YaraFile, list, list]:
        """Parse YARA text and return AST with separate error lists."""
        result = self.parse(text)
        lexer_errors = []  # Lexer errors would be handled separately
        parser_errors = result.errors
        return result.ast, lexer_errors, parser_errors

    def _parse_with_recovery(self, text: str) -> YaraFile:
        """Parse with error recovery strategies."""
        return parse_with_recovery(self)

    def _parse_import_line(self, line: str, line_num: int) -> Import | None:
        """Parse an import statement."""
        return parse_import_line(self, line, line_num)

    def _parse_include_line(self, line: str, line_num: int) -> Include | None:
        """Parse an include statement."""
        return parse_include_line(self, line, line_num)

    def _parse_rule_with_recovery(self, start_line: int) -> tuple[Rule | None, int]:
        """Parse a rule with error recovery."""
        return parse_rule_with_recovery(self, start_line)

    def _extract_rule_header(self, line: str, line_num: int) -> tuple[str | None, list[str]]:
        """Extract rule name and tags from rule declaration line."""
        return extract_rule_header(self, line, line_num)

    def _collect_rule_body(self, start_line: int, header_line: str) -> tuple[list[str], int]:
        """Collect lines that form the rule body."""
        return collect_rule_body(self, start_line, header_line)

    def _create_rule_from_body(
        self, name: str, tags: list[str], body_lines: list[str], start_line: int = 0
    ) -> Rule:
        """Create a Rule object from parsed body lines."""
        return create_rule_from_body(self, name, tags, body_lines, start_line)

    def _parse_body_line(
        self,
        rule: Rule,
        body_line: str,
        current_section: str | None,
        line_num: int,
    ) -> str | None:
        """Parse a single line from rule body. Returns updated section."""
        stripped = body_line.strip()

        if stripped.startswith("meta:"):
            return "meta"
        if stripped.startswith("strings:"):
            return "strings"
        if stripped.startswith("condition:"):
            condition_text = stripped[10:].strip()
            if condition_text:
                rule.condition = self._parse_condition(condition_text, line_num, body_line)
            return "condition"

        if not stripped or stripped.startswith("}"):
            return current_section

        self._parse_section_content(rule, stripped, current_section, line_num, body_line)
        return current_section

    def _parse_section_content(
        self,
        rule: Rule,
        line: str,
        section: str | None,
        line_num: int,
        raw_line: str,
    ) -> None:
        """Parse content based on current section."""
        parse_section_content(self, rule, line, section, line_num, raw_line)

    def _parse_meta_line(
        self, line: str, line_num: int | None = None, raw_line: str | None = None
    ) -> Meta | None:
        """Parse a meta line."""
        return parse_meta_line(self, line, line_num, raw_line)

    def _parse_string_line(
        self,
        line: str,
        line_num: int | None = None,
        raw_line: str | None = None,
    ) -> PlainString | None:
        """Parse a string definition line."""
        return parse_string_line(self, line, line_num, raw_line)

    def _parse_condition(
        self,
        condition_text: str,
        line_num: int | None = None,
        raw_line: str | None = None,
    ) -> Any:
        """Parse a condition expression (simplified)."""
        return parse_condition(self, condition_text, line_num, raw_line)

    def _set_recovered_location(
        self,
        node: Any,
        line_num: int | None,
        raw_line: str | None,
        start_col: int,
        end_col: int,
    ) -> Any:
        return set_recovered_location(self, node, line_num, raw_line, start_col, end_col)

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
        return self.errors

    def get_recovered_rules(self) -> list[Rule]:
        """Get rules that were successfully recovered."""
        return self.recovered_rules

    def has_errors(self) -> bool:
        """Check if any errors occurred."""
        return len(self.errors) > 0

    def format_errors(self) -> str:
        """Format errors for display."""
        return format_parser_errors(self.errors)
