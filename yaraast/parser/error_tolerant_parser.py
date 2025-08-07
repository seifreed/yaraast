"""Error-tolerant YARA parser that can recover from syntax errors."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import BooleanLiteral, Identifier
from yaraast.ast.meta import Meta
from yaraast.ast.rules import Import, Include, Rule
from yaraast.ast.strings import PlainString
from yaraast.parser.better_parser import Parser


@dataclass
class ParserError:
    """Represents a parsing error."""

    message: str
    line: int
    column: int
    context: str = ""

    def format_error(self) -> str:
        """Format the error for display."""
        if self.context:
            return f"Line {self.line}:{self.column}: {self.message}\n  {self.context}"
        return f"Line {self.line}:{self.column}: {self.message}"

    severity: str = "error"  # error, warning


@dataclass
class ParseResult:
    """Result of error-tolerant parsing."""

    ast: YaraFile
    errors: list[ParserError] = field(default_factory=list)
    warnings: list[ParserError] = field(default_factory=list)


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
            return ParseResult(ast=ast, errors=[], warnings=[])
        except (ValueError, TypeError, AttributeError):
            # If normal parsing fails, try error-tolerant parsing
            ast = self._parse_with_recovery(text)
            return ParseResult(ast=ast, errors=self.errors, warnings=[])

    def parse_with_errors(self, text: str) -> tuple[YaraFile, list, list]:
        """Parse YARA text and return AST with separate error lists."""
        result = self.parse(text)
        lexer_errors = []  # Lexer errors would be handled separately
        parser_errors = result.errors
        return result.ast, lexer_errors, parser_errors

    def _parse_with_recovery(self, text: str) -> YaraFile:
        """Parse with error recovery strategies."""
        yara_file = YaraFile()
        yara_file.imports = []
        yara_file.includes = []
        yara_file.rules = []

        # Parse line by line for recovery
        i = 0
        while i < len(self.lines):
            line = self.lines[i].strip()

            # Skip empty lines and comments
            if not line or line.startswith(("//", "/*")):
                i += 1
                continue

            # Try to parse imports
            if line.startswith("import "):
                import_stmt = self._parse_import_line(line, i)
                if import_stmt:
                    yara_file.imports.append(import_stmt)
                i += 1
                continue

            # Try to parse includes
            if line.startswith("include "):
                include_stmt = self._parse_include_line(line, i)
                if include_stmt:
                    yara_file.includes.append(include_stmt)
                i += 1
                continue

            # Try to parse rules
            if line.startswith("rule "):
                rule, lines_consumed = self._parse_rule_with_recovery(i)
                if rule:
                    yara_file.rules.append(rule)
                    self.recovered_rules.append(rule)
                i += lines_consumed
                continue

            # Unknown line
            self._add_error(f"Unexpected line: {line}", i, 0)
            i += 1

        return yara_file

    def _parse_import_line(self, line: str, line_num: int) -> Import | None:
        """Parse an import statement."""
        match = re.match(r'import\s+"([^"]+)"', line)
        if match:
            return Import(match.group(1))

        match = re.match(r"import\s+(\w+)", line)
        if match:
            return Import(match.group(1))

        self._add_error(f"Invalid import statement: {line}", line_num, 0)
        return None

    def _parse_include_line(self, line: str, line_num: int) -> Include | None:
        """Parse an include statement."""
        match = re.match(r'include\s+"([^"]+)"', line)
        if match:
            return Include(match.group(1))

        self._add_error(f"Invalid include statement: {line}", line_num, 0)
        return None

    def _parse_rule_with_recovery(self, start_line: int) -> tuple[Rule | None, int]:
        """Parse a rule with error recovery."""
        line = self.lines[start_line].strip()

        # Extract rule name
        match = re.match(r"rule\s+(\w+)\s*(?:\:\s*([^{]+))?\s*{?", line)
        if not match:
            self._add_error(f"Invalid rule declaration: {line}", start_line, 0)
            return None, 1

        rule_name = match.group(1)
        tags_str = match.group(2)

        # Parse tags
        tags = []
        if tags_str:
            tags = [tag.strip() for tag in tags_str.split()]

        # Find rule body
        rule_body_lines = []
        brace_count = 1 if "{" in line else 0
        current_line = start_line + 1

        while current_line < len(self.lines) and (
            brace_count > 0 or (brace_count == 0 and not rule_body_lines)
        ):
            body_line = self.lines[current_line]
            rule_body_lines.append(body_line)

            # Count braces
            brace_count += body_line.count("{") - body_line.count("}")

            if brace_count == 0 and "}" in body_line:
                break

            current_line += 1

        # Parse rule sections
        rule = Rule(rule_name, BooleanLiteral(True))
        rule.tags = tags
        rule.meta = []
        rule.strings = []

        # Simple section parsing
        section = None
        for body_line in rule_body_lines:
            stripped = body_line.strip()

            if stripped.startswith("meta:"):
                section = "meta"
                continue
            if stripped.startswith("strings:"):
                section = "strings"
                continue
            if stripped.startswith("condition:"):
                section = "condition"
                # Extract condition
                condition_text = stripped[10:].strip()
                if condition_text:
                    rule.condition = self._parse_condition(condition_text)
                continue

            # Parse content based on section
            if section == "meta" and stripped and not stripped.startswith("}"):
                meta_item = self._parse_meta_line(stripped)
                if meta_item:
                    rule.meta.append(meta_item)
            elif section == "strings" and stripped and not stripped.startswith("}"):
                string_def = self._parse_string_line(stripped)
                if string_def:
                    rule.strings.append(string_def)
            elif section == "condition" and stripped and not stripped.startswith("}"):
                rule.condition = self._parse_condition(stripped)

        return rule, current_line - start_line + 1

    def _parse_meta_line(self, line: str) -> Meta | None:
        """Parse a meta line."""
        match = re.match(r'(\w+)\s*=\s*"([^"]*)"', line)
        if match:
            return Meta(match.group(1), match.group(2))

        match = re.match(r"(\w+)\s*=\s*(\d+)", line)
        if match:
            return Meta(match.group(1), int(match.group(2)))

        match = re.match(r"(\w+)\s*=\s*(true|false)", line, re.IGNORECASE)
        if match:
            return Meta(match.group(1), match.group(2).lower() == "true")

        return None

    def _parse_string_line(self, line: str) -> PlainString | None:
        """Parse a string definition line."""
        # Plain string
        match = re.match(r'(\$\w+)\s*=\s*"([^"]*)"', line)
        if match:
            return PlainString(match.group(1), match.group(2))

        # Hex string (simplified)
        match = re.match(r"(\$\w+)\s*=\s*{([^}]+)}", line)
        if match:
            # For now, treat as plain string
            return PlainString(match.group(1), match.group(2))

        # Regex string (simplified)
        match = re.match(r"(\$\w+)\s*=\s*/([^/]+)/", line)
        if match:
            # For now, treat as plain string
            return PlainString(match.group(1), match.group(2))

        return None

    def _parse_condition(self, condition_text: str) -> Any:
        """Parse a condition expression (simplified)."""
        condition_text = condition_text.strip()

        # Simple conditions
        if condition_text == "true":
            return BooleanLiteral(True)
        if condition_text == "false":
            return BooleanLiteral(False)
        if re.match(r"\$\w+", condition_text):
            return Identifier(condition_text)
        # For complex conditions, return as identifier for now
        return Identifier(condition_text)

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
        if not self.errors:
            return "No errors"

        lines = []
        for error in self.errors:
            lines.append(f"{error.severity.upper()}: {error.message}")
            lines.append(f"  at line {error.line}, column {error.column}")
            if error.context:
                lines.append(f"  > {error.context}")
                lines.append(f"    {' ' * error.column}^")
            lines.append("")

        return "\n".join(lines)
