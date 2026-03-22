"""Formatting provider for YARA Language Server."""

from __future__ import annotations

from lsprotocol.types import Position, Range, TextEdit

from yaraast.codegen.advanced_generator import AdvancedCodeGenerator
from yaraast.codegen.formatting import FormattingConfig
from yaraast.lsp.parsing import parse_for_lsp
from yaraast.lsp.runtime import LspRuntime
from yaraast.lsp.structure import find_rule_end, find_rule_line


class FormattingProvider:
    """Provides configurable code formatting functionality."""

    def __init__(self, runtime: LspRuntime | None = None) -> None:
        self.runtime = runtime

    def format_document(self, text: str, uri: str | None = None) -> list[TextEdit]:
        """
        Format the entire document.

        Args:
            text: The YARA source code
            uri: Optional document URI to read runtime formatting settings

        Returns:
            List of text edits to apply
        """
        try:
            ast = self._parse(text, uri)
            formatted_text = self._generator(uri).generate(ast)

            lines = text.split("\n")
            doc_range = Range(
                start=Position(line=0, character=0),
                end=Position(line=max(len(lines) - 1, 0), character=len(lines[-1]) if lines else 0),
            )

            return [TextEdit(range=doc_range, new_text=formatted_text)]
        except Exception:
            return []

    def format_range(
        self,
        text: str,
        start: Position,
        end: Position,
        uri: str | None = None,
    ) -> list[TextEdit]:
        """
        Format a specific range in the document.

        Strategy:
        - if the range falls inside a rule, replace that full rule only
        - otherwise, fall back to whole-document formatting
        """
        try:
            ast = self._parse(text, uri)
            rule_info = self._find_enclosing_rule(text, ast, start, end)
            if rule_info is None:
                return self.format_document(text, uri)

            rule, rule_range = rule_info
            formatted_rule = self._generator(uri).generate(rule)
            return [TextEdit(range=rule_range, new_text=formatted_rule)]
        except Exception:
            return []

    def _generator(self, uri: str | None) -> AdvancedCodeGenerator:
        return AdvancedCodeGenerator(self._config(uri))

    def _config(self, uri: str | None) -> FormattingConfig:
        if self.runtime is None:
            return FormattingConfig()
        config_data = dict(self.runtime.config.code_formatting)
        return FormattingConfig.from_dict(config_data)

    def _parse(self, text: str, uri: str | None):
        return parse_for_lsp(text, uri=uri, runtime=self.runtime)

    def _find_enclosing_rule(self, text: str, ast, start: Position, end: Position):
        lines = text.split("\n")
        for rule in getattr(ast, "rules", []):
            rule_line = find_rule_line(lines, rule.name)
            if rule_line < 0:
                continue
            rule_end = find_rule_end(lines, rule_line)
            if rule_end < 0 or rule_end >= len(lines):
                continue
            if start.line < rule_line or end.line > rule_end:
                continue
            return (
                rule,
                Range(
                    start=Position(line=rule_line, character=0),
                    end=Position(line=rule_end, character=len(lines[rule_end])),
                ),
            )
        return None
