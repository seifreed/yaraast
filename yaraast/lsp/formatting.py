"""Formatting provider for YARA Language Server."""

from __future__ import annotations

import logging
from typing import Any

from lsprotocol.types import Position, Range, TextEdit

from yaraast.codegen.formatting import FormattingConfig
from yaraast.codegen.generator import CodeGenerator
from yaraast.codegen.options import GeneratorOptions
from yaraast.lsp.parsing import parse_for_lsp
from yaraast.lsp.runtime import LspRuntime
from yaraast.lsp.safe_handler import lsp_safe_handler
from yaraast.lsp.structure import find_rule_end, find_rule_line
from yaraast.lsp.utf16 import utf8_col_to_utf16

logger = logging.getLogger(__name__)


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
        self._validate_document_request(text, uri)
        return self._format_document_safe(text, uri)

    @lsp_safe_handler(default=[])
    def _format_document_safe(self, text: str, uri: str | None = None) -> list[TextEdit]:
        ast = self._parse(text, uri)
        formatted_text = self._generator(uri).generate(ast)

        lines = text.split("\n")
        doc_range = Range(
            start=Position(line=0, character=0),
            end=_line_end_position(lines, max(len(lines) - 1, 0)),
        )

        return [TextEdit(range=doc_range, new_text=formatted_text)]

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
        self._validate_document_request(text, uri)
        if not isinstance(start, Position):
            msg = "format range start must be an LSP Position"
            raise TypeError(msg)
        if not isinstance(end, Position):
            msg = "format range end must be an LSP Position"
            raise TypeError(msg)
        return self._format_range_safe(text, start, end, uri)

    @lsp_safe_handler(default=[])
    def _format_range_safe(
        self,
        text: str,
        start: Position,
        end: Position,
        uri: str | None = None,
    ) -> list[TextEdit]:
        ast = self._parse(text, uri)
        rule_info = self._find_enclosing_rule(text, ast, start, end)
        if rule_info is None:
            return self._format_document_safe(text, uri)

        rule, rule_range = rule_info
        formatted_rule = self._generator(uri).generate(rule)
        return [TextEdit(range=rule_range, new_text=formatted_rule)]

    def _validate_document_request(self, text: str, uri: str | None) -> None:
        if not isinstance(text, str):
            msg = "Formatting text must be a string"
            raise TypeError(msg)
        if uri is not None and not isinstance(uri, str):
            msg = "Formatting URI must be a string or None"
            raise TypeError(msg)

    def _generator(self, uri: str | None) -> CodeGenerator:
        return CodeGenerator(options=GeneratorOptions(advanced=self._config(uri)))

    def _config(self, uri: str | None) -> FormattingConfig:
        if self.runtime is None:
            return FormattingConfig()
        config_data = dict(self.runtime.config.code_formatting)
        return FormattingConfig.from_dict(config_data)

    def _parse(self, text: str, uri: str | None) -> Any:
        return parse_for_lsp(text, uri=uri, runtime=self.runtime)

    def _find_enclosing_rule(
        self, text: str, ast: Any, start: Position, end: Position
    ) -> tuple[Any, Range] | None:
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
                    end=_line_end_position(lines, rule_end),
                ),
            )
        return None


def _line_end_position(lines: list[str], line_num: int) -> Position:
    if not lines or line_num < 0 or line_num >= len(lines):
        return Position(line=0, character=0)
    return Position(
        line=line_num,
        character=utf8_col_to_utf16(lines[line_num], len(lines[line_num])),
    )
