"""Facade for structural authoring helpers used by LSP code actions."""

from __future__ import annotations

from lsprotocol.types import Range

import yaraast.lsp.authoring_actions as authoring_actions
from yaraast.codegen.advanced_generator import AdvancedCodeGenerator
from yaraast.codegen.generator import CodeGenerator
from yaraast.lsp.authoring_actions import StructuralEdit
from yaraast.lsp.authoring_support import (
    canonical_config,
    get_rule_context,
    modifier_start,
    normalize_modifiers,
)
from yaraast.lsp.structure import find_rule_end, find_rule_start, find_section_line
from yaraast.optimization.rule_optimizer import RuleOptimizer
from yaraast.parser.parser import Parser
from yaraast.serialization.roundtrip_serializer import RoundTripSerializer
from yaraast.shared.ast_analysis import ASTDiffer, ASTFormatter

__all__ = ["AuthoringActions", "StructuralEdit"]


class AuthoringActions:
    """Produce structural edits for LSP code actions."""

    def __init__(self) -> None:
        self._parser = Parser()
        self._generator = CodeGenerator()
        self._advanced_generator = AdvancedCodeGenerator(canonical_config())
        self._ast_formatter = ASTFormatter()
        self._optimizer = RuleOptimizer()
        self._roundtrip = RoundTripSerializer()
        self._differ = ASTDiffer()

    def create_missing_string(
        self,
        text: str,
        identifier: str,
        diagnostic_range: Range,
    ) -> StructuralEdit | None:
        return authoring_actions.create_missing_string(text, identifier, diagnostic_range)

    def normalize_string_modifiers(self, text: str, selection: Range) -> StructuralEdit | None:
        return authoring_actions.normalize_string_modifiers(text, selection)

    def convert_plain_string_to_hex(self, text: str, selection: Range) -> StructuralEdit | None:
        return authoring_actions.convert_plain_string_to_hex(text, selection)

    def optimize_rule(self, text: str, selection: Range) -> StructuralEdit | None:
        return authoring_actions.optimize_rule(self, text, selection)

    def roundtrip_rewrite_rule(self, text: str, selection: Range) -> StructuralEdit | None:
        return authoring_actions.roundtrip_rewrite_rule(self, text, selection)

    def deduplicate_identical_strings(self, text: str, selection: Range) -> StructuralEdit | None:
        return authoring_actions.deduplicate_identical_strings(self, text, selection)

    def sort_strings_by_identifier(self, text: str, selection: Range) -> StructuralEdit | None:
        return authoring_actions.sort_strings_by_identifier(self, text, selection)

    def sort_meta_by_key(self, text: str, selection: Range) -> StructuralEdit | None:
        return authoring_actions.sort_meta_by_key(self, text, selection)

    def sort_tags_alphabetically(self, text: str, selection: Range) -> StructuralEdit | None:
        return authoring_actions.sort_tags_alphabetically(self, text, selection)

    def canonicalize_rule_structure(self, text: str, selection: Range) -> StructuralEdit | None:
        return authoring_actions.canonicalize_rule_structure(self, text, selection)

    def pretty_print_rule(self, text: str, selection: Range) -> StructuralEdit | None:
        return authoring_actions.pretty_print_rule(self, text, selection)

    def expand_of_them(self, text: str, selection: Range) -> StructuralEdit | None:
        return authoring_actions.rewrite_of_them(
            self,
            text,
            selection,
            mode="expand",
            title="Expand 'of them' to explicit set",
        )

    def compress_of_them(self, text: str, selection: Range) -> StructuralEdit | None:
        return authoring_actions.rewrite_of_them(
            self,
            text,
            selection,
            mode="compress",
            title="Compress explicit set to 'of them'",
        )

    # Compatibility wrappers for existing tests; implementation lives in support modules.
    def _find_rule_start(self, lines: list[str], current_line: int) -> int:
        return find_rule_start(lines, current_line)

    def _get_rule_context(self, text: str, current_line: int):
        return get_rule_context(text, current_line)

    def _find_rule_end(self, lines: list[str], start_line: int) -> int:
        return find_rule_end(lines, start_line)

    def _find_section_line(self, lines: list[str], section_header: str, start_line: int) -> int:
        return find_section_line(lines, section_header, start_line)

    def _modifier_start(self, body: str) -> int | None:
        return modifier_start(body)

    def _normalize_modifiers(self, modifiers: list[str]) -> list[str]:
        return normalize_modifiers(modifiers)
