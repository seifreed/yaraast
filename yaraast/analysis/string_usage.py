"""String usage analyzer for YARA rules."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from yaraast.ast.expressions import Identifier
from yaraast.visitor.base import BaseVisitor

if TYPE_CHECKING:
    from yaraast.ast.base import YaraFile
    from yaraast.ast.conditions import AtExpression, ForOfExpression, InExpression, OfExpression
    from yaraast.ast.expressions import (
        SetExpression,
        StringCount,
        StringIdentifier,
        StringLength,
        StringOffset,
    )
    from yaraast.ast.rules import Rule
    from yaraast.ast.strings import HexString, PlainString, RegexString, StringDefinition


class StringUsageAnalyzer(BaseVisitor[None]):
    """Analyze string usage in YARA rules."""

    def __init__(self) -> None:
        self.defined_strings: dict[str, set[str]] = {}  # rule_name -> set of string ids
        self.used_strings: dict[str, set[str]] = {}  # rule_name -> set of string ids
        self.current_rule: str | None = None
        self.in_condition: bool = False

    def analyze(self, yara_file: YaraFile) -> dict[str, dict[str, Any]]:
        """Analyze string usage in YARA file."""
        self.defined_strings.clear()
        self.used_strings.clear()

        self.visit(yara_file)

        # Build analysis results
        results = {}
        for rule_name in self.defined_strings:
            defined = self.defined_strings.get(rule_name, set())
            used = self.used_strings.get(rule_name, set())

            unused = defined - used
            undefined = used - defined

            results[rule_name] = {
                "defined": list(defined),
                "used": list(used),
                "unused": list(unused),
                "undefined": list(undefined),
                "usage_rate": len(used) / len(defined) if defined else 0,
            }

        return results

    def _normalize_string_id(self, string_id: str) -> str:
        """Normalize string ids so #a/@a/!a map to $a like normal string refs."""
        return string_id if string_id.startswith("$") else f"${string_id}"

    def get_unused_strings(self, rule_name: str | None = None) -> dict[str, list[str]]:
        """Get unused strings for a specific rule or all rules."""
        if rule_name:
            defined = self.defined_strings.get(rule_name, set())
            used = self.used_strings.get(rule_name, set())
            return {rule_name: list(defined - used)}

        unused = {}
        for rule in self.defined_strings:
            defined = self.defined_strings[rule]
            used = self.used_strings.get(rule, set())
            unused_in_rule = list(defined - used)
            if unused_in_rule:
                unused[rule] = unused_in_rule

        return unused

    def get_undefined_strings(
        self,
        rule_name: str | None = None,
    ) -> dict[str, list[str]]:
        """Get undefined but used strings for a specific rule or all rules."""
        if rule_name:
            defined = self.defined_strings.get(rule_name, set())
            used = self.used_strings.get(rule_name, set())
            return {rule_name: list(used - defined)}

        undefined = {}
        for rule in self.used_strings:
            defined = self.defined_strings.get(rule, set())
            used = self.used_strings[rule]
            undefined_in_rule = list(used - defined)
            if undefined_in_rule:
                undefined[rule] = undefined_in_rule

        return undefined

    # Visitor methods
    def visit_yara_file(self, node: YaraFile) -> None:
        for rule in node.rules:
            self.visit(rule)

    def visit_rule(self, node: Rule) -> None:
        self.current_rule = node.name
        self.defined_strings[node.name] = set()
        self.used_strings[node.name] = set()
        self.in_condition = False

        # Visit strings section
        for string in node.strings:
            self.visit(string)

        # Visit condition section
        self.in_condition = True
        if node.condition:
            self.visit(node.condition)
        self.in_condition = False

        self.current_rule = None

    def visit_string_definition(self, node: StringDefinition) -> None:
        if self.current_rule:
            self.defined_strings[self.current_rule].add(node.identifier)

    def visit_plain_string(self, node: PlainString) -> None:
        self.visit_string_definition(node)

    def visit_hex_string(self, node: HexString) -> None:
        self.visit_string_definition(node)

    def visit_regex_string(self, node: RegexString) -> None:
        self.visit_string_definition(node)

    def visit_string_identifier(self, node: StringIdentifier) -> None:
        if self.current_rule and self.in_condition:
            self.used_strings[self.current_rule].add(self._normalize_string_id(node.name))

    def visit_string_count(self, node: StringCount) -> None:
        if self.current_rule and self.in_condition:
            self.used_strings[self.current_rule].add(self._normalize_string_id(node.string_id))

    def visit_string_offset(self, node: StringOffset) -> None:
        """Visit string offset expression - marks string as used."""
        if self.current_rule and self.in_condition:
            self.used_strings[self.current_rule].add(self._normalize_string_id(node.string_id))
        # Additionally visit index if present for offset expressions
        if hasattr(node, "index") and node.index:
            self.visit(node.index)

    def visit_string_length(self, node: StringLength) -> None:
        """Visit string length expression - marks string as used."""
        if self.current_rule and self.in_condition:
            self.used_strings[self.current_rule].add(self._normalize_string_id(node.string_id))
        # Additionally visit index if present for length expressions
        if hasattr(node, "index") and node.index:
            self.visit(node.index)

    def visit_at_expression(self, node: AtExpression) -> None:
        if self.current_rule and self.in_condition:
            self.used_strings[self.current_rule].add(self._normalize_string_id(node.string_id))
        self.visit(node.offset)

    def visit_in_expression(self, node: InExpression) -> None:
        if isinstance(node.subject, str):
            if self.current_rule and self.in_condition:
                self.used_strings[self.current_rule].add(self._normalize_string_id(node.subject))
        else:
            self.visit(node.subject)
        self.visit(node.range)

    def visit_for_of_expression(self, node: ForOfExpression) -> None:
        self._visit_ast_value(node.quantifier)
        self._visit_string_set_value(node.string_set)

        if node.condition:
            self.visit(node.condition)

    def visit_of_expression(self, node: OfExpression) -> None:
        self._visit_ast_value(node.quantifier)
        self._visit_string_set_value(node.string_set)

    def _visit_ast_value(self, value) -> None:
        if hasattr(value, "accept"):
            self.visit(value)
        elif isinstance(value, list):
            for item in value:
                self._visit_ast_value(item)

    def _visit_string_set_value(self, string_set) -> None:
        if isinstance(string_set, str):
            self._mark_string_set_text(string_set)
            return
        if isinstance(string_set, list):
            for item in string_set:
                if isinstance(item, str):
                    self._mark_string_set_text(item)
                else:
                    self._visit_ast_value(item)
            return
        if isinstance(string_set, Identifier) and string_set.name == "them":
            self._mark_all_current_rule_strings()
            return
        self._visit_ast_value(string_set)

    def _mark_string_set_text(self, text: str) -> None:
        if not (self.current_rule and self.in_condition):
            return
        if text == "them":
            self._mark_all_current_rule_strings()
        else:
            self.used_strings[self.current_rule].add(self._normalize_string_id(text))

    def _mark_all_current_rule_strings(self) -> None:
        if self.current_rule:
            self.used_strings[self.current_rule].update(
                self.defined_strings[self.current_rule],
            )

    def visit_set_expression(self, node: SetExpression) -> None:
        for element in node.elements:
            self.visit(element)
