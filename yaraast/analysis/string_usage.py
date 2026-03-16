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
        if self.current_rule and self.in_condition:
            subject = (
                node.subject
                if isinstance(node.subject, str)
                else getattr(node.subject, "name", None)
            )
            if subject:
                self.used_strings[self.current_rule].add(self._normalize_string_id(subject))
        self.visit(node.range)

    def visit_for_of_expression(self, node: ForOfExpression) -> None:
        # Handle "them" keyword
        if isinstance(node.string_set, Identifier) and node.string_set.name == "them":
            # "them" refers to all defined strings
            if self.current_rule:
                self.used_strings[self.current_rule].update(
                    self.defined_strings[self.current_rule],
                )
        else:
            self.visit(node.string_set)

        if node.condition:
            self.visit(node.condition)

    def visit_of_expression(self, node: OfExpression) -> None:
        self.visit(node.quantifier)

        # Handle special case of "them" keyword
        if (
            hasattr(node.string_set, "name")
            and node.string_set.name == "them"
            and self.current_rule
        ):
            # "them" refers to all defined strings in the current rule
            self.used_strings[self.current_rule].update(
                self.defined_strings[self.current_rule],
            )
        else:
            self.visit(node.string_set)

    def visit_set_expression(self, node: SetExpression) -> None:
        for element in node.elements:
            self.visit(element)
