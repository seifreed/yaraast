"""Dead code elimination for YARA rules."""

from __future__ import annotations

from fnmatch import fnmatchcase
from typing import TYPE_CHECKING, Any

from yaraast.ast.conditions import AtExpression, ForOfExpression, InExpression, OfExpression
from yaraast.ast.expressions import (
    BooleanLiteral,
    Identifier,
    SetExpression,
    StringCount,
    StringIdentifier,
    StringLength,
    StringLiteral,
    StringOffset,
    StringWildcard,
)
from yaraast.visitor.base import ASTTransformer

if TYPE_CHECKING:
    from yaraast.ast.base import ASTNode, YaraFile
    from yaraast.ast.rules import Rule


class DeadCodeEliminator(ASTTransformer):
    """Eliminates dead code from YARA rules."""

    def __init__(self) -> None:
        super().__init__()
        self.used_strings: set[str] = set()
        self.used_strings_by_rule: dict[str, set[str]] = {}
        self.used_rules: set[str] = set()
        self.in_condition = False
        self.current_rule: str | None = None
        self.current_rule_strings: set[str] = set()
        self.current_rule_anonymous_strings: set[str] = set()
        self.anonymous_strings_by_rule: dict[str, set[str]] = {}
        self.elimination_count = 0

    def eliminate(self, ast: YaraFile) -> tuple[YaraFile, int]:
        """Eliminate dead code from AST.

        Returns:
            Tuple of (optimized YaraFile, number of eliminations)
        """
        # Reset state
        self.used_strings.clear()
        self.used_strings_by_rule.clear()
        self.used_rules.clear()
        self.in_condition = False
        self.current_rule = None
        self.current_rule_strings = set()
        self.current_rule_anonymous_strings = set()
        self.anonymous_strings_by_rule.clear()
        self.elimination_count = 0

        # First pass: collect used strings and rules
        self._collect_usage(ast)

        # Count strings to be removed
        for rule in ast.rules:
            if rule.strings:
                used_strings = self.used_strings_by_rule.get(rule.name, set())
                anonymous_strings = self.anonymous_strings_by_rule.get(rule.name, set())
                for string_def in rule.strings:
                    if not self._is_string_identifier_used(
                        string_def.identifier,
                        used_strings,
                        anonymous_strings,
                    ):
                        self.elimination_count += 1

        # Count rules with always-false conditions
        for rule in ast.rules:
            if self._is_removable_false_rule(rule):
                self.elimination_count += 1

        # Second pass: eliminate unused code
        optimized_ast = self.visit(ast)

        return optimized_ast, self.elimination_count

    def _collect_usage(self, ast: YaraFile) -> None:
        """Collect usage information."""
        for rule in ast.rules:
            self.current_rule = rule.name
            self.current_rule_strings = {string_def.identifier for string_def in rule.strings}
            self.current_rule_anonymous_strings = {
                self._normalize_string_id(string_def.identifier)
                for string_def in rule.strings
                if getattr(string_def, "is_anonymous", False)
            }
            self.used_strings_by_rule.setdefault(rule.name, set())
            self.anonymous_strings_by_rule[rule.name] = set(self.current_rule_anonymous_strings)
            self.in_condition = True
            if rule.condition:
                self._collect_from_expression(rule.condition)
            self.in_condition = False
            self.current_rule_strings = set()
            self.current_rule_anonymous_strings = set()

    def _collect_from_expression(self, expr: ASTNode) -> None:
        """Collect usage from expression."""
        if isinstance(expr, StringIdentifier):
            self._mark_used_string(expr.name)
        elif isinstance(expr, StringWildcard):
            self._mark_used_string(expr.pattern)
        elif isinstance(expr, StringCount | StringOffset | StringLength | AtExpression):
            self._mark_used_string(expr.string_id)
        elif isinstance(expr, InExpression) and isinstance(expr.subject, str):
            self._mark_used_string(expr.subject)
        elif isinstance(expr, OfExpression | ForOfExpression):
            self._collect_string_set_value(expr.string_set)
        elif isinstance(expr, Identifier) and expr.name not in _RESERVED_IDENTIFIERS:
            # Could be a rule reference
            self.used_rules.add(expr.name)

        # Recursively collect from children
        for child in expr.children():
            self._collect_from_expression(child)

    def visit_yara_file(self, node: YaraFile) -> YaraFile:
        """Visit YaraFile and remove unused rules."""
        kept_rules = []

        for rule in node.rules:
            # Skip rules with always-false conditions
            if self._is_removable_false_rule(rule):
                continue  # Remove this rule

            # Keep only used rules (or all if we can't determine)
            if self.used_rules:
                # Determine if the rule is private (internal helper)
                is_private = False
                if hasattr(rule, "modifiers") and isinstance(
                    rule.modifiers,
                    list | tuple,
                ):
                    is_private = any(
                        getattr(m, "modifier_type", None) and m.modifier_type.value == "private"
                        for m in rule.modifiers
                    )
                # Remove only private rules that nobody references
                if not is_private or rule.name in self.used_rules:
                    kept_rules.append(self.visit(rule))
            else:
                # If no usage info, keep all rules but optimize them
                kept_rules.append(self.visit(rule))

        node.rules = kept_rules
        return node

    def _is_removable_false_rule(self, rule: Rule) -> bool:
        return (
            rule.condition is not None
            and isinstance(rule.condition, BooleanLiteral)
            and not rule.condition.value
            and rule.name not in self.used_rules
        )

    def _is_referenced_by_other_rules(self, rule_name: str) -> bool:
        """Check if this rule is referenced by any other rule."""
        return rule_name in self.used_rules

    def _has_external_references(self, rule: Rule) -> bool:
        """Check if rule references other rules."""
        if rule.condition:
            return self._contains_rule_reference(rule.condition)
        return False

    def _contains_rule_reference(self, expr: ASTNode) -> bool:
        """Check if expression contains rule reference."""
        if isinstance(expr, Identifier) and expr.name not in [
            "true",
            "false",
            "any",
            "all",
            "them",
        ]:
            # Could be a rule reference
            return True

        return any(self._contains_rule_reference(child) for child in expr.children())

    def _normalize_string_id(self, identifier: str) -> str:
        return identifier if identifier.startswith("$") else f"${identifier}"

    def _mark_used_string(self, identifier: str) -> None:
        normalized = self._normalize_string_id(identifier)
        self.used_strings.add(normalized)
        if self.current_rule:
            self.used_strings_by_rule.setdefault(self.current_rule, set()).add(normalized)

    def _mark_all_current_rule_strings(self) -> None:
        for identifier in self.current_rule_strings:
            self._mark_used_string(identifier)

    def _collect_string_set_value(self, value: Any) -> None:
        if isinstance(value, str):
            if value == "them":
                self._mark_all_current_rule_strings()
            else:
                self._mark_used_string(value)
            return
        if isinstance(value, list | tuple | set | frozenset):
            for item in value:
                self._collect_string_set_value(item)
            return
        if isinstance(value, Identifier) and value.name == "them":
            self._mark_all_current_rule_strings()
            return
        if isinstance(value, StringLiteral):
            self._mark_used_string(value.value)
            return
        if isinstance(value, StringIdentifier):
            self._mark_used_string(value.name)
            return
        if isinstance(value, StringWildcard):
            self._mark_used_string(value.pattern)
            return
        if isinstance(value, SetExpression):
            for element in value.elements:
                self._collect_string_set_value(element)

    def _is_string_identifier_used(
        self,
        identifier: str,
        used_strings: set[str] | None = None,
        anonymous_strings: set[str] | None = None,
    ) -> bool:
        """Return True when an exact or wildcard string reference keeps an identifier live."""
        patterns = self.used_strings if used_strings is None else used_strings
        normalized = self._normalize_string_id(identifier)
        anonymous = (
            self.current_rule_anonymous_strings if anonymous_strings is None else anonymous_strings
        )
        for pattern in patterns:
            if pattern == "$*":
                return True
            if pattern.endswith("*") and normalized in anonymous:
                continue
            if fnmatchcase(normalized, pattern):
                return True
        return False

    def visit_rule(self, node: Rule) -> Rule:
        """Visit Rule and remove unused strings."""
        self.current_rule = node.name

        # Remove unused strings
        if node.strings:
            used_strings = self.used_strings_by_rule.get(node.name, set())
            anonymous_strings = self.anonymous_strings_by_rule.get(node.name, set())
            kept_strings = []
            for string_def in node.strings:
                if self._is_string_identifier_used(
                    string_def.identifier,
                    used_strings,
                    anonymous_strings,
                ):
                    kept_strings.append(string_def)
            node.strings = kept_strings

        # Optimize condition
        if node.condition:
            self.in_condition = True
            node.condition = self.visit(node.condition)
            self.in_condition = False

        return node

    def visit_boolean_literal(self, node: BooleanLiteral) -> BooleanLiteral:
        """Visit BooleanLiteral - detect always true/false conditions."""
        # In a real implementation, we might eliminate rules with always-false conditions
        return node

    def visit_string_identifier(self, node: StringIdentifier) -> StringIdentifier:
        """Visit StringIdentifier - track usage."""
        if self.in_condition:
            self._mark_used_string(node.name)
        return node

    def visit_string_wildcard(self, node: StringWildcard) -> StringWildcard:
        """Visit StringWildcard node."""
        if self.in_condition:
            self._mark_used_string(node.pattern)
        return node

    def visit_identifier(self, node: Identifier) -> Identifier:
        """Visit Identifier - track potential rule usage."""
        if self.in_condition and node.name not in _RESERVED_IDENTIFIERS:
            self.used_rules.add(node.name)
        return node

    # Pass-through methods for other node types
    def visit_import(self, node: Any) -> Any:
        return node

    def visit_include(self, node: Any) -> Any:
        return node

    def visit_tag(self, node: Any) -> Any:
        return node

    def visit_meta(self, node: Any) -> Any:
        return node

    def visit_plain_string(self, node: Any) -> Any:
        return node

    def visit_hex_string(self, node: Any) -> Any:
        return node

    def visit_regex_string(self, node: Any) -> Any:
        return node

    def visit_string_count(self, node: Any) -> Any:
        if self.in_condition and hasattr(node, "string_id"):
            self._mark_used_string(node.string_id)
        return node

    def visit_string_offset(self, node: Any) -> Any:
        if self.in_condition and hasattr(node, "string_id"):
            self._mark_used_string(node.string_id)
        return node

    def visit_string_length(self, node: Any) -> Any:
        if self.in_condition and hasattr(node, "string_id"):
            self._mark_used_string(node.string_id)
        return node

    def visit_binary_expression(self, node: Any) -> Any:
        """Visit BinaryExpression and optimize if possible."""
        # Visit children first
        node.left = self.visit(node.left)
        node.right = self.visit(node.right)

        # Constant folding for boolean literals
        if isinstance(node.left, BooleanLiteral) and isinstance(
            node.right,
            BooleanLiteral,
        ):
            if node.operator == "and":
                return BooleanLiteral(value=node.left.value and node.right.value)
            if node.operator == "or":
                return BooleanLiteral(value=node.left.value or node.right.value)

        # Simplifications
        if isinstance(node.left, BooleanLiteral):
            if node.operator == "and" and not node.left.value:
                return BooleanLiteral(value=False)
            if node.operator == "or" and node.left.value:
                return BooleanLiteral(value=True)

        if isinstance(node.right, BooleanLiteral):
            if node.operator == "and" and not node.right.value:
                return BooleanLiteral(value=False)
            if node.operator == "or" and node.right.value:
                return BooleanLiteral(value=True)

        return node

    def visit_unary_expression(self, node: Any) -> Any:
        """Visit UnaryExpression and optimize if possible."""
        node.operand = self.visit(node.operand)

        # Optimize not on boolean literal
        if node.operator == "not" and isinstance(node.operand, BooleanLiteral):
            return BooleanLiteral(value=not node.operand.value)

        return node

    def eliminate_dead_code(self, rule: Rule) -> Rule:
        """Eliminate dead code from a single rule.

        This is a simplified version that just removes unused strings.
        """
        # First collect used strings from this rule
        self.used_strings.clear()
        self.used_strings_by_rule.clear()
        self.current_rule = rule.name
        self.current_rule_strings = {string_def.identifier for string_def in rule.strings}
        self.current_rule_anonymous_strings = {
            self._normalize_string_id(string_def.identifier)
            for string_def in rule.strings
            if getattr(string_def, "is_anonymous", False)
        }
        self.used_strings_by_rule[rule.name] = set()
        self.anonymous_strings_by_rule[rule.name] = set(self.current_rule_anonymous_strings)
        self.in_condition = True

        if rule.condition:
            self._collect_from_expression(rule.condition)

        # Remove unused strings
        if rule.strings:
            used_strings = self.used_strings_by_rule.get(rule.name, set())
            anonymous_strings = self.anonymous_strings_by_rule.get(rule.name, set())
            kept_strings = []
            for string_def in rule.strings:
                if self._is_string_identifier_used(
                    string_def.identifier,
                    used_strings,
                    anonymous_strings,
                ):
                    kept_strings.append(string_def)
            rule.strings = kept_strings

        self.current_rule_anonymous_strings = set()
        return rule


def eliminate_dead_code(ast: YaraFile) -> tuple[YaraFile, int]:
    """Convenience function to eliminate dead code."""
    eliminator = DeadCodeEliminator()
    return eliminator.eliminate(ast)


_RESERVED_IDENTIFIERS = frozenset({"true", "false", "any", "all", "them"})
