"""Dead code elimination for YARA rules."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from yaraast.ast.expressions import BooleanLiteral, Identifier, StringIdentifier
from yaraast.visitor.visitor import ASTTransformer

if TYPE_CHECKING:
    from yaraast.ast.base import ASTNode, YaraFile
    from yaraast.ast.rules import Rule


class DeadCodeEliminator(ASTTransformer):
    """Eliminates dead code from YARA rules."""

    def __init__(self) -> None:
        super().__init__()
        self.used_strings: set[str] = set()
        self.used_rules: set[str] = set()
        self.in_condition = False
        self.current_rule: str | None = None

    def eliminate(self, ast: YaraFile) -> YaraFile:
        """Eliminate dead code from AST."""
        # Reset state
        self.used_strings.clear()
        self.used_rules.clear()
        self.in_condition = False
        self.current_rule = None

        # First pass: collect used strings and rules
        self._collect_usage(ast)

        # Second pass: eliminate unused code
        _ = self.visit(ast)

        return ast

    def _collect_usage(self, ast: YaraFile) -> None:
        """Collect usage information."""
        for rule in ast.rules:
            self.current_rule = rule.name
            self.in_condition = True
            if rule.condition:
                self._collect_from_expression(rule.condition)
            self.in_condition = False

    def _collect_from_expression(self, expr: ASTNode) -> None:
        """Collect usage from expression."""
        if isinstance(expr, StringIdentifier):
            self.used_strings.add(expr.name)
        elif isinstance(expr, Identifier):
            # Could be a rule reference
            self.used_rules.add(expr.name)

        # Recursively collect from children
        for child in expr.children():
            self._collect_from_expression(child)

    def visit_yara_file(self, node: YaraFile) -> YaraFile:
        """Visit YaraFile and remove unused rules."""
        # Keep only used rules (or all if we can't determine)
        if self.used_rules:
            # Filter rules - keep if used or if it's a private rule that might be used internally
            kept_rules = []
            for rule in node.rules:
                is_private = False
                if hasattr(rule, "modifiers") and isinstance(
                    rule.modifiers,
                    list | tuple,
                ):
                    is_private = "private" in rule.modifiers
                if (
                    rule.name in self.used_rules
                    or is_private
                    or not self._has_external_references(rule)
                ):
                    kept_rules.append(self.visit(rule))
            node.rules = kept_rules
        else:
            # If no usage info, keep all rules but optimize them
            node.rules = [self.visit(rule) for rule in node.rules]

        return node

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

    def visit_rule(self, node: Rule) -> Rule:
        """Visit Rule and remove unused strings."""
        self.current_rule = node.name

        # Remove unused strings
        if node.strings and self.used_strings:
            kept_strings = []
            for string_def in node.strings:
                if string_def.identifier in self.used_strings:
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
            self.used_strings.add(node.name)
        return node

    def visit_identifier(self, node: Identifier) -> Identifier:
        """Visit Identifier - track potential rule usage."""
        if self.in_condition and node.name not in [
            "true",
            "false",
            "any",
            "all",
            "them",
        ]:
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
            self.used_strings.add(node.string_id)
        return node

    def visit_string_offset(self, node: Any) -> Any:
        if self.in_condition and hasattr(node, "string_id"):
            self.used_strings.add(node.string_id)
        return node

    def visit_string_length(self, node: Any) -> Any:
        if self.in_condition and hasattr(node, "string_id"):
            self.used_strings.add(node.string_id)
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
        self.current_rule = rule.name
        self.in_condition = True

        if rule.condition:
            self._collect_from_expression(rule.condition)

        # Remove unused strings
        if rule.strings and self.used_strings:
            kept_strings = []
            for string_def in rule.strings:
                if string_def.identifier in self.used_strings:
                    kept_strings.append(string_def)
            rule.strings = kept_strings

        return rule


def eliminate_dead_code(ast: YaraFile) -> YaraFile:
    """Convenience function to eliminate dead code."""
    eliminator = DeadCodeEliminator()
    return eliminator.eliminate(ast)
