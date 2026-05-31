"""Dead code elimination for YARA rules."""

from __future__ import annotations

from collections import Counter, defaultdict
from fnmatch import fnmatchcase
from typing import TYPE_CHECKING, Any

from yaraast.ast.conditions import AtExpression, ForOfExpression, InExpression, OfExpression
from yaraast.ast.expressions import (
    BooleanLiteral,
    Identifier,
    MemberAccess,
    ParenthesesExpression,
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
        self.current_rule_key: str | None = None
        self.current_rule_strings: set[str] = set()
        self.current_rule_anonymous_strings: set[str] = set()
        self.anonymous_strings_by_rule: dict[str, set[str]] = {}
        self.rule_usage_keys: dict[int, str] = {}
        self.rule_names: set[str] = set()
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
        self.current_rule_key = None
        self.current_rule_strings = set()
        self.current_rule_anonymous_strings = set()
        self.anonymous_strings_by_rule.clear()
        self.rule_usage_keys.clear()
        self.rule_names.clear()
        self.elimination_count = 0

        # First pass: collect used strings and rules
        self._collect_usage(ast)

        # Count strings to be removed
        for rule in ast.rules:
            if rule.strings:
                rule_key = self._usage_key_for_rule(rule)
                used_strings = self.used_strings_by_rule.get(rule_key, set())
                anonymous_strings = self.anonymous_strings_by_rule.get(rule_key, set())
                for string_def in rule.strings:
                    if not self._is_string_identifier_used(
                        string_def.identifier,
                        used_strings,
                        anonymous_strings,
                    ):
                        self.elimination_count += 1

        # Count rules that will be removed
        for rule in ast.rules:
            if self._should_remove_rule(rule):
                self.elimination_count += 1

        # Second pass: eliminate unused code
        optimized_ast = self.visit(ast)

        return optimized_ast, self.elimination_count

    def _collect_usage(self, ast: YaraFile) -> None:
        """Collect usage information."""
        rule_counts = Counter(rule.name for rule in ast.rules)
        self.rule_names = set(rule_counts)
        seen_rules: defaultdict[str, int] = defaultdict(int)
        for rule in ast.rules:
            seen_rules[rule.name] += 1
            rule_key = self._rule_usage_key(rule.name, seen_rules[rule.name], rule_counts)
            self.rule_usage_keys[id(rule)] = rule_key
            self.current_rule = rule.name
            self.current_rule_key = rule_key
            self.current_rule_strings = {string_def.identifier for string_def in rule.strings}
            self.current_rule_anonymous_strings = {
                self._normalize_string_id(string_def.identifier)
                for string_def in rule.strings
                if getattr(string_def, "is_anonymous", False)
            }
            self.used_strings_by_rule.setdefault(rule_key, set())
            self.anonymous_strings_by_rule[rule_key] = set(self.current_rule_anonymous_strings)
            self.in_condition = True
            if rule.condition:
                self._collect_from_expression(rule.condition)
            self.in_condition = False
            self.current_rule_key = None
            self.current_rule_strings = set()
            self.current_rule_anonymous_strings = set()

    def _rule_usage_key(self, rule_name: str, occurrence: int, counts: Counter[str]) -> str:
        if counts[rule_name] == 1:
            return rule_name
        return f"{rule_name}#{occurrence}"

    def _usage_key_for_rule(self, rule: Rule) -> str:
        return self.rule_usage_keys.get(id(rule), rule.name)

    def _collect_from_expression(self, expr: ASTNode) -> None:
        """Collect usage from expression."""
        if isinstance(expr, StringIdentifier):
            self._mark_used_string(expr.name)
        elif isinstance(expr, StringWildcard):
            self._mark_used_wildcard(expr.pattern)
        elif isinstance(expr, StringCount | StringOffset | StringLength):
            self._mark_used_string(expr.string_id)
        elif isinstance(expr, AtExpression):
            if isinstance(expr.string_id, str):
                self._mark_used_string(expr.string_id)
            else:
                self._collect_from_expression(expr.string_id)
        elif isinstance(expr, InExpression) and isinstance(expr.subject, str):
            self._mark_used_string(expr.subject)
        elif isinstance(expr, OfExpression | ForOfExpression):
            self._collect_string_set_value(expr.string_set)
        elif isinstance(expr, MemberAccess):
            if not isinstance(expr.object, Identifier):
                self._collect_from_expression(expr.object)
            return
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
            if self._should_remove_rule(rule):
                continue  # Remove this rule

            kept_rules.append(self.visit(rule))

        node.rules = kept_rules
        return node

    def _is_removable_false_rule(self, rule: Rule) -> bool:
        return (
            rule.condition is not None
            and isinstance(rule.condition, BooleanLiteral)
            and not rule.condition.value
            and not rule.is_global
            and rule.name not in self.used_rules
        )

    def _should_remove_rule(self, rule: Rule) -> bool:
        return self._is_removable_false_rule(rule) or self._is_unreferenced_private_rule(rule)

    def _is_unreferenced_private_rule(self, rule: Rule) -> bool:
        return self._is_private_rule(rule) and rule.name not in self.used_rules

    def _is_private_rule(self, rule: Rule) -> bool:
        modifiers = getattr(rule, "modifiers", ())
        if not isinstance(modifiers, list | tuple):
            return False
        for modifier in modifiers:
            if isinstance(modifier, str) and modifier == "private":
                return True
            modifier_type = getattr(modifier, "modifier_type", None)
            if getattr(modifier_type, "value", None) == "private":
                return True
            if getattr(modifier, "name", None) == "private":
                return True
        return False

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
        if isinstance(expr, MemberAccess):
            return not isinstance(expr.object, Identifier) and self._contains_rule_reference(
                expr.object
            )

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
        if self.current_rule_key:
            self.used_strings_by_rule.setdefault(self.current_rule_key, set()).add(normalized)

    def _mark_used_wildcard(self, pattern: str) -> None:
        if pattern.startswith("$"):
            self._mark_used_string(pattern)
            return

        self.used_rules.update(self._matching_rule_wildcard_names(pattern))

    def _matching_rule_wildcard_names(self, pattern: str) -> tuple[str, ...]:
        if not pattern.endswith("*"):
            return ()
        prefix = pattern[:-1]
        if not prefix:
            return ()
        return tuple(
            sorted(
                rule_name
                for rule_name in self.rule_names
                if rule_name.startswith(prefix) and rule_name != self.current_rule
            )
        )

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
            self._mark_used_wildcard(value.pattern)
            return
        if isinstance(value, ParenthesesExpression):
            self._collect_string_set_value(value.expression)
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
        self.current_rule_key = self._usage_key_for_rule(node)

        # Remove unused strings
        if node.strings:
            used_strings = self.used_strings_by_rule.get(self.current_rule_key, set())
            anonymous_strings = self.anonymous_strings_by_rule.get(self.current_rule_key, set())
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
            self._mark_used_wildcard(node.pattern)
        return node

    def visit_identifier(self, node: Identifier) -> Identifier:
        """Visit Identifier - track potential rule usage."""
        if self.in_condition and node.name not in _RESERVED_IDENTIFIERS:
            self.used_rules.add(node.name)
        return node

    def visit_member_access(self, node: MemberAccess) -> MemberAccess:
        """Visit member access without treating a bare object root as a rule reference."""
        if not isinstance(node.object, Identifier):
            node.object = self.visit(node.object)
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
        self.current_rule_key = rule.name
        self.rule_usage_keys[id(rule)] = rule.name
        self.current_rule_strings = {string_def.identifier for string_def in rule.strings}
        self.current_rule_anonymous_strings = {
            self._normalize_string_id(string_def.identifier)
            for string_def in rule.strings
            if getattr(string_def, "is_anonymous", False)
        }
        self.used_strings_by_rule[self.current_rule_key] = set()
        self.anonymous_strings_by_rule[self.current_rule_key] = set(
            self.current_rule_anonymous_strings
        )
        self.in_condition = True

        if rule.condition:
            self._collect_from_expression(rule.condition)

        # Remove unused strings
        if rule.strings:
            rule_key = self._usage_key_for_rule(rule)
            used_strings = self.used_strings_by_rule.get(rule_key, set())
            anonymous_strings = self.anonymous_strings_by_rule.get(rule_key, set())
            kept_strings = []
            for string_def in rule.strings:
                if self._is_string_identifier_used(
                    string_def.identifier,
                    used_strings,
                    anonymous_strings,
                ):
                    kept_strings.append(string_def)
            rule.strings = kept_strings

        self.in_condition = False
        self.current_rule = None
        self.current_rule_key = None
        self.current_rule_strings = set()
        self.current_rule_anonymous_strings = set()
        return rule


def eliminate_dead_code(ast: YaraFile) -> tuple[YaraFile, int]:
    """Convenience function to eliminate dead code."""
    eliminator = DeadCodeEliminator()
    return eliminator.eliminate(ast)


_RESERVED_IDENTIFIERS = frozenset({"true", "false", "any", "all", "them"})
