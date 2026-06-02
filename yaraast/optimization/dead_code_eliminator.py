"""Dead code elimination for YARA rules."""

from __future__ import annotations

from collections import Counter, defaultdict
import copy
from fnmatch import fnmatchcase
from typing import Any, cast

from yaraast.ast.base import ASTNode, YaraFile, require_yara_file
from yaraast.ast.conditions import (
    AtExpression,
    ForExpression,
    ForOfExpression,
    InExpression,
    OfExpression,
)
from yaraast.ast.expressions import (
    BooleanLiteral,
    Expression,
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
from yaraast.ast.rules import Rule
from yaraast.string_references import normalize_string_reference_id
from yaraast.visitor.base import ASTTransformer
from yaraast.yarax.ast_nodes import (
    ArrayComprehension,
    DictComprehension,
    LambdaExpression,
    WithStatement,
)


def _boolean_literal_value(node: BooleanLiteral) -> bool | None:
    if not isinstance(node.value, bool):
        return None
    return node.value


class DeadCodeEliminator(ASTTransformer):
    """Eliminates dead code from YARA rules."""

    _LOCAL_WITHOUT_VALUE = object()
    _MISSING_LOCAL = object()

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
        self.local_variables: list[str] = []
        self.local_variable_values: list[object] = []
        self.anonymous_strings_by_rule: dict[str, set[str]] = {}
        self.rule_usage_keys: dict[int, str] = {}
        self.rule_names: set[str] = set()
        self.elimination_count = 0

    def eliminate(self, ast: YaraFile) -> tuple[YaraFile, int]:
        """Eliminate dead code from AST.

        Returns:
            Tuple of (optimized YaraFile, number of eliminations)
        """
        ast = require_yara_file(ast, "ast")
        ast.validate_structure()

        # Reset state
        self.used_strings.clear()
        self.used_strings_by_rule.clear()
        self.used_rules.clear()
        self.in_condition = False
        self.current_rule = None
        self.current_rule_key = None
        self.current_rule_strings = set()
        self.current_rule_anonymous_strings = set()
        self.local_variables = []
        self.local_variable_values = []
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
        optimized_ast = cast(YaraFile, self.visit(ast))

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
            if rule.condition is not None:
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
        elif isinstance(expr, ForExpression):
            self._collect_for_expression_usage(expr)
            return
        elif isinstance(expr, WithStatement):
            self._collect_with_statement_usage(expr)
            return
        elif isinstance(expr, ArrayComprehension):
            self._collect_array_comprehension_usage(expr)
            return
        elif isinstance(expr, DictComprehension):
            self._collect_dict_comprehension_usage(expr)
            return
        elif isinstance(expr, LambdaExpression):
            self._collect_lambda_expression_usage(expr)
            return
        elif isinstance(expr, MemberAccess):
            if not isinstance(expr.object, Identifier):
                self._collect_from_expression(expr.object)
            return
        elif (
            isinstance(expr, Identifier)
            and expr.name not in _RESERVED_IDENTIFIERS
            and expr.name not in self.local_variables
        ):
            # Could be a rule reference
            self.used_rules.add(expr.name)

        # Recursively collect from children
        for child in expr.children():
            self._collect_from_expression(child)

    def _collect_for_expression_usage(self, expr: ForExpression) -> None:
        if isinstance(expr.quantifier, ASTNode):
            self._collect_from_expression(expr.quantifier)
        self._collect_from_expression(expr.iterable)
        local_count = len(self.local_variables)
        self._add_local_variables(expr.variable)
        try:
            self._collect_from_expression(expr.body)
        finally:
            del self.local_variables[local_count:]
            del self.local_variable_values[local_count:]

    def _collect_with_statement_usage(self, expr: WithStatement) -> None:
        local_count = len(self.local_variables)
        try:
            for declaration in expr.declarations:
                self._collect_from_expression(declaration.value)
                self._add_local_variables(declaration.identifier, value=declaration.value)
            self._collect_from_expression(expr.body)
        finally:
            del self.local_variables[local_count:]
            del self.local_variable_values[local_count:]

    def _collect_array_comprehension_usage(self, expr: ArrayComprehension) -> None:
        if expr.iterable is not None:
            self._collect_from_expression(expr.iterable)
        local_count = len(self.local_variables)
        self._add_local_variables(expr.variable)
        try:
            if expr.condition is not None:
                self._collect_from_expression(expr.condition)
            if expr.expression is not None:
                self._collect_from_expression(expr.expression)
        finally:
            del self.local_variables[local_count:]
            del self.local_variable_values[local_count:]

    def _collect_dict_comprehension_usage(self, expr: DictComprehension) -> None:
        if expr.iterable is not None:
            self._collect_from_expression(expr.iterable)
        local_count = len(self.local_variables)
        try:
            self._add_local_variables(expr.key_variable)
            if expr.value_variable is not None:
                self._add_local_variables(expr.value_variable)
            if expr.condition is not None:
                self._collect_from_expression(expr.condition)
            if expr.key_expression is not None:
                self._collect_from_expression(expr.key_expression)
            if expr.value_expression is not None:
                self._collect_from_expression(expr.value_expression)
        finally:
            del self.local_variables[local_count:]
            del self.local_variable_values[local_count:]

    def _collect_lambda_expression_usage(self, expr: LambdaExpression) -> None:
        local_count = len(self.local_variables)
        self._add_local_variables(*expr.parameters)
        try:
            self._collect_from_expression(expr.body)
        finally:
            del self.local_variables[local_count:]
            del self.local_variable_values[local_count:]

    def visit_yara_file(self, node: YaraFile) -> YaraFile:
        """Visit YaraFile and remove unused rules."""
        node = copy.copy(node)
        kept_rules: list[Rule] = []

        for rule in node.rules:
            if self._should_remove_rule(rule):
                continue  # Remove this rule

            kept_rules.append(cast(Rule, self.visit(rule)))

        node.rules = kept_rules
        return node

    def _is_removable_false_rule(self, rule: Rule) -> bool:
        if not isinstance(rule.condition, BooleanLiteral):
            return False
        condition_value = _boolean_literal_value(rule.condition)
        return condition_value is False and not rule.is_global and rule.name not in self.used_rules

    def _should_remove_rule(self, rule: Rule) -> bool:
        return self._is_removable_false_rule(rule) or self._is_unreferenced_private_rule(rule)

    def _is_unreferenced_private_rule(self, rule: Rule) -> bool:
        return (
            self._is_private_rule(rule) and not rule.is_global and rule.name not in self.used_rules
        )

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
        if rule.condition is not None:
            return self._contains_rule_reference(rule.condition)
        return False

    def _contains_rule_reference(self, expr: ASTNode) -> bool:
        return self._contains_rule_reference_with_locals(expr, set())

    def _contains_rule_reference_with_locals(
        self, expr: ASTNode, local_variables: set[str]
    ) -> bool:
        """Check if expression contains rule reference."""
        if isinstance(expr, ForExpression):
            nested_locals = {*local_variables, expr.variable}
            return (
                (
                    isinstance(expr.quantifier, ASTNode)
                    and self._contains_rule_reference_with_locals(expr.quantifier, local_variables)
                )
                or self._contains_rule_reference_with_locals(expr.iterable, local_variables)
                or self._contains_rule_reference_with_locals(expr.body, nested_locals)
            )

        if isinstance(expr, WithStatement):
            active_locals = set(local_variables)
            for declaration in expr.declarations:
                if self._contains_rule_reference_with_locals(declaration.value, active_locals):
                    return True
                active_locals.add(declaration.identifier)
            return self._contains_rule_reference_with_locals(expr.body, active_locals)

        if isinstance(expr, ArrayComprehension):
            nested_locals = {*local_variables, expr.variable}
            return (
                (
                    expr.iterable is not None
                    and self._contains_rule_reference_with_locals(expr.iterable, local_variables)
                )
                or (
                    expr.condition is not None
                    and self._contains_rule_reference_with_locals(expr.condition, nested_locals)
                )
                or (
                    expr.expression is not None
                    and self._contains_rule_reference_with_locals(expr.expression, nested_locals)
                )
            )

        if isinstance(expr, DictComprehension):
            nested_locals = {*local_variables, expr.key_variable}
            if expr.value_variable is not None:
                nested_locals.add(expr.value_variable)
            return (
                (
                    expr.iterable is not None
                    and self._contains_rule_reference_with_locals(expr.iterable, local_variables)
                )
                or (
                    expr.condition is not None
                    and self._contains_rule_reference_with_locals(expr.condition, nested_locals)
                )
                or (
                    expr.key_expression is not None
                    and self._contains_rule_reference_with_locals(
                        expr.key_expression, nested_locals
                    )
                )
                or (
                    expr.value_expression is not None
                    and self._contains_rule_reference_with_locals(
                        expr.value_expression,
                        nested_locals,
                    )
                )
            )

        if isinstance(expr, LambdaExpression):
            return self._contains_rule_reference_with_locals(
                expr.body,
                {*local_variables, *expr.parameters},
            )

        if isinstance(expr, MemberAccess):
            return not isinstance(
                expr.object, Identifier
            ) and self._contains_rule_reference_with_locals(
                expr.object,
                local_variables,
            )

        if isinstance(expr, Identifier) and expr.name not in [
            "true",
            "false",
            "any",
            "all",
            "them",
        ]:
            # Could be a rule reference
            return expr.name not in local_variables

        return any(
            self._contains_rule_reference_with_locals(child, local_variables)
            for child in expr.children()
        )

    def _normalize_string_id(self, identifier: str) -> str:
        return normalize_string_reference_id(identifier)

    def _mark_used_string(self, identifier: str) -> None:
        normalized = self._normalize_string_id(identifier)
        if normalized in self.local_variables:
            return
        self.used_strings.add(normalized)
        if self.current_rule_key:
            self.used_strings_by_rule.setdefault(self.current_rule_key, set()).add(normalized)

    def _mark_used_wildcard(self, pattern: str) -> None:
        if not isinstance(pattern, str):
            raise TypeError("String wildcard pattern must be a string")
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

    def _local_variable_value(self, name: str) -> object:
        for index in range(len(self.local_variables) - 1, -1, -1):
            if self.local_variables[index] == name:
                return self.local_variable_values[index]
        return self._MISSING_LOCAL

    def _collect_string_set_value(self, value: Any) -> None:
        if isinstance(value, str):
            local_value = self._local_variable_value(self._normalize_string_id(value))
            if local_value is not self._MISSING_LOCAL:
                if local_value is not self._LOCAL_WITHOUT_VALUE:
                    self._collect_string_set_value(local_value)
                return
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
            self._collect_string_set_value(value.value)
            return
        if isinstance(value, StringIdentifier):
            self._collect_string_set_value(value.name)
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
        usage_key = self._usage_key_for_rule(node)
        node = copy.deepcopy(node)
        self.current_rule = node.name
        self.current_rule_key = usage_key

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
        if node.condition is not None:
            self.in_condition = True
            node.condition = cast(Expression, self.visit(node.condition))
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
        if (
            self.in_condition
            and node.name not in _RESERVED_IDENTIFIERS
            and node.name not in self.local_variables
        ):
            self.used_rules.add(node.name)
        return node

    def visit_for_expression(self, node: ForExpression) -> ForExpression:
        if isinstance(node.quantifier, ASTNode):
            node.quantifier = cast(Expression, self.visit(node.quantifier))
        node.iterable = cast(Expression, self.visit(node.iterable))
        local_count = len(self.local_variables)
        self._add_local_variables(node.variable)
        try:
            node.body = cast(Expression, self.visit(node.body))
        finally:
            del self.local_variables[local_count:]
            del self.local_variable_values[local_count:]
        return node

    def visit_with_statement(self, node: WithStatement) -> WithStatement:
        local_count = len(self.local_variables)
        try:
            for declaration in node.declarations:
                declaration.value = cast(Expression, self.visit(declaration.value))
                self._add_local_variables(declaration.identifier, value=declaration.value)
            node.body = cast(Expression, self.visit(node.body))
        finally:
            del self.local_variables[local_count:]
            del self.local_variable_values[local_count:]
        return node

    def visit_array_comprehension(self, node: ArrayComprehension) -> ArrayComprehension:
        if node.iterable is not None:
            node.iterable = cast(Expression, self.visit(node.iterable))
        local_count = len(self.local_variables)
        self._add_local_variables(node.variable)
        try:
            if node.condition is not None:
                node.condition = cast(Expression, self.visit(node.condition))
            if node.expression is not None:
                node.expression = cast(Expression, self.visit(node.expression))
        finally:
            del self.local_variables[local_count:]
            del self.local_variable_values[local_count:]
        return node

    def visit_dict_comprehension(self, node: DictComprehension) -> DictComprehension:
        if node.iterable is not None:
            node.iterable = cast(Expression, self.visit(node.iterable))
        local_count = len(self.local_variables)
        try:
            self._add_local_variables(node.key_variable)
            if node.value_variable is not None:
                self._add_local_variables(node.value_variable)
            if node.condition is not None:
                node.condition = cast(Expression, self.visit(node.condition))
            if node.key_expression is not None:
                node.key_expression = cast(Expression, self.visit(node.key_expression))
            if node.value_expression is not None:
                node.value_expression = cast(Expression, self.visit(node.value_expression))
        finally:
            del self.local_variables[local_count:]
            del self.local_variable_values[local_count:]
        return node

    def visit_lambda_expression(self, node: LambdaExpression) -> LambdaExpression:
        local_count = len(self.local_variables)
        self._add_local_variables(*node.parameters)
        try:
            node.body = cast(Expression, self.visit(node.body))
        finally:
            del self.local_variables[local_count:]
            del self.local_variable_values[local_count:]
        return node

    def visit_member_access(self, node: MemberAccess) -> MemberAccess:
        """Visit member access without treating a bare object root as a rule reference."""
        if not isinstance(node.object, Identifier):
            node.object = cast(Expression, self.visit(node.object))
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
        """Traverse a BinaryExpression without rewriting it.

        Dead-code elimination must not fold or simplify expressions: usage is
        collected from the original condition, so folding away a branch here
        (e.g. ``true or $a`` -> ``true``) would silently orphan the strings it
        referenced and leave them defined but unreferenced. Constant folding is
        the responsibility of :class:`ExpressionOptimizer`, which
        :class:`RuleOptimizer` runs before this pass.
        """
        node.left = self.visit(node.left)
        node.right = self.visit(node.right)
        return node

    def visit_unary_expression(self, node: Any) -> Any:
        """Traverse a UnaryExpression without rewriting it.

        See :meth:`visit_binary_expression` for why this pass never folds.
        """
        node.operand = self.visit(node.operand)
        return node

    def eliminate_dead_code(self, rule: Rule) -> Rule:
        """Eliminate dead code from a single rule.

        This is a simplified version that just removes unused strings.
        """
        # First collect used strings from this rule
        self.used_strings.clear()
        self.used_strings_by_rule.clear()
        self.local_variables.clear()
        self.local_variable_values.clear()
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

        if rule.condition is not None:
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
        self.local_variables.clear()
        self.local_variable_values.clear()
        return rule

    def _add_local_variables(self, *names: str, value: object = _LOCAL_WITHOUT_VALUE) -> None:
        for name in names:
            variants = self._local_name_variants(name)
            self.local_variables.extend(variants)
            self.local_variable_values.extend(value for _ in variants)

    @staticmethod
    def _local_name_variants(name: str) -> tuple[str, ...]:
        if not isinstance(name, str):
            raise TypeError("Local variable name must be a string")
        return tuple(part.strip() for part in name.split(",") if part.strip())


def eliminate_dead_code(ast: YaraFile) -> tuple[YaraFile, int]:
    """Convenience function to eliminate dead code."""
    eliminator = DeadCodeEliminator()
    return eliminator.eliminate(ast)


_RESERVED_IDENTIFIERS = frozenset({"true", "false", "any", "all", "them"})
