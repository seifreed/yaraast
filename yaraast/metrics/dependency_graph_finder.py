"""Traversal helpers for dependency graph analysis."""

from __future__ import annotations

from typing import TYPE_CHECKING

from yaraast.metrics._visitor_base import MetricsVisitorBase

if TYPE_CHECKING:
    from yaraast.ast.expressions import Identifier


class DependencyFinder(MetricsVisitorBase):
    """Collect inter-rule identifier dependencies from a condition tree."""

    def __init__(self, current_rule: str, all_rules: set[str]) -> None:
        super().__init__(default=None)
        self.current_rule = current_rule
        self.all_rules = all_rules
        self.dependencies = set()
        self.local_scopes: list[set[str]] = []

    def visit_identifier(self, node: Identifier) -> None:
        if (
            node.name in self.all_rules
            and node.name != self.current_rule
            and not self._is_local(node.name)
        ):
            self.dependencies.add(node.name)

    def visit_binary_expression(self, node) -> None:
        self.visit(node.left)
        self.visit(node.right)

    def visit_unary_expression(self, node) -> None:
        self.visit(node.operand)

    def visit_parentheses_expression(self, node) -> None:
        self.visit(node.expression)

    def visit_set_expression(self, node) -> None:
        for elem in node.elements:
            self.visit(elem)

    def visit_range_expression(self, node) -> None:
        self.visit(node.low)
        self.visit(node.high)

    def visit_function_call(self, node) -> None:
        self._required_string(node.function, "Function name")
        for arg in self._required_ast_sequence(node.arguments, "Function arguments"):
            self.visit(arg)

    def visit_array_access(self, node) -> None:
        self.visit(node.array)
        self.visit(node.index)

    def visit_member_access(self, node) -> None:
        from yaraast.ast.expressions import Identifier

        if not isinstance(node.object, Identifier):
            self.visit(node.object)

    def visit_for_expression(self, node) -> None:
        if hasattr(node.quantifier, "accept"):
            self.visit(node.quantifier)
        self.visit(node.iterable)
        self._push_local_scope(node.variable)
        try:
            self.visit(node.body)
        finally:
            self._pop_local_scope()

    def visit_for_of_expression(self, node) -> None:
        if hasattr(node.quantifier, "accept"):
            self.visit(node.quantifier)
        self._visit_ast_value(node.string_set)
        if node.condition is not None:
            self.visit(node.condition)

    def visit_at_expression(self, node) -> None:
        self.visit(self._required_ast_node(node.offset, "'at' offset"))

    def visit_in_expression(self, node) -> None:
        if hasattr(node.subject, "accept"):
            self.visit(node.subject)
        self.visit(self._required_ast_node(node.range, "'in' range"))

    def visit_of_expression(self, node) -> None:
        if hasattr(node.quantifier, "accept"):
            self.visit(node.quantifier)
        self._visit_ast_value(node.string_set)

    def visit_dictionary_access(self, node) -> None:
        self.visit(node.object)
        if hasattr(node.key, "accept"):
            self.visit(node.key)

    def visit_defined_expression(self, node) -> None:
        self.visit(node.expression)

    def visit_string_operator_expression(self, node) -> None:
        self.visit(node.left)
        self.visit(node.right)

    def visit_string_wildcard(self, node) -> None:
        if not isinstance(node.pattern, str):
            raise TypeError("String wildcard pattern must be a string")
        pattern = node.pattern
        if pattern.startswith("$") or not pattern.endswith("*"):
            return

        prefix = pattern[:-1]
        if not prefix:
            return

        self.dependencies.update(
            rule_name
            for rule_name in sorted(self.all_rules)
            if rule_name.startswith(prefix)
            and rule_name != self.current_rule
            and not self._is_local(rule_name)
        )

    def visit_with_statement(self, node) -> None:
        self._push_local_scope()
        try:
            for declaration in node.declarations:
                self.visit(declaration)
            self.visit(node.body)
        finally:
            self._pop_local_scope()

    def visit_with_declaration(self, node) -> None:
        self._visit_ast_value(node.value)
        self._define_local(node.identifier)

    def visit_array_comprehension(self, node) -> None:
        self._visit_ast_value(node.iterable)
        self._push_local_scope(node.variable)
        try:
            self._visit_ast_value(node.condition)
            self._visit_ast_value(node.expression)
        finally:
            self._pop_local_scope()

    def visit_dict_comprehension(self, node) -> None:
        self._visit_ast_value(node.iterable)
        names = [node.key_variable]
        if node.value_variable:
            names.append(node.value_variable)
        self._push_local_scope(*names)
        try:
            self._visit_ast_value(node.condition)
            self._visit_ast_value(node.key_expression)
            self._visit_ast_value(node.value_expression)
        finally:
            self._pop_local_scope()

    def visit_lambda_expression(self, node) -> None:
        self._push_local_scope(*node.parameters)
        try:
            self._visit_ast_value(node.body)
        finally:
            self._pop_local_scope()

    def _is_local(self, name: str) -> bool:
        return any(name in scope for scope in reversed(self.local_scopes))

    def _push_local_scope(self, *names: str) -> None:
        scope: set[str] = set()
        for name in names:
            scope.update(self._local_name_variants(name))
        self.local_scopes.append(scope)

    def _pop_local_scope(self) -> None:
        self.local_scopes.pop()

    def _define_local(self, name: str) -> None:
        if self.local_scopes:
            self.local_scopes[-1].update(self._local_name_variants(name))

    @staticmethod
    def _local_name_variants(name: str) -> set[str]:
        if not isinstance(name, str):
            raise TypeError("Local variable name must be a string")
        names = [part.strip() for part in name.split(",")]
        return {local_name for local_name in names if local_name}

    def _visit_ast_value(self, value) -> None:
        if hasattr(value, "accept"):
            self.visit(value)
        elif isinstance(value, list | tuple | set | frozenset):
            for item in value:
                self._visit_ast_value(item)
