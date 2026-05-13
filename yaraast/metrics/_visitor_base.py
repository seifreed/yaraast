"""Default visitor implementations for metrics modules."""

from __future__ import annotations

from typing import Any

from yaraast.visitor.defaults import DefaultASTVisitor


class MetricsVisitorBase(DefaultASTVisitor[Any]):
    """ASTVisitor with default no-op implementations."""

    def __init__(self, default: Any = None) -> None:
        super().__init__(default=default)

    def _visit_ast_value(self, value: Any) -> None:
        if hasattr(value, "accept"):
            self.visit(value)
        elif isinstance(value, list | tuple):
            for item in value:
                self._visit_ast_value(item)

    def visit_with_statement(self, node) -> Any:
        self._visit_ast_value(node.declarations)
        self._visit_ast_value(node.body)
        return self._default

    def visit_with_declaration(self, node) -> Any:
        self._visit_ast_value(node.value)
        return self._default

    def visit_array_comprehension(self, node) -> Any:
        self._visit_ast_value(node.expression)
        self._visit_ast_value(node.iterable)
        self._visit_ast_value(node.condition)
        return self._default

    def visit_dict_comprehension(self, node) -> Any:
        self._visit_ast_value(node.key_expression)
        self._visit_ast_value(node.value_expression)
        self._visit_ast_value(node.iterable)
        self._visit_ast_value(node.condition)
        return self._default

    def visit_tuple_expression(self, node) -> Any:
        self._visit_ast_value(node.elements)
        return self._default

    def visit_tuple_indexing(self, node) -> Any:
        self._visit_ast_value(node.tuple_expr)
        self._visit_ast_value(node.index)
        return self._default

    def visit_list_expression(self, node) -> Any:
        self._visit_ast_value(node.elements)
        return self._default

    def visit_dict_expression(self, node) -> Any:
        self._visit_ast_value(node.items)
        return self._default

    def visit_dict_item(self, node) -> Any:
        self._visit_ast_value(node.key)
        self._visit_ast_value(node.value)
        return self._default

    def visit_slice_expression(self, node) -> Any:
        self._visit_ast_value(node.target)
        self._visit_ast_value(node.start)
        self._visit_ast_value(node.stop)
        self._visit_ast_value(node.step)
        return self._default

    def visit_lambda_expression(self, node) -> Any:
        self._visit_ast_value(node.body)
        return self._default

    def visit_pattern_match(self, node) -> Any:
        self._visit_ast_value(node.value)
        self._visit_ast_value(node.cases)
        self._visit_ast_value(node.default)
        return self._default

    def visit_match_case(self, node) -> Any:
        self._visit_ast_value(node.pattern)
        self._visit_ast_value(node.result)
        return self._default

    def visit_spread_operator(self, node) -> Any:
        self._visit_ast_value(node.expression)
        return self._default
