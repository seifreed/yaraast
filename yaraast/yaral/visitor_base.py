"""Shared visitor base for YARA-L nodes."""

from __future__ import annotations

from typing import Any, TypeVar

from yaraast.visitor import ASTVisitor

T = TypeVar("T")


class YaraLVisitor[T](ASTVisitor[T]):
    """YARA-L visitor base with explicit handlers for every YARA-L AST node."""

    def _visit_yaral_node(self, node: Any) -> T:
        return self._default_visit(node)

    def visit_yaral_file(self, node: Any) -> T:
        return self._visit_yaral_node(node)

    def visit_yaral_rule(self, node: Any) -> T:
        return self._visit_yaral_node(node)

    def visit_yaral_meta_section(self, node: Any) -> T:
        return self._visit_yaral_node(node)

    def visit_yaral_meta_entry(self, node: Any) -> T:
        return self._visit_yaral_node(node)

    def visit_yaral_events_section(self, node: Any) -> T:
        return self._visit_yaral_node(node)

    def visit_yaral_event_statement(self, node: Any) -> T:
        return self._visit_yaral_node(node)

    def visit_yaral_event_assignment(self, node: Any) -> T:
        return self._visit_yaral_node(node)

    def visit_yaral_event_variable(self, node: Any) -> T:
        return self._visit_yaral_node(node)

    def visit_yaral_udm_field_path(self, node: Any) -> T:
        return self._visit_yaral_node(node)

    def visit_yaral_udm_field_access(self, node: Any) -> T:
        return self._visit_yaral_node(node)

    def visit_yaral_reference_list(self, node: Any) -> T:
        return self._visit_yaral_node(node)

    def visit_yaral_match_section(self, node: Any) -> T:
        return self._visit_yaral_node(node)

    def visit_yaral_match_variable(self, node: Any) -> T:
        return self._visit_yaral_node(node)

    def visit_yaral_time_window(self, node: Any) -> T:
        return self._visit_yaral_node(node)

    def visit_yaral_condition_section(self, node: Any) -> T:
        return self._visit_yaral_node(node)

    def visit_yaral_condition_expression(self, node: Any) -> T:
        return self._visit_yaral_node(node)

    def visit_yaral_binary_condition(self, node: Any) -> T:
        return self._visit_yaral_node(node)

    def visit_yaral_unary_condition(self, node: Any) -> T:
        return self._visit_yaral_node(node)

    def visit_yaral_event_count_condition(self, node: Any) -> T:
        return self._visit_yaral_node(node)

    def visit_yaral_event_exists_condition(self, node: Any) -> T:
        return self._visit_yaral_node(node)

    def visit_yaral_variable_comparison_condition(self, node: Any) -> T:
        return self._visit_yaral_node(node)

    def visit_yaral_join_condition(self, node: Any) -> T:
        return self._visit_yaral_node(node)

    def visit_yaral_n_of_condition(self, node: Any) -> T:
        return self._visit_yaral_node(node)

    def visit_yaral_null_check_condition(self, node: Any) -> T:
        return self._visit_yaral_node(node)

    def visit_yaral_outcome_section(self, node: Any) -> T:
        return self._visit_yaral_node(node)

    def visit_yaral_outcome_assignment(self, node: Any) -> T:
        return self._visit_yaral_node(node)

    def visit_yaral_outcome_expression(self, node: Any) -> T:
        return self._visit_yaral_node(node)

    def visit_yaral_aggregation_function(self, node: Any) -> T:
        return self._visit_yaral_node(node)

    def visit_yaral_conditional_expression(self, node: Any) -> T:
        return self._visit_yaral_node(node)

    def visit_yaral_arithmetic_expression(self, node: Any) -> T:
        return self._visit_yaral_node(node)

    def visit_yaral_options_section(self, node: Any) -> T:
        return self._visit_yaral_node(node)

    def visit_yaral_regex_pattern(self, node: Any) -> T:
        return self._visit_yaral_node(node)

    def visit_yaral_cidr_expression(self, node: Any) -> T:
        return self._visit_yaral_node(node)

    def visit_yaral_function_call(self, node: Any) -> T:
        return self._visit_yaral_node(node)
