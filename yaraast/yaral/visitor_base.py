"""Shared visitor base for YARA-L that stubs core YARA visitors."""

from __future__ import annotations

from typing import Any, TypeVar

from yaraast.visitor import ASTVisitor

T = TypeVar("T")


class YaraLVisitor[T](ASTVisitor[T]):
    """YARA-L visitor base that stubs standard YARA AST methods."""

    def visit_yara_file(self, node: Any) -> T:
        raise NotImplementedError

    def visit_import(self, node: Any) -> T:
        raise NotImplementedError

    def visit_include(self, node: Any) -> T:
        raise NotImplementedError

    def visit_rule(self, node: Any) -> T:
        raise NotImplementedError

    def visit_tag(self, node: Any) -> T:
        raise NotImplementedError

    def visit_string_definition(self, node: Any) -> T:
        raise NotImplementedError

    def visit_plain_string(self, node: Any) -> T:
        raise NotImplementedError

    def visit_hex_string(self, node: Any) -> T:
        raise NotImplementedError

    def visit_regex_string(self, node: Any) -> T:
        raise NotImplementedError

    def visit_string_modifier(self, node: Any) -> T:
        raise NotImplementedError

    def visit_hex_token(self, node: Any) -> T:
        raise NotImplementedError

    def visit_hex_byte(self, node: Any) -> T:
        raise NotImplementedError

    def visit_hex_wildcard(self, node: Any) -> T:
        raise NotImplementedError

    def visit_hex_jump(self, node: Any) -> T:
        raise NotImplementedError

    def visit_hex_alternative(self, node: Any) -> T:
        raise NotImplementedError

    def visit_hex_nibble(self, node: Any) -> T:
        raise NotImplementedError

    def visit_expression(self, node: Any) -> T:
        raise NotImplementedError

    def visit_identifier(self, node: Any) -> T:
        raise NotImplementedError

    def visit_string_identifier(self, node: Any) -> T:
        raise NotImplementedError

    def visit_string_wildcard(self, node: Any) -> T:
        raise NotImplementedError

    def visit_string_count(self, node: Any) -> T:
        raise NotImplementedError

    def visit_string_offset(self, node: Any) -> T:
        raise NotImplementedError

    def visit_string_length(self, node: Any) -> T:
        raise NotImplementedError

    def visit_integer_literal(self, node: Any) -> T:
        raise NotImplementedError

    def visit_double_literal(self, node: Any) -> T:
        raise NotImplementedError

    def visit_string_literal(self, node: Any) -> T:
        raise NotImplementedError

    def visit_regex_literal(self, node: Any) -> T:
        raise NotImplementedError

    def visit_boolean_literal(self, node: Any) -> T:
        raise NotImplementedError

    def visit_binary_expression(self, node: Any) -> T:
        raise NotImplementedError

    def visit_unary_expression(self, node: Any) -> T:
        raise NotImplementedError

    def visit_parentheses_expression(self, node: Any) -> T:
        raise NotImplementedError

    def visit_set_expression(self, node: Any) -> T:
        raise NotImplementedError

    def visit_range_expression(self, node: Any) -> T:
        raise NotImplementedError

    def visit_function_call(self, node: Any) -> T:
        raise NotImplementedError

    def visit_array_access(self, node: Any) -> T:
        raise NotImplementedError

    def visit_member_access(self, node: Any) -> T:
        raise NotImplementedError

    def visit_condition(self, node: Any) -> T:
        raise NotImplementedError

    def visit_for_expression(self, node: Any) -> T:
        raise NotImplementedError

    def visit_for_of_expression(self, node: Any) -> T:
        raise NotImplementedError

    def visit_at_expression(self, node: Any) -> T:
        raise NotImplementedError

    def visit_in_expression(self, node: Any) -> T:
        raise NotImplementedError

    def visit_of_expression(self, node: Any) -> T:
        raise NotImplementedError

    def visit_meta(self, node: Any) -> T:
        raise NotImplementedError

    def visit_module_reference(self, node: Any) -> T:
        raise NotImplementedError

    def visit_dictionary_access(self, node: Any) -> T:
        raise NotImplementedError

    def visit_comment(self, node: Any) -> T:
        raise NotImplementedError

    def visit_comment_group(self, node: Any) -> T:
        raise NotImplementedError

    def visit_defined_expression(self, node: Any) -> T:
        raise NotImplementedError

    def visit_string_operator_expression(self, node: Any) -> T:
        raise NotImplementedError

    def visit_extern_rule(self, node: Any) -> T:
        raise NotImplementedError

    def visit_extern_rule_reference(self, node: Any) -> T:
        raise NotImplementedError

    def visit_extern_import(self, node: Any) -> T:
        raise NotImplementedError

    def visit_extern_namespace(self, node: Any) -> T:
        raise NotImplementedError

    def visit_pragma(self, node: Any) -> T:
        raise NotImplementedError

    def visit_in_rule_pragma(self, node: Any) -> T:
        raise NotImplementedError

    def visit_pragma_block(self, node: Any) -> T:
        raise NotImplementedError
