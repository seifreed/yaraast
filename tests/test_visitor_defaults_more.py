"""Additional branch coverage for DefaultASTVisitor default methods."""

from __future__ import annotations

from types import SimpleNamespace

from yaraast.visitor.defaults import DefaultASTVisitor


def test_default_ast_visitor_all_methods_return_default() -> None:
    marker = object()
    visitor = DefaultASTVisitor(marker)
    node = SimpleNamespace()

    methods = [
        "visit_yara_file",
        "visit_import",
        "visit_include",
        "visit_rule",
        "visit_tag",
        "visit_string_definition",
        "visit_plain_string",
        "visit_hex_string",
        "visit_regex_string",
        "visit_string_modifier",
        "visit_hex_token",
        "visit_hex_byte",
        "visit_hex_wildcard",
        "visit_hex_jump",
        "visit_hex_alternative",
        "visit_hex_nibble",
        "visit_expression",
        "visit_identifier",
        "visit_string_identifier",
        "visit_string_wildcard",
        "visit_string_count",
        "visit_string_offset",
        "visit_string_length",
        "visit_integer_literal",
        "visit_double_literal",
        "visit_string_literal",
        "visit_regex_literal",
        "visit_boolean_literal",
        "visit_binary_expression",
        "visit_unary_expression",
        "visit_parentheses_expression",
        "visit_set_expression",
        "visit_range_expression",
        "visit_function_call",
        "visit_array_access",
        "visit_member_access",
        "visit_condition",
        "visit_for_expression",
        "visit_for_of_expression",
        "visit_at_expression",
        "visit_in_expression",
        "visit_of_expression",
        "visit_meta",
        "visit_module_reference",
        "visit_dictionary_access",
        "visit_comment",
        "visit_comment_group",
        "visit_defined_expression",
        "visit_string_operator_expression",
        "visit_extern_import",
        "visit_extern_namespace",
        "visit_extern_rule",
        "visit_extern_rule_reference",
        "visit_in_rule_pragma",
        "visit_pragma",
        "visit_pragma_block",
    ]

    for method in methods:
        assert getattr(visitor, method)(node) is marker
