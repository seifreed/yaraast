"""Coverage tests for trivial HTML tree node visitors."""

from __future__ import annotations

from types import SimpleNamespace

from yaraast.metrics.html_tree import HtmlTreeGenerator


def test_trivial_visitors_return_serializable_nodes() -> None:
    gen = HtmlTreeGenerator()
    node = SimpleNamespace()

    method_names = [
        "visit_string_definition",
        "visit_hex_token",
        "visit_hex_jump",
        "visit_hex_alternative",
        "visit_hex_nibble",
        "visit_expression",
        "visit_string_count",
        "visit_string_offset",
        "visit_string_length",
        "visit_double_literal",
        "visit_string_literal",
        "visit_regex_literal",
        "visit_unary_expression",
        "visit_parentheses_expression",
        "visit_set_expression",
        "visit_range_expression",
        "visit_function_call",
        "visit_array_access",
        "visit_member_access",
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
        "visit_extern_rule_reference",
        "visit_in_rule_pragma",
        "visit_pragma",
        "visit_pragma_block",
    ]

    for method_name in method_names:
        out = getattr(gen, method_name)(node)
        assert isinstance(out, dict)
        assert "id" in out
        assert "label" in out
        assert "node_class" in out

    identifier = gen.visit_identifier(SimpleNamespace(name="field_name"))
    assert identifier["value"] == "field_name"

    ext_import = gen.visit_extern_import(node)
    ext_namespace = gen.visit_extern_namespace(node)
    ext_rule = gen.visit_extern_rule(node)
    assert ext_import["node_class"] == "import"
    assert ext_namespace["node_class"] == "namespace"
    assert ext_rule["node_class"] == "rule"

    boolean_literal = gen.visit_boolean_literal(SimpleNamespace(value=True))
    integer_literal = gen.visit_integer_literal(SimpleNamespace(value=123))
    assert boolean_literal["value"] == "true"
    assert integer_literal["value"] == "123"

    tag = gen.visit_tag(SimpleNamespace(name="malware"))
    assert tag["value"] == "malware"

    modifier_with_value = gen.visit_string_modifier(SimpleNamespace(name="xor", value="0x10"))
    modifier_without_value = gen.visit_string_modifier(SimpleNamespace(name="wide", value=None))
    assert modifier_with_value["value"] == "xor(0x10)"
    assert modifier_without_value["value"] == "wide"

    hex_byte = gen.visit_hex_byte(SimpleNamespace(value=255))
    assert hex_byte["value"] == "255"
