"""Trivial node helpers for HTML tree visualization."""

from __future__ import annotations

from typing import Any


class HtmlTreeNodesTrivialMixin:
    """Mixin providing trivial HTML tree node helpers."""

    def visit_string_definition(self, node) -> dict[str, Any]:
        return self._simple_node("String Definition", "string")

    def visit_hex_token(self, node) -> dict[str, Any]:
        return self._simple_node("Hex Token", "hex-token")

    def visit_hex_jump(self, node) -> dict[str, Any]:
        return self._simple_node("Hex Jump", "hex-jump")

    def visit_hex_alternative(self, node) -> dict[str, Any]:
        return self._simple_node("Hex Alternative", "hex-alt")

    def visit_hex_nibble(self, node) -> dict[str, Any]:
        return self._simple_node("Hex Nibble", "hex-nibble")

    def visit_expression(self, node) -> dict[str, Any]:
        return self._simple_expression_node("Expression")

    def visit_identifier(self, node) -> dict[str, Any]:
        return self._simple_expression_node("Identifier", value=node.name)

    def visit_string_count(self, node) -> dict[str, Any]:
        return self._simple_expression_node("String Count")

    def visit_string_offset(self, node) -> dict[str, Any]:
        return self._simple_expression_node("String Offset")

    def visit_string_length(self, node) -> dict[str, Any]:
        return self._simple_expression_node("String Length")

    def visit_double_literal(self, node) -> dict[str, Any]:
        return self._simple_literal_node("Double Literal")

    def visit_string_literal(self, node) -> dict[str, Any]:
        return self._simple_literal_node("String Literal")

    def visit_regex_literal(self, node) -> dict[str, Any]:
        return self._simple_literal_node("Regex Literal")

    def visit_unary_expression(self, node) -> dict[str, Any]:
        return self._simple_expression_node("Unary Expression")

    def visit_parentheses_expression(self, node) -> dict[str, Any]:
        return self._simple_expression_node("Parentheses Expression")

    def visit_set_expression(self, node) -> dict[str, Any]:
        return self._simple_expression_node("Set Expression")

    def visit_range_expression(self, node) -> dict[str, Any]:
        return self._simple_expression_node("Range Expression")

    def visit_function_call(self, node) -> dict[str, Any]:
        return self._simple_expression_node("Function Call")

    def visit_array_access(self, node) -> dict[str, Any]:
        return self._simple_expression_node("Array Access")

    def visit_member_access(self, node) -> dict[str, Any]:
        return self._simple_expression_node("Member Access")

    def visit_for_expression(self, node) -> dict[str, Any]:
        return self._simple_expression_node("For Expression")

    def visit_for_of_expression(self, node) -> dict[str, Any]:
        return self._simple_expression_node("For-Of Expression")

    def visit_at_expression(self, node) -> dict[str, Any]:
        return self._simple_expression_node("At Expression")

    def visit_in_expression(self, node) -> dict[str, Any]:
        return self._simple_expression_node("In Expression")

    def visit_of_expression(self, node) -> dict[str, Any]:
        return self._simple_expression_node("Of Expression")

    def visit_meta(self, node) -> dict[str, Any]:
        return self._simple_meta_node("Meta")

    def visit_module_reference(self, node) -> dict[str, Any]:
        return self._simple_expression_node("Module Reference")

    def visit_dictionary_access(self, node) -> dict[str, Any]:
        return self._simple_expression_node("Dictionary Access")

    def visit_comment(self, node) -> dict[str, Any]:
        return self._simple_comment_node("Comment")

    def visit_comment_group(self, node) -> dict[str, Any]:
        return self._simple_comment_node("Comment Group")

    def visit_defined_expression(self, node) -> dict[str, Any]:
        return self._simple_expression_node("Defined Expression")

    def visit_string_operator_expression(self, node) -> dict[str, Any]:
        return self._simple_expression_node("String Operator Expression")

    def visit_extern_import(self, node) -> dict[str, Any]:
        """Visit ExternImport node."""
        return {
            "id": self._get_node_id(),
            "label": "Extern Import",
            "node_class": "import",
        }

    def visit_extern_namespace(self, node) -> dict[str, Any]:
        """Visit ExternNamespace node."""
        return {
            "id": self._get_node_id(),
            "label": "Extern Namespace",
            "node_class": "namespace",
        }

    def visit_extern_rule(self, node) -> dict[str, Any]:
        """Visit ExternRule node."""
        return {"id": self._get_node_id(), "label": "Extern Rule", "node_class": "rule"}

    def visit_extern_rule_reference(self, node) -> dict[str, Any]:
        """Visit ExternRuleReference node."""
        return self._simple_expression_node("Extern Rule Reference")

    def visit_in_rule_pragma(self, node) -> dict[str, Any]:
        """Visit InRulePragma node."""
        return self._simple_pragma_node("In-Rule Pragma")

    def visit_pragma(self, node) -> dict[str, Any]:
        """Visit Pragma node."""
        return self._simple_pragma_node("Pragma")

    def visit_pragma_block(self, node) -> dict[str, Any]:
        """Visit PragmaBlock node."""
        return self._simple_pragma_node("Pragma Block")

    def visit_boolean_literal(self, node) -> dict[str, Any]:
        """Visit boolean literal node."""
        return self._simple_literal_node("Boolean Literal", value=str(node.value).lower())

    def visit_integer_literal(self, node) -> dict[str, Any]:
        """Visit integer literal node."""
        return self._simple_literal_node("Integer Literal", value=str(node.value))

    # Required visitor methods (minimal implementations)

    def visit_tag(self, node) -> dict[str, Any]:
        """Visit tag node."""
        return {
            "id": self._get_node_id(),
            "label": f"Tag: {node.name}",
            "node_class": "tag",
            "value": node.name,
        }

    def visit_string_modifier(self, node) -> dict[str, Any]:
        """Visit string modifier node."""
        value = f"{node.name}"
        if node.value:
            value += f"({node.value})"

        return {
            "id": self._get_node_id(),
            "label": "Modifier",
            "node_class": "modifier",
            "value": value,
        }

    def visit_hex_byte(self, node) -> dict[str, Any]:
        """Visit hex byte node."""
        return {
            "id": self._get_node_id(),
            "label": "Hex Byte",
            "node_class": "hex-byte",
            "value": str(node.value),
        }
