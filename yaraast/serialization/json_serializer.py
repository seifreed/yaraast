"""Enhanced JSON serialization for YARA AST."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from yaraast.ast.base import ASTNode, Location
from yaraast.config import JSON_DEFAULT_INDENT
from yaraast.errors import SerializationError
from yaraast.serialization.json_serialize_visitors import (
    _serialize_nullable_string,
    _serialize_required_bool,
    _serialize_required_expression,
    _serialize_required_int,
    _serialize_required_number,
    _serialize_required_string,
    visit_array_access,
    visit_array_comprehension,
    visit_at_expression,
    visit_binary_expression,
    visit_comment_group,
    visit_dict_comprehension,
    visit_dict_expression,
    visit_dict_item,
    visit_dictionary_access,
    visit_for_expression,
    visit_for_of_expression,
    visit_function_call,
    visit_hex_alternative,
    visit_hex_string,
    visit_in_expression,
    visit_lambda_expression,
    visit_list_expression,
    visit_match_case,
    visit_member_access,
    visit_of_expression,
    visit_parentheses_expression,
    visit_pattern_match,
    visit_plain_string,
    visit_pragma_block,
    visit_range_expression,
    visit_regex_string,
    visit_rule,
    visit_set_expression,
    visit_slice_expression,
    visit_spread_operator,
    visit_string_length,
    visit_string_offset,
    visit_string_operator_expression,
    visit_tuple_expression,
    visit_tuple_indexing,
    visit_unary_expression,
    visit_with_declaration,
    visit_with_statement,
    visit_yara_file,
)
from yaraast.serialization.json_serializer_deserialize import (
    JsonSerializerDeserializeMixin,
    _deserialize_list_field,
    _deserialize_object,
)
from yaraast.serialization.serializer_helpers import build_base_metadata, read_text, write_text
from yaraast.visitor.visitor import ASTVisitor

if TYPE_CHECKING:
    from yaraast.ast.base import YaraFile


def _serialize_modifier_value(value: Any) -> Any:
    if isinstance(value, tuple):
        return list(value)
    return value


class JsonSerializer(JsonSerializerDeserializeMixin, ASTVisitor[dict[str, Any]]):
    """Enhanced JSON serializer for YARA AST with metadata."""

    def __init__(self, include_metadata: bool = True) -> None:
        self.include_metadata = include_metadata

    def visit(self, node: ASTNode) -> dict[str, Any]:
        """Visit a node and attach common AST metadata when present."""
        return self._with_node_metadata(node, super().visit(node))

    def _serialize_location(self, location: Location) -> dict[str, Any]:
        data: dict[str, Any] = {"line": location.line, "column": location.column}
        if location.file is not None:
            data["file"] = location.file
        if location.end_line is not None:
            data["end_line"] = location.end_line
        if location.end_column is not None:
            data["end_column"] = location.end_column
        return data

    def _with_node_metadata(self, node: ASTNode, data: dict[str, Any]) -> dict[str, Any]:
        if node.location is not None:
            data["location"] = self._serialize_location(node.location)
        if node.leading_comments:
            data["leading_comments"] = [self.visit(comment) for comment in node.leading_comments]
        if node.trailing_comment is not None:
            data["trailing_comment"] = self.visit(node.trailing_comment)
        return data

    def serialize(self, ast: YaraFile, output_path: str | Path | None = None) -> str:
        """Serialize AST to JSON format."""
        serialized = self._serialize_with_metadata(ast)
        json_str = json.dumps(serialized, indent=JSON_DEFAULT_INDENT, ensure_ascii=False)

        if output_path:
            write_text(output_path, json_str)

        return json_str

    def deserialize(
        self,
        json_str: str | None = None,
        input_path: str | Path | None = None,
    ) -> YaraFile:
        """Deserialize JSON to AST."""
        if input_path:
            json_str = read_text(input_path)

        if not json_str:
            msg = "No JSON input provided"
            raise SerializationError(msg)

        try:
            data = json.loads(json_str)
        except json.JSONDecodeError as exc:
            msg = "Invalid JSON input"
            raise SerializationError(msg) from exc
        return self._deserialize_ast(data)

    def _serialize_with_metadata(self, ast: YaraFile) -> dict[str, Any]:
        """Serialize with metadata."""
        result = {"ast": self.visit(ast)}

        if self.include_metadata:
            result["metadata"] = build_base_metadata(ast, "yaraast-json")

        return result

    def _deserialize_ast(self, data: dict[str, Any]) -> YaraFile:
        """Deserialize JSON data to AST."""
        from yaraast.ast.base import YaraFile

        data = _deserialize_object(data, "YaraFile")
        # Handle both wrapped (with metadata) and direct AST data
        ast_data = data.get("ast", data)
        ast_data = _deserialize_object(ast_data, "YaraFile")
        if ast_data.get("type") != "YaraFile":
            msg = f"Expected YaraFile, got {ast_data.get('type')}"
            raise SerializationError(msg)

        imports = [
            self._deserialize_import(imp)
            for imp in _deserialize_list_field(ast_data, "imports", "YaraFile")
        ]
        includes = [
            self._deserialize_include(inc)
            for inc in _deserialize_list_field(ast_data, "includes", "YaraFile")
        ]
        rules = [
            self._deserialize_rule(rule)
            for rule in _deserialize_list_field(ast_data, "rules", "YaraFile")
        ]

        kwargs: dict = {"imports": imports, "includes": includes, "rules": rules}
        if "extern_rules" in ast_data:
            kwargs["extern_rules"] = [
                self._deserialize_extern_rule(rule)
                for rule in _deserialize_list_field(ast_data, "extern_rules", "YaraFile")
            ]
        if "extern_imports" in ast_data:
            kwargs["extern_imports"] = [
                self._deserialize_extern_import(imp)
                for imp in _deserialize_list_field(ast_data, "extern_imports", "YaraFile")
            ]
        if "pragmas" in ast_data:
            kwargs["pragmas"] = [
                self._deserialize_pragma(pragma)
                for pragma in _deserialize_list_field(ast_data, "pragmas", "YaraFile")
            ]
        if "namespaces" in ast_data:
            kwargs["namespaces"] = [
                self._deserialize_extern_namespace(namespace)
                for namespace in _deserialize_list_field(ast_data, "namespaces", "YaraFile")
            ]
        return self._apply_node_metadata(YaraFile(**kwargs), ast_data)

    def _simple_node(self, type_name: str, **fields: Any) -> dict[str, Any]:
        payload = {"type": type_name}
        payload.update(fields)
        return payload

    def visit_yara_file(self, node) -> dict[str, Any]:
        return visit_yara_file(self, node)

    def visit_import(self, node) -> dict[str, Any]:
        return self._simple_node(
            "Import",
            module=_serialize_required_string(node.module, "Import module"),
            alias=_serialize_nullable_string(getattr(node, "alias", None), "Import alias"),
        )

    def visit_include(self, node) -> dict[str, Any]:
        return self._simple_node(
            "Include",
            path=_serialize_required_string(node.path, "Include path"),
        )

    def visit_rule(self, node) -> dict[str, Any]:
        return visit_rule(self, node)

    def visit_tag(self, node) -> dict[str, Any]:
        return self._simple_node("Tag", name=_serialize_required_string(node.name, "Tag name"))

    def visit_string_definition(self, node) -> dict[str, Any]:
        return self._simple_node(
            "StringDefinition",
            identifier=_serialize_required_string(node.identifier, "StringDefinition identifier"),
        )

    def visit_plain_string(self, node) -> dict[str, Any]:
        return visit_plain_string(self, node)

    def visit_hex_string(self, node) -> dict[str, Any]:
        return visit_hex_string(self, node)

    def visit_regex_string(self, node) -> dict[str, Any]:
        return visit_regex_string(self, node)

    def visit_string_modifier(self, node) -> dict[str, Any]:
        return self._simple_node(
            "StringModifier",
            name=node.name,
            value=_serialize_modifier_value(node.value),
        )

    def visit_hex_token(self, node) -> dict[str, Any]:
        return self._simple_node("HexToken")

    def visit_hex_byte(self, node) -> dict[str, Any]:
        return self._simple_node("HexByte", value=node.value)

    def visit_hex_negated_byte(self, node) -> dict[str, Any]:
        return self._simple_node("HexNegatedByte", value=node.value)

    def visit_hex_wildcard(self, node) -> dict[str, Any]:
        return self._simple_node("HexWildcard")

    def visit_hex_jump(self, node) -> dict[str, Any]:
        return self._simple_node("HexJump", min_jump=node.min_jump, max_jump=node.max_jump)

    def visit_hex_alternative(self, node) -> dict[str, Any]:
        return visit_hex_alternative(self, node)

    def visit_hex_nibble(self, node) -> dict[str, Any]:
        return self._simple_node("HexNibble", high=node.high, value=node.value)

    # Expression visitor methods (simplified)
    def visit_expression(self, node) -> dict[str, Any]:
        return self._simple_node("Expression")

    def visit_identifier(self, node) -> dict[str, Any]:
        return self._simple_node(
            "Identifier",
            name=_serialize_required_string(node.name, "Identifier name"),
        )

    def visit_string_identifier(self, node) -> dict[str, Any]:
        return self._simple_node(
            "StringIdentifier",
            name=_serialize_required_string(node.name, "StringIdentifier name"),
        )

    def visit_string_wildcard(self, node) -> dict[str, Any]:
        return self._simple_node(
            "StringWildcard",
            pattern=_serialize_required_string(node.pattern, "StringWildcard pattern"),
        )

    def visit_string_count(self, node) -> dict[str, Any]:
        return self._simple_node(
            "StringCount",
            string_id=_serialize_required_string(node.string_id, "StringCount string_id"),
        )

    def visit_string_offset(self, node) -> dict[str, Any]:
        return visit_string_offset(self, node)

    def visit_string_length(self, node) -> dict[str, Any]:
        return visit_string_length(self, node)

    def visit_integer_literal(self, node) -> dict[str, Any]:
        return self._simple_node(
            "IntegerLiteral",
            value=_serialize_required_int(node.value, "IntegerLiteral value"),
        )

    def visit_double_literal(self, node) -> dict[str, Any]:
        return self._simple_node(
            "DoubleLiteral",
            value=_serialize_required_number(node.value, "DoubleLiteral value"),
        )

    def visit_string_literal(self, node) -> dict[str, Any]:
        return self._simple_node(
            "StringLiteral",
            value=_serialize_required_string(node.value, "StringLiteral value"),
        )

    def visit_regex_literal(self, node) -> dict[str, Any]:
        return {
            "type": "RegexLiteral",
            "pattern": _serialize_required_string(node.pattern, "RegexLiteral pattern"),
            "modifiers": _serialize_required_string(node.modifiers, "RegexLiteral modifiers"),
        }

    def visit_boolean_literal(self, node) -> dict[str, Any]:
        return self._simple_node(
            "BooleanLiteral",
            value=_serialize_required_bool(node.value, "BooleanLiteral value"),
        )

    def visit_binary_expression(self, node) -> dict[str, Any]:
        return visit_binary_expression(self, node)

    def visit_unary_expression(self, node) -> dict[str, Any]:
        return visit_unary_expression(self, node)

    def visit_parentheses_expression(self, node) -> dict[str, Any]:
        return visit_parentheses_expression(self, node)

    def visit_set_expression(self, node) -> dict[str, Any]:
        return visit_set_expression(self, node)

    def visit_range_expression(self, node) -> dict[str, Any]:
        return visit_range_expression(self, node)

    def visit_function_call(self, node) -> dict[str, Any]:
        return visit_function_call(self, node)

    def visit_array_access(self, node) -> dict[str, Any]:
        return visit_array_access(self, node)

    def visit_member_access(self, node) -> dict[str, Any]:
        return visit_member_access(self, node)

    def visit_condition(self, node) -> dict[str, Any]:
        return self._simple_node("Condition")

    def visit_for_expression(self, node) -> dict[str, Any]:
        return visit_for_expression(self, node)

    def visit_for_of_expression(self, node) -> dict[str, Any]:
        return visit_for_of_expression(self, node)

    def visit_at_expression(self, node) -> dict[str, Any]:
        return visit_at_expression(self, node)

    def visit_in_expression(self, node) -> dict[str, Any]:
        return visit_in_expression(self, node)

    def visit_of_expression(self, node) -> dict[str, Any]:
        return visit_of_expression(self, node)

    def visit_meta(self, node) -> dict[str, Any]:
        data = self._simple_node("Meta", key=node.key, value=node.value)
        scope = getattr(node, "scope", None)
        if scope is not None:
            data["scope"] = getattr(scope, "value", str(scope))
        return data

    def visit_module_reference(self, node) -> dict[str, Any]:
        return self._simple_node(
            "ModuleReference",
            module=_serialize_required_string(node.module, "ModuleReference module"),
        )

    def visit_dictionary_access(self, node) -> dict[str, Any]:
        return visit_dictionary_access(self, node)

    def visit_comment(self, node) -> dict[str, Any]:
        return self._simple_node("Comment", text=node.text, is_multiline=node.is_multiline)

    def visit_comment_group(self, node) -> dict[str, Any]:
        return visit_comment_group(self, node)

    def visit_defined_expression(self, node) -> dict[str, Any]:
        return self._simple_node(
            "DefinedExpression",
            expression=_serialize_required_expression(
                self,
                node.expression,
                "DefinedExpression expression",
            ),
        )

    def visit_string_operator_expression(self, node) -> dict[str, Any]:
        return visit_string_operator_expression(self, node)

    # Add missing abstract methods
    def visit_extern_import(self, node) -> dict[str, Any]:
        return self._simple_node(
            "ExternImport",
            module_path=node.module_path,
            alias=node.alias,
            rules=list(node.rules),
        )

    def visit_extern_namespace(self, node) -> dict[str, Any]:
        return self._simple_node(
            "ExternNamespace",
            name=node.name,
            extern_rules=[self.visit(rule) for rule in node.extern_rules],
        )

    def visit_extern_rule(self, node) -> dict[str, Any]:
        return {
            "type": "ExternRule",
            "name": node.name,
            "modifiers": [str(modifier) for modifier in node.modifiers],
            "namespace": node.namespace,
        }

    def visit_extern_rule_reference(self, node) -> dict[str, Any]:
        return {
            "type": "ExternRuleReference",
            "rule_name": node.rule_name,
            "namespace": node.namespace,
        }

    def visit_in_rule_pragma(self, node) -> dict[str, Any]:
        return {
            "type": "InRulePragma",
            "pragma": self.visit(node.pragma),
            "position": node.position,
        }

    def visit_pragma(self, node) -> dict[str, Any]:
        data = {
            "type": "Pragma",
            "pragma_type": node.pragma_type.value,
            "name": node.name,
            "arguments": list(node.arguments),
            "scope": node.scope.value,
        }
        if hasattr(node, "macro_name"):
            data["macro_name"] = node.macro_name
        if hasattr(node, "macro_value"):
            data["macro_value"] = node.macro_value
        if hasattr(node, "condition"):
            data["condition"] = node.condition
        if hasattr(node, "parameters"):
            data["parameters"] = dict(node.parameters)
        return data

    def visit_pragma_block(self, node) -> dict[str, Any]:
        return visit_pragma_block(self, node)

    def visit_with_statement(self, node) -> dict[str, Any]:
        return visit_with_statement(self, node)

    def visit_with_declaration(self, node) -> dict[str, Any]:
        return visit_with_declaration(self, node)

    def visit_array_comprehension(self, node) -> dict[str, Any]:
        return visit_array_comprehension(self, node)

    def visit_dict_comprehension(self, node) -> dict[str, Any]:
        return visit_dict_comprehension(self, node)

    def visit_tuple_expression(self, node) -> dict[str, Any]:
        return visit_tuple_expression(self, node)

    def visit_tuple_indexing(self, node) -> dict[str, Any]:
        return visit_tuple_indexing(self, node)

    def visit_list_expression(self, node) -> dict[str, Any]:
        return visit_list_expression(self, node)

    def visit_dict_expression(self, node) -> dict[str, Any]:
        return visit_dict_expression(self, node)

    def visit_dict_item(self, node) -> dict[str, Any]:
        return visit_dict_item(self, node)

    def visit_slice_expression(self, node) -> dict[str, Any]:
        return visit_slice_expression(self, node)

    def visit_lambda_expression(self, node) -> dict[str, Any]:
        return visit_lambda_expression(self, node)

    def visit_pattern_match(self, node) -> dict[str, Any]:
        return visit_pattern_match(self, node)

    def visit_match_case(self, node) -> dict[str, Any]:
        return visit_match_case(self, node)

    def visit_spread_operator(self, node) -> dict[str, Any]:
        return visit_spread_operator(self, node)
