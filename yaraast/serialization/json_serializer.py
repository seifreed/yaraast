"""Enhanced JSON serialization for YARA AST."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from yaraast.serialization.json_serialize_visitors import (
    visit_array_access as helper_visit_array_access,
)
from yaraast.serialization.json_serialize_visitors import (
    visit_at_expression as helper_visit_at_expression,
)
from yaraast.serialization.json_serialize_visitors import (
    visit_binary_expression as helper_visit_binary_expression,
)
from yaraast.serialization.json_serialize_visitors import (
    visit_comment_group as helper_visit_comment_group,
)
from yaraast.serialization.json_serialize_visitors import (
    visit_dictionary_access as helper_visit_dictionary_access,
)
from yaraast.serialization.json_serialize_visitors import (
    visit_for_expression as helper_visit_for_expression,
)
from yaraast.serialization.json_serialize_visitors import (
    visit_for_of_expression as helper_visit_for_of_expression,
)
from yaraast.serialization.json_serialize_visitors import (
    visit_function_call as helper_visit_function_call,
)
from yaraast.serialization.json_serialize_visitors import (
    visit_hex_alternative as helper_visit_hex_alternative,
)
from yaraast.serialization.json_serialize_visitors import (
    visit_hex_string as helper_visit_hex_string,
)
from yaraast.serialization.json_serialize_visitors import (
    visit_in_expression as helper_visit_in_expression,
)
from yaraast.serialization.json_serialize_visitors import (
    visit_member_access as helper_visit_member_access,
)
from yaraast.serialization.json_serialize_visitors import (
    visit_of_expression as helper_visit_of_expression,
)
from yaraast.serialization.json_serialize_visitors import (
    visit_parentheses_expression as helper_visit_parentheses_expression,
)
from yaraast.serialization.json_serialize_visitors import (
    visit_plain_string as helper_visit_plain_string,
)
from yaraast.serialization.json_serialize_visitors import (
    visit_pragma_block as helper_visit_pragma_block,
)
from yaraast.serialization.json_serialize_visitors import (
    visit_range_expression as helper_visit_range_expression,
)
from yaraast.serialization.json_serialize_visitors import (
    visit_regex_string as helper_visit_regex_string,
)
from yaraast.serialization.json_serialize_visitors import visit_rule as helper_visit_rule
from yaraast.serialization.json_serialize_visitors import (
    visit_set_expression as helper_visit_set_expression,
)
from yaraast.serialization.json_serialize_visitors import (
    visit_string_length as helper_visit_string_length,
)
from yaraast.serialization.json_serialize_visitors import (
    visit_string_offset as helper_visit_string_offset,
)
from yaraast.serialization.json_serialize_visitors import (
    visit_string_operator_expression as helper_visit_string_operator_expression,
)
from yaraast.serialization.json_serialize_visitors import (
    visit_unary_expression as helper_visit_unary_expression,
)
from yaraast.serialization.json_serialize_visitors import visit_yara_file as helper_visit_yara_file
from yaraast.serialization.json_serializer_deserialize import JsonSerializerDeserializeMixin
from yaraast.serialization.serializer_helpers import build_base_metadata, read_text, write_text
from yaraast.visitor.visitor import ASTVisitor

if TYPE_CHECKING:
    from yaraast.ast.base import YaraFile


class JsonSerializer(JsonSerializerDeserializeMixin, ASTVisitor[dict[str, Any]]):
    """Enhanced JSON serializer for YARA AST with metadata."""

    def __init__(self, include_metadata: bool = True) -> None:
        self.include_metadata = include_metadata

    def serialize(self, ast: YaraFile, output_path: str | Path | None = None) -> str:
        """Serialize AST to JSON format."""
        serialized = self._serialize_with_metadata(ast)
        json_str = json.dumps(serialized, indent=2, ensure_ascii=False)

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
            raise ValueError(msg)

        data = json.loads(json_str)
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

        # Handle both wrapped (with metadata) and direct AST data
        ast_data = data.get("ast", data)
        if ast_data.get("type") != "YaraFile":
            msg = f"Expected YaraFile, got {ast_data.get('type')}"
            raise ValueError(msg)

        imports = [self._deserialize_import(imp) for imp in ast_data.get("imports", [])]
        includes = [self._deserialize_include(inc) for inc in ast_data.get("includes", [])]
        rules = [self._deserialize_rule(rule) for rule in ast_data.get("rules", [])]

        kwargs: dict = {"imports": imports, "includes": includes, "rules": rules}
        for field_name in ("extern_rules", "extern_imports", "pragmas", "namespaces"):
            if field_name in ast_data and ast_data[field_name]:
                kwargs[field_name] = ast_data[field_name]
        return YaraFile(**kwargs)

    def _simple_node(self, type_name: str, **fields: Any) -> dict[str, Any]:
        payload = {"type": type_name}
        payload.update(fields)
        return payload

    def visit_yara_file(self, node) -> dict[str, Any]:
        return helper_visit_yara_file(self, node)

    def visit_import(self, node) -> dict[str, Any]:
        return self._simple_node("Import", module=node.module, alias=getattr(node, "alias", None))

    def visit_include(self, node) -> dict[str, Any]:
        return self._simple_node("Include", path=node.path)

    def visit_rule(self, node) -> dict[str, Any]:
        return helper_visit_rule(self, node)

    def visit_tag(self, node) -> dict[str, Any]:
        return self._simple_node("Tag", name=node.name)

    def visit_string_definition(self, node) -> dict[str, Any]:
        return self._simple_node("StringDefinition", identifier=node.identifier)

    def visit_plain_string(self, node) -> dict[str, Any]:
        return helper_visit_plain_string(self, node)

    def visit_hex_string(self, node) -> dict[str, Any]:
        return helper_visit_hex_string(self, node)

    def visit_regex_string(self, node) -> dict[str, Any]:
        return helper_visit_regex_string(self, node)

    def visit_string_modifier(self, node) -> dict[str, Any]:
        return self._simple_node("StringModifier", name=node.name, value=node.value)

    def visit_hex_token(self, node) -> dict[str, Any]:
        return self._simple_node("HexToken")

    def visit_hex_byte(self, node) -> dict[str, Any]:
        return self._simple_node("HexByte", value=node.value)

    def visit_hex_wildcard(self, node) -> dict[str, Any]:
        return self._simple_node("HexWildcard")

    def visit_hex_jump(self, node) -> dict[str, Any]:
        return self._simple_node("HexJump", min_jump=node.min_jump, max_jump=node.max_jump)

    def visit_hex_alternative(self, node) -> dict[str, Any]:
        return helper_visit_hex_alternative(self, node)

    def visit_hex_nibble(self, node) -> dict[str, Any]:
        return self._simple_node("HexNibble", high=node.high, value=node.value)

    # Expression visitor methods (simplified)
    def visit_expression(self, node) -> dict[str, Any]:
        return self._simple_node("Expression")

    def visit_identifier(self, node) -> dict[str, Any]:
        return self._simple_node("Identifier", name=node.name)

    def visit_string_identifier(self, node) -> dict[str, Any]:
        return self._simple_node("StringIdentifier", name=node.name)

    def visit_string_wildcard(self, node) -> dict[str, Any]:
        return self._simple_node("StringWildcard", pattern=node.pattern)

    def visit_string_count(self, node) -> dict[str, Any]:
        return self._simple_node("StringCount", string_id=node.string_id)

    def visit_string_offset(self, node) -> dict[str, Any]:
        return helper_visit_string_offset(self, node)

    def visit_string_length(self, node) -> dict[str, Any]:
        return helper_visit_string_length(self, node)

    def visit_integer_literal(self, node) -> dict[str, Any]:
        return self._simple_node("IntegerLiteral", value=node.value)

    def visit_double_literal(self, node) -> dict[str, Any]:
        return self._simple_node("DoubleLiteral", value=node.value)

    def visit_string_literal(self, node) -> dict[str, Any]:
        return self._simple_node("StringLiteral", value=node.value)

    def visit_regex_literal(self, node) -> dict[str, Any]:
        return {
            "type": "RegexLiteral",
            "pattern": node.pattern,
            "modifiers": node.modifiers,
        }

    def visit_boolean_literal(self, node) -> dict[str, Any]:
        return self._simple_node("BooleanLiteral", value=node.value)

    def visit_binary_expression(self, node) -> dict[str, Any]:
        return helper_visit_binary_expression(self, node)

    def visit_unary_expression(self, node) -> dict[str, Any]:
        return helper_visit_unary_expression(self, node)

    def visit_parentheses_expression(self, node) -> dict[str, Any]:
        return helper_visit_parentheses_expression(self, node)

    def visit_set_expression(self, node) -> dict[str, Any]:
        return helper_visit_set_expression(self, node)

    def visit_range_expression(self, node) -> dict[str, Any]:
        return helper_visit_range_expression(self, node)

    def visit_function_call(self, node) -> dict[str, Any]:
        return helper_visit_function_call(self, node)

    def visit_array_access(self, node) -> dict[str, Any]:
        return helper_visit_array_access(self, node)

    def visit_member_access(self, node) -> dict[str, Any]:
        return helper_visit_member_access(self, node)

    def visit_condition(self, node) -> dict[str, Any]:
        return self._simple_node("Condition")

    def visit_for_expression(self, node) -> dict[str, Any]:
        return helper_visit_for_expression(self, node)

    def visit_for_of_expression(self, node) -> dict[str, Any]:
        return helper_visit_for_of_expression(self, node)

    def visit_at_expression(self, node) -> dict[str, Any]:
        return helper_visit_at_expression(self, node)

    def visit_in_expression(self, node) -> dict[str, Any]:
        return helper_visit_in_expression(self, node)

    def visit_of_expression(self, node) -> dict[str, Any]:
        return helper_visit_of_expression(self, node)

    def visit_meta(self, node) -> dict[str, Any]:
        return self._simple_node("Meta", key=node.key, value=node.value)

    def visit_module_reference(self, node) -> dict[str, Any]:
        return self._simple_node("ModuleReference", module=node.module)

    def visit_dictionary_access(self, node) -> dict[str, Any]:
        return helper_visit_dictionary_access(self, node)

    def visit_comment(self, node) -> dict[str, Any]:
        return self._simple_node("Comment", text=node.text, is_multiline=node.is_multiline)

    def visit_comment_group(self, node) -> dict[str, Any]:
        return helper_visit_comment_group(self, node)

    def visit_defined_expression(self, node) -> dict[str, Any]:
        return self._simple_node("DefinedExpression", expression=self.visit(node.expression))

    def visit_string_operator_expression(self, node) -> dict[str, Any]:
        return helper_visit_string_operator_expression(self, node)

    # Add missing abstract methods
    def visit_extern_import(self, node) -> dict[str, Any]:
        return self._simple_node(
            "ExternImport",
            module=node.module if hasattr(node, "module") else None,
        )

    def visit_extern_namespace(self, node) -> dict[str, Any]:
        return self._simple_node(
            "ExternNamespace",
            name=node.name if hasattr(node, "name") else None,
        )

    def visit_extern_rule(self, node) -> dict[str, Any]:
        return {
            "type": "ExternRule",
            "name": node.name if hasattr(node, "name") else None,
        }

    def visit_extern_rule_reference(self, node) -> dict[str, Any]:
        return {
            "type": "ExternRuleReference",
            "name": node.name if hasattr(node, "name") else None,
        }

    def visit_in_rule_pragma(self, node) -> dict[str, Any]:
        return {
            "type": "InRulePragma",
            "pragma": node.pragma if hasattr(node, "pragma") else None,
        }

    def visit_pragma(self, node) -> dict[str, Any]:
        return {
            "type": "Pragma",
            "directive": node.directive if hasattr(node, "directive") else None,
        }

    def visit_pragma_block(self, node) -> dict[str, Any]:
        return helper_visit_pragma_block(self, node)
