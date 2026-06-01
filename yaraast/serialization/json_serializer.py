"""Enhanced JSON serialization for YARA AST."""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import TYPE_CHECKING, Any

from yaraast.ast.base import ASTNode, Location
from yaraast.config import JSON_DEFAULT_INDENT
from yaraast.errors import SerializationError
from yaraast.serialization.json_serialize_visitors import (
    _serialize_anonymous_flag,
    _serialize_hex_byte_value,
    _serialize_hex_jump_bounds,
    _serialize_hex_negated_value,
    _serialize_hex_nibble_high,
    _serialize_hex_nibble_value,
    _serialize_meta_value,
    _serialize_node_list,
    _serialize_nonempty_string_list,
    _serialize_nullable_nonempty_string,
    _serialize_nullable_string,
    _serialize_required_bool,
    _serialize_required_expression,
    _serialize_required_int,
    _serialize_required_nonempty_string,
    _serialize_required_number,
    _serialize_required_string,
    _serialize_rule_modifiers,
    _serialize_string_key_dict,
    _serialize_string_list,
    _serialize_string_modifiers,
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
from yaraast.serialization.meta_scopes import serialize_meta_scope
from yaraast.serialization.pragma_scopes import serialize_pragma_scope
from yaraast.serialization.serializer_helpers import (
    build_base_metadata,
    read_text,
    require_bool_option,
    require_input_path,
    write_text,
)
from yaraast.visitor.visitor import ASTVisitor

if TYPE_CHECKING:
    from yaraast.ast.base import YaraFile


def _serialize_modifier_value(value: Any) -> str | int | float | list[int] | None:
    if value is None or isinstance(value, str):
        return value
    if isinstance(value, bool):
        msg = "StringModifier value must be a string, number, tuple, or null"
        raise SerializationError(msg)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            msg = "StringModifier value must be finite"
            raise SerializationError(msg)
        return value
    if isinstance(value, tuple):
        if (
            len(value) != 2
            or not all(isinstance(item, int) for item in value)
            or any(isinstance(item, bool) for item in value)
        ):
            msg = "StringModifier tuple value must contain two integers"
            raise SerializationError(msg)
        return list(value)
    msg = "StringModifier value must be a string, number, tuple, or null"
    raise SerializationError(msg)


def _serialize_enum_value(value: Any, context: str) -> str:
    if isinstance(value, str):
        return value
    return _serialize_required_string(getattr(value, "value", None), context)


def _serialize_comment_node(serializer, value, context: str) -> dict[str, Any]:
    from yaraast.ast.comments import Comment, CommentGroup

    if not isinstance(value, Comment | CommentGroup):
        msg = f"{context} must be a Comment or CommentGroup node"
        raise SerializationError(msg)
    return serializer.visit(value)


class JsonSerializer(JsonSerializerDeserializeMixin, ASTVisitor[dict[str, Any]]):
    """Enhanced JSON serializer for YARA AST with metadata."""

    def __init__(self, include_metadata: bool = True) -> None:
        self.include_metadata = require_bool_option(include_metadata, "include_metadata")

    @staticmethod
    def _require_yara_file(ast: object) -> YaraFile:
        from yaraast.ast.base import YaraFile

        if not isinstance(ast, YaraFile):
            msg = "ast must be a YaraFile"
            raise TypeError(msg)
        return ast

    def visit(self, node: ASTNode) -> dict[str, Any]:
        """Visit a node and attach common AST metadata when present."""
        if not isinstance(node, ASTNode):
            return super().visit(node)

        from yaraast.ast.base import YaraFile

        serialized = (
            self.visit_yara_file(node) if isinstance(node, YaraFile) else super().visit(node)
        )
        return self._with_node_metadata(node, serialized)

    def _serialize_location(self, location: Location) -> dict[str, Any]:
        data: dict[str, Any] = {
            "line": _serialize_required_int(location.line, "Location line"),
            "column": _serialize_required_int(location.column, "Location column"),
        }
        if location.file is not None:
            data["file"] = _serialize_nullable_string(location.file, "Location file")
        if location.end_line is not None:
            data["end_line"] = _serialize_required_int(location.end_line, "Location end_line")
        if location.end_column is not None:
            data["end_column"] = _serialize_required_int(
                location.end_column,
                "Location end_column",
            )
        return data

    def _with_node_metadata(self, node: ASTNode, data: dict[str, Any]) -> dict[str, Any]:
        from yaraast.ast.comments import Comment, CommentGroup

        if node.location is not None:
            data["location"] = self._serialize_location(node.location)
        if not isinstance(node.leading_comments, list | tuple):
            msg = "leading_comments must be a list of Comment or CommentGroup nodes"
            raise SerializationError(msg)
        if node.leading_comments:
            data["leading_comments"] = _serialize_node_list(
                self,
                node.leading_comments,
                "leading_comments",
                (Comment, CommentGroup),
            )
        if node.trailing_comment is not None:
            data["trailing_comment"] = _serialize_comment_node(
                self,
                node.trailing_comment,
                "trailing_comment",
            )
        return data

    def serialize(self, ast: YaraFile, output_path: str | Path | None = None) -> str:
        """Serialize AST to JSON format."""
        ast = self._require_yara_file(ast)
        serialized = self._serialize_with_metadata(ast)
        json_str = json.dumps(serialized, indent=JSON_DEFAULT_INDENT, ensure_ascii=False)

        if output_path is not None:
            write_text(require_input_path(output_path, "output_path"), json_str)

        return json_str

    def deserialize(
        self,
        json_str: str | None = None,
        input_path: str | Path | None = None,
    ) -> YaraFile:
        """Deserialize JSON to AST."""
        if input_path is not None:
            json_str = read_text(require_input_path(input_path, "input_path"))

        if json_str is None or json_str == "":
            msg = "No JSON input provided"
            raise SerializationError(msg)
        if not isinstance(json_str, str):
            msg = "JSON input must be a string"
            raise TypeError(msg)

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
            module=_serialize_required_nonempty_string(node.module, "Import module"),
            alias=_serialize_nullable_nonempty_string(getattr(node, "alias", None), "Import alias"),
        )

    def visit_include(self, node) -> dict[str, Any]:
        return self._simple_node(
            "Include",
            path=_serialize_required_nonempty_string(node.path, "Include path"),
        )

    def visit_rule(self, node) -> dict[str, Any]:
        return visit_rule(self, node)

    def visit_tag(self, node) -> dict[str, Any]:
        return self._simple_node(
            "Tag",
            name=_serialize_required_nonempty_string(node.name, "Tag name"),
        )

    def visit_string_definition(self, node) -> dict[str, Any]:
        data = self._simple_node(
            "StringDefinition",
            identifier=_serialize_required_nonempty_string(
                node.identifier,
                "StringDefinition identifier",
            ),
            modifiers=_serialize_string_modifiers(self, node.modifiers, "StringDefinition"),
        )
        _serialize_anonymous_flag(data, getattr(node, "is_anonymous", False), "StringDefinition")
        return data

    def visit_plain_string(self, node) -> dict[str, Any]:
        return visit_plain_string(self, node)

    def visit_hex_string(self, node) -> dict[str, Any]:
        return visit_hex_string(self, node)

    def visit_regex_string(self, node) -> dict[str, Any]:
        return visit_regex_string(self, node)

    def visit_string_modifier(self, node) -> dict[str, Any]:
        modifier_type = getattr(node, "modifier_type", None)
        name = getattr(modifier_type, "value", None)
        if name is None:
            try:
                name = node.name
            except AttributeError:
                name = None
        return self._simple_node(
            "StringModifier",
            name=_serialize_required_nonempty_string(name, "StringModifier name"),
            value=_serialize_modifier_value(node.value),
        )

    def visit_hex_token(self, node) -> dict[str, Any]:
        return self._simple_node("HexToken")

    def visit_hex_byte(self, node) -> dict[str, Any]:
        return self._simple_node(
            "HexByte",
            value=_serialize_hex_byte_value(node.value, "HexByte"),
        )

    def visit_hex_negated_byte(self, node) -> dict[str, Any]:
        return self._simple_node(
            "HexNegatedByte",
            value=_serialize_hex_negated_value(node.value),
        )

    def visit_hex_wildcard(self, node) -> dict[str, Any]:
        return self._simple_node("HexWildcard")

    def visit_hex_jump(self, node) -> dict[str, Any]:
        min_jump, max_jump = _serialize_hex_jump_bounds(node.min_jump, node.max_jump)
        return self._simple_node("HexJump", min_jump=min_jump, max_jump=max_jump)

    def visit_hex_alternative(self, node) -> dict[str, Any]:
        return visit_hex_alternative(self, node)

    def visit_hex_nibble(self, node) -> dict[str, Any]:
        return self._simple_node(
            "HexNibble",
            high=_serialize_hex_nibble_high(node.high),
            value=_serialize_hex_nibble_value(node.value),
        )

    # Expression visitor methods (simplified)
    def visit_expression(self, node) -> dict[str, Any]:
        return self._simple_node("Expression")

    def visit_identifier(self, node) -> dict[str, Any]:
        return self._simple_node(
            "Identifier",
            name=_serialize_required_nonempty_string(node.name, "Identifier name"),
        )

    def visit_string_identifier(self, node) -> dict[str, Any]:
        return self._simple_node(
            "StringIdentifier",
            name=_serialize_required_nonempty_string(node.name, "StringIdentifier name"),
        )

    def visit_string_wildcard(self, node) -> dict[str, Any]:
        return self._simple_node(
            "StringWildcard",
            pattern=_serialize_required_nonempty_string(
                node.pattern,
                "StringWildcard pattern",
            ),
        )

    def visit_string_count(self, node) -> dict[str, Any]:
        return self._simple_node(
            "StringCount",
            string_id=_serialize_required_nonempty_string(
                node.string_id,
                "StringCount string_id",
            ),
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
        pattern = _serialize_required_string(node.pattern, "RegexLiteral pattern")
        if not pattern:
            msg = "RegexLiteral pattern must not be empty"
            raise SerializationError(msg)
        return {
            "type": "RegexLiteral",
            "pattern": pattern,
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
        data = self._simple_node(
            "Meta",
            key=_serialize_required_nonempty_string(node.key, "Meta key"),
            value=_serialize_meta_value(node.value),
        )
        scope = getattr(node, "scope", None)
        if scope is not None:
            data["scope"] = serialize_meta_scope(scope)
        return data

    def visit_module_reference(self, node) -> dict[str, Any]:
        return self._simple_node(
            "ModuleReference",
            module=_serialize_required_nonempty_string(node.module, "ModuleReference module"),
        )

    def visit_dictionary_access(self, node) -> dict[str, Any]:
        return visit_dictionary_access(self, node)

    def visit_comment(self, node) -> dict[str, Any]:
        return self._simple_node(
            "Comment",
            text=_serialize_required_string(node.text, "Comment text"),
            is_multiline=_serialize_required_bool(node.is_multiline, "Comment is_multiline"),
        )

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
            module_path=_serialize_required_nonempty_string(
                node.module_path,
                "ExternImport module_path",
            ),
            alias=_serialize_nullable_nonempty_string(node.alias, "ExternImport alias"),
            rules=_serialize_nonempty_string_list(node.rules, "ExternImport rules"),
        )

    def visit_extern_namespace(self, node) -> dict[str, Any]:
        from yaraast.ast.extern import ExternRule

        return self._simple_node(
            "ExternNamespace",
            name=_serialize_required_nonempty_string(node.name, "ExternNamespace name"),
            extern_rules=_serialize_node_list(
                self,
                node.extern_rules,
                "ExternNamespace extern_rules",
                ExternRule,
            ),
        )

    def visit_extern_rule(self, node) -> dict[str, Any]:
        return {
            "type": "ExternRule",
            "name": _serialize_required_nonempty_string(node.name, "ExternRule name"),
            "modifiers": _serialize_rule_modifiers(node.modifiers, "ExternRule"),
            "namespace": _serialize_nullable_nonempty_string(
                node.namespace,
                "ExternRule namespace",
            ),
        }

    def visit_extern_rule_reference(self, node) -> dict[str, Any]:
        return {
            "type": "ExternRuleReference",
            "rule_name": _serialize_required_nonempty_string(
                node.rule_name,
                "ExternRuleReference rule_name",
            ),
            "namespace": _serialize_nullable_nonempty_string(
                node.namespace,
                "ExternRuleReference namespace",
            ),
        }

    def visit_in_rule_pragma(self, node) -> dict[str, Any]:
        return {
            "type": "InRulePragma",
            "pragma": self.visit(node.pragma),
            "position": _serialize_required_nonempty_string(
                node.position,
                "InRulePragma position",
            ),
        }

    def visit_pragma(self, node) -> dict[str, Any]:
        from yaraast.ast.pragmas import PragmaType

        data = {
            "type": "Pragma",
            "pragma_type": _serialize_enum_value(node.pragma_type, "Pragma pragma_type"),
            "name": _serialize_required_nonempty_string(node.name, "Pragma name"),
            "arguments": _serialize_string_list(node.arguments, "Pragma arguments"),
            "scope": serialize_pragma_scope(node.scope),
        }
        if hasattr(node, "macro_name"):
            data["macro_name"] = _serialize_required_nonempty_string(
                node.macro_name,
                "Pragma macro_name",
            )
        if hasattr(node, "macro_value"):
            data["macro_value"] = _serialize_nullable_string(
                node.macro_value,
                "Pragma macro_value",
            )
        if hasattr(node, "condition"):
            if node.pragma_type in {PragmaType.IFDEF, PragmaType.IFNDEF}:
                data["condition"] = _serialize_required_nonempty_string(
                    node.condition,
                    "Pragma condition",
                )
            else:
                data["condition"] = _serialize_nullable_nonempty_string(
                    node.condition,
                    "Pragma condition",
                )
        if hasattr(node, "parameters"):
            data["parameters"] = _serialize_string_key_dict(
                node.parameters,
                "Pragma parameters",
            )
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
