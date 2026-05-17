"""Deserialization helpers for JSON serializer."""

from __future__ import annotations

import base64
import binascii
from typing import Any

from yaraast.ast.base import ASTNode, Location
from yaraast.ast.comments import Comment, CommentGroup
from yaraast.errors import SerializationError, ValidationError
from yaraast.string_escaping import escape_string_source_value

_HEX_CHARS = frozenset("0123456789abcdefABCDEF")


def _deserialize_ast_value(self, data):
    if isinstance(data, dict):
        return self._deserialize_expression(data)
    return data


def _deserialize_optional_expression(self, data):
    return self._deserialize_expression(data) if data else None


def _deserialize_location(data: dict[str, Any]) -> Location:
    return Location(
        line=data["line"],
        column=data["column"],
        file=data.get("file"),
        end_line=data.get("end_line"),
        end_column=data.get("end_column"),
    )


def _deserialize_comment_node(self, data: dict[str, Any]) -> Any:
    node_type = data.get("type")
    if node_type == "Comment":
        return _apply_node_metadata(
            self,
            Comment(data["text"], is_multiline=data.get("is_multiline", False)),
            data,
        )
    if node_type == "CommentGroup":
        return _apply_node_metadata(
            self,
            CommentGroup(
                [
                    _cast_comment(_deserialize_comment_node(self, c))
                    for c in data.get("comments", [])
                ]
            ),
            data,
        )
    return Comment(str(data))


def _deserialize_plain_string_value(data: dict[str, Any]) -> str | bytes:
    value = data["value"]
    if data.get("value_encoding") != "base64":
        if isinstance(value, str | bytes):
            return value
        msg = "PlainString value must be a string or bytes"
        raise SerializationError(msg)
    if isinstance(value, bytes):
        return value
    try:
        return base64.b64decode(str(value).encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError) as exc:
        msg = "Invalid base64-encoded plain string value"
        raise SerializationError(msg) from exc


def _deserialize_is_anonymous(data: dict[str, Any]) -> bool:
    return data.get("is_anonymous") is True


def _deserialize_integer_literal_value(data: dict[str, Any]) -> int:
    value = data["value"]
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    msg = "IntegerLiteral value must be an integer"
    raise SerializationError(msg)


def _deserialize_boolean_literal_value(data: dict[str, Any]) -> bool:
    value = data["value"]
    if isinstance(value, bool):
        return value
    msg = "BooleanLiteral value must be a boolean"
    raise SerializationError(msg)


def _deserialize_double_literal_value(data: dict[str, Any]) -> float:
    value = data["value"]
    if isinstance(value, int | float) and not isinstance(value, bool):
        return float(value)
    msg = "DoubleLiteral value must be numeric"
    raise SerializationError(msg)


def _deserialize_string_field(data: dict[str, Any], field: str, context: str) -> str:
    value = data[field]
    if isinstance(value, str):
        return value
    msg = f"{context} {field} must be a string"
    raise SerializationError(msg)


def _deserialize_optional_string_field(
    data: dict[str, Any], field: str, context: str, default: str = ""
) -> str:
    value = data.get(field, default)
    if isinstance(value, str):
        return value
    msg = f"{context} {field} must be a string"
    raise SerializationError(msg)


def _deserialize_nullable_string_field(
    data: dict[str, Any], field: str, context: str
) -> str | None:
    value = data.get(field)
    if value is None or isinstance(value, str):
        return value
    msg = f"{context} {field} must be a string"
    raise SerializationError(msg)


def _deserialize_string_list_field(data: dict[str, Any], field: str, context: str) -> list[str]:
    value = data.get(field, [])
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return value
    msg = f"{context} {field} must be a list of strings"
    raise SerializationError(msg)


def _deserialize_meta_value(data: dict[str, Any]) -> str | int | bool:
    value = data["value"]
    if isinstance(value, str | bool):
        return value
    if isinstance(value, int):
        return value
    msg = "Meta value must be a string, integer, or boolean"
    raise SerializationError(msg)


def _deserialize_hex_byte_value(data: dict[str, Any], context: str) -> int | str:
    value = data["value"]
    if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 0xFF:
        return value
    if isinstance(value, str) and len(value) == 2 and all(char in _HEX_CHARS for char in value):
        return value
    msg = f"{context} value must be a byte"
    raise SerializationError(msg)


def _deserialize_hex_nibble_value(data: dict[str, Any]) -> int | str:
    value = data["value"]
    if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 0xF:
        return value
    if isinstance(value, str) and len(value) == 1 and value in _HEX_CHARS:
        return value
    msg = "HexNibble value must be a nibble"
    raise SerializationError(msg)


def _deserialize_hex_nibble_high(data: dict[str, Any]) -> bool:
    value = data.get("high", True)
    if isinstance(value, bool):
        return value
    msg = "HexNibble high must be a boolean"
    raise SerializationError(msg)


def _deserialize_hex_jump_bound(data: dict[str, Any], field: str) -> int | None:
    value = data.get(field)
    if value is None:
        return None
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    msg = f"HexJump {field} must be a non-negative integer"
    raise SerializationError(msg)


def _deserialize_hex_jump_bounds(data: dict[str, Any]) -> tuple[int | None, int | None]:
    min_jump = _deserialize_hex_jump_bound(data, "min_jump")
    max_jump = _deserialize_hex_jump_bound(data, "max_jump")
    if min_jump is not None and max_jump is not None and min_jump > max_jump:
        msg = "HexJump min_jump cannot exceed max_jump"
        raise SerializationError(msg)
    return min_jump, max_jump


def _cast_comment(node: Any) -> Comment:
    if isinstance(node, Comment):
        return node
    return Comment(str(node))


def _apply_node_metadata(self, node: ASTNode, data: dict[str, Any]) -> Any:
    location = data.get("location")
    if isinstance(location, dict):
        node.location = _deserialize_location(location)
    if data.get("leading_comments"):
        node.leading_comments = [
            _cast_comment(_deserialize_comment_node(self, comment))
            for comment in data["leading_comments"]
        ]
    trailing_comment = data.get("trailing_comment")
    if isinstance(trailing_comment, dict):
        node.trailing_comment = _deserialize_comment_node(self, trailing_comment)
    return node


def _deser_binary_expression(self, data: dict[str, Any]):
    from yaraast.ast.expressions import BinaryExpression

    left = self._deserialize_expression(data["left"])
    right = self._deserialize_expression(data["right"])
    return BinaryExpression(left=left, operator=data["operator"], right=right)


def _deser_unary_expression(self, data: dict[str, Any]):
    from yaraast.ast.expressions import UnaryExpression

    operand = self._deserialize_expression(data["operand"])
    return UnaryExpression(operator=data["operator"], operand=operand)


def _deser_parentheses_expression(self, data: dict[str, Any]):
    from yaraast.ast.expressions import ParenthesesExpression

    expression = self._deserialize_expression(data["expression"])
    return ParenthesesExpression(expression=expression)


def _deser_set_expression(self, data: dict[str, Any]):
    from yaraast.ast.expressions import SetExpression

    elements = [self._deserialize_expression(e) for e in data.get("elements", [])]
    return SetExpression(elements=elements)


def _deser_range_expression(self, data: dict[str, Any]):
    from yaraast.ast.expressions import RangeExpression

    low = self._deserialize_expression(data["low"])
    high = self._deserialize_expression(data["high"])
    return RangeExpression(low=low, high=high)


def _deser_function_call(self, data: dict[str, Any]):
    from yaraast.ast.expressions import FunctionCall

    args = [self._deserialize_expression(a) for a in data.get("arguments", [])]
    return FunctionCall(function=data["function"], arguments=args)


def _deser_array_access(self, data: dict[str, Any]):
    from yaraast.ast.expressions import ArrayAccess

    array = self._deserialize_expression(data["array"])
    index = self._deserialize_expression(data["index"])
    return ArrayAccess(array=array, index=index)


def _deser_member_access(self, data: dict[str, Any]):
    from yaraast.ast.expressions import MemberAccess

    obj = self._deserialize_expression(data["object"])
    return MemberAccess(object=obj, member=data["member"])


def _deser_identifier(self, data: dict[str, Any]):
    from yaraast.ast.expressions import Identifier

    return Identifier(name=_deserialize_string_field(data, "name", "Identifier"))


def _deser_string_identifier(self, data: dict[str, Any]):
    from yaraast.ast.expressions import StringIdentifier

    return StringIdentifier(name=_deserialize_string_field(data, "name", "StringIdentifier"))


def _deser_string_wildcard(self, data: dict[str, Any]):
    from yaraast.ast.expressions import StringWildcard

    return StringWildcard(pattern=_deserialize_string_field(data, "pattern", "StringWildcard"))


def _deser_string_count(self, data: dict[str, Any]):
    from yaraast.ast.expressions import StringCount

    return StringCount(string_id=_deserialize_string_field(data, "string_id", "StringCount"))


def _deser_string_offset(self, data: dict[str, Any]):
    from yaraast.ast.expressions import StringOffset

    index = data.get("index")
    return StringOffset(
        string_id=_deserialize_string_field(data, "string_id", "StringOffset"),
        index=self._deserialize_expression(index) if index else None,
    )


def _deser_string_length(self, data: dict[str, Any]):
    from yaraast.ast.expressions import StringLength

    index = data.get("index")
    return StringLength(
        string_id=_deserialize_string_field(data, "string_id", "StringLength"),
        index=self._deserialize_expression(index) if index else None,
    )


def _deser_integer_literal(self, data: dict[str, Any]):
    from yaraast.ast.expressions import IntegerLiteral

    return IntegerLiteral(value=_deserialize_integer_literal_value(data))


def _deser_double_literal(self, data: dict[str, Any]):
    from yaraast.ast.expressions import DoubleLiteral

    return DoubleLiteral(value=_deserialize_double_literal_value(data))


def _deser_string_literal(self, data: dict[str, Any]):
    from yaraast.ast.expressions import StringLiteral

    return StringLiteral(value=_deserialize_string_field(data, "value", "StringLiteral"))


def _deser_regex_literal(self, data: dict[str, Any]):
    from yaraast.ast.expressions import RegexLiteral

    return RegexLiteral(
        pattern=_deserialize_string_field(data, "pattern", "RegexLiteral"),
        modifiers=_deserialize_optional_string_field(data, "modifiers", "RegexLiteral"),
    )


def _deser_boolean_literal(self, data: dict[str, Any]):
    from yaraast.ast.expressions import BooleanLiteral

    return BooleanLiteral(value=_deserialize_boolean_literal_value(data))


def _deser_for_expression(self, data: dict[str, Any]):
    from yaraast.ast.conditions import ForExpression

    return ForExpression(
        quantifier=_deserialize_ast_value(self, data["quantifier"]),
        variable=data.get("variable", "i"),
        iterable=self._deserialize_expression(data["iterable"]),
        body=self._deserialize_expression(data["body"]),
    )


def _deser_for_of_expression(self, data: dict[str, Any]):
    from yaraast.ast.conditions import ForOfExpression

    condition = data.get("condition")
    return ForOfExpression(
        quantifier=_deserialize_ast_value(self, data["quantifier"]),
        string_set=_deserialize_ast_value(self, data["string_set"]),
        condition=self._deserialize_expression(condition) if condition else None,
    )


def _deser_at_expression(self, data: dict[str, Any]):
    from yaraast.ast.conditions import AtExpression

    return AtExpression(
        string_id=data["string_id"],
        offset=self._deserialize_expression(data["offset"]),
    )


def _deser_in_expression(self, data: dict[str, Any]):
    from yaraast.ast.conditions import InExpression

    subject = data.get("subject")
    if subject is None and "string_id" in data:
        subject = data["string_id"]
    if isinstance(subject, dict):
        subject = self._deserialize_expression(subject)
    return InExpression(
        subject=subject,
        range=self._deserialize_expression(data["range"]),
    )


def _deser_of_expression(self, data: dict[str, Any]):
    from yaraast.ast.conditions import OfExpression

    return OfExpression(
        quantifier=_deserialize_ast_value(self, data["quantifier"]),
        string_set=_deserialize_ast_value(self, data["string_set"]),
    )


def _deser_module_reference(self, data: dict[str, Any]):
    from yaraast.ast.modules import ModuleReference

    return ModuleReference(module=data["module"])


def _deser_dictionary_access(self, data: dict[str, Any]):
    from yaraast.ast.modules import DictionaryAccess

    obj = self._deserialize_expression(data["object"])
    key = data.get("key")
    if isinstance(key, dict):
        key = self._deserialize_expression(key)
    return DictionaryAccess(object=obj, key=key)


def _deser_defined_expression(self, data: dict[str, Any]):
    from yaraast.ast.operators import DefinedExpression

    expression = data.get("expression")
    if expression is None and "identifier" in data:
        expression = {"type": "Identifier", "name": data["identifier"]}
    return DefinedExpression(expression=self._deserialize_expression(expression))


def _deser_string_operator_expression(self, data: dict[str, Any]):
    from yaraast.ast.operators import StringOperatorExpression

    left = data.get("left")
    right = data.get("right")
    if left is None and "subject" in data:
        left = data.get("subject")
    if right is None and "pattern" in data:
        right = {"type": "StringLiteral", "value": data.get("pattern", "")}
    if left is None:
        left = {"type": "Identifier", "name": "true"}
    if right is None:
        right = {"type": "Identifier", "name": "true"}
    return StringOperatorExpression(
        left=self._deserialize_expression(left),
        operator=data["operator"],
        right=self._deserialize_expression(right),
    )


def _deser_extern_rule_reference(self, data: dict[str, Any]):
    from yaraast.ast.extern import ExternRuleReference

    rule_name = data.get("rule_name", data.get("name"))
    if rule_name is None:
        msg = "ExternRuleReference missing rule_name"
        raise SerializationError(msg)
    if not isinstance(rule_name, str):
        msg = "ExternRuleReference rule_name must be a string"
        raise SerializationError(msg)
    return ExternRuleReference(
        rule_name=rule_name,
        namespace=_deserialize_nullable_string_field(data, "namespace", "ExternRuleReference"),
    )


def _deser_with_statement(self, data: dict[str, Any]):
    from yaraast.yarax.ast_nodes import WithStatement

    return WithStatement(
        declarations=[
            self._deserialize_expression(declaration)
            for declaration in data.get("declarations", [])
        ],
        body=self._deserialize_expression(data["body"]),
    )


def _deser_with_declaration(self, data: dict[str, Any]):
    from yaraast.yarax.ast_nodes import WithDeclaration

    return WithDeclaration(
        identifier=data["identifier"],
        value=self._deserialize_expression(data["value"]),
    )


def _deser_array_comprehension(self, data: dict[str, Any]):
    from yaraast.yarax.ast_nodes import ArrayComprehension

    return ArrayComprehension(
        expression=_deserialize_optional_expression(self, data.get("expression")),
        variable=data.get("variable", ""),
        iterable=_deserialize_optional_expression(self, data.get("iterable")),
        condition=_deserialize_optional_expression(self, data.get("condition")),
    )


def _deser_dict_comprehension(self, data: dict[str, Any]):
    from yaraast.yarax.ast_nodes import DictComprehension

    return DictComprehension(
        key_expression=_deserialize_optional_expression(self, data.get("key_expression")),
        value_expression=_deserialize_optional_expression(self, data.get("value_expression")),
        key_variable=data.get("key_variable", ""),
        value_variable=data.get("value_variable"),
        iterable=_deserialize_optional_expression(self, data.get("iterable")),
        condition=_deserialize_optional_expression(self, data.get("condition")),
    )


def _deser_tuple_expression(self, data: dict[str, Any]):
    from yaraast.yarax.ast_nodes import TupleExpression

    return TupleExpression(
        elements=[self._deserialize_expression(element) for element in data.get("elements", [])]
    )


def _deser_tuple_indexing(self, data: dict[str, Any]):
    from yaraast.yarax.ast_nodes import TupleIndexing

    return TupleIndexing(
        tuple_expr=self._deserialize_expression(data["tuple_expr"]),
        index=self._deserialize_expression(data["index"]),
    )


def _deser_list_expression(self, data: dict[str, Any]):
    from yaraast.yarax.ast_nodes import ListExpression

    return ListExpression(
        elements=[self._deserialize_expression(element) for element in data.get("elements", [])]
    )


def _deser_dict_expression(self, data: dict[str, Any]):
    from yaraast.yarax.ast_nodes import DictExpression

    return DictExpression(
        items=[self._deserialize_expression(item) for item in data.get("items", [])]
    )


def _deser_dict_item(self, data: dict[str, Any]):
    from yaraast.yarax.ast_nodes import DictItem

    return DictItem(
        key=self._deserialize_expression(data["key"]),
        value=self._deserialize_expression(data["value"]),
    )


def _deser_slice_expression(self, data: dict[str, Any]):
    from yaraast.yarax.ast_nodes import SliceExpression

    return SliceExpression(
        target=self._deserialize_expression(data["target"]),
        start=_deserialize_optional_expression(self, data.get("start")),
        stop=_deserialize_optional_expression(self, data.get("stop")),
        step=_deserialize_optional_expression(self, data.get("step")),
    )


def _deser_lambda_expression(self, data: dict[str, Any]):
    from yaraast.yarax.ast_nodes import LambdaExpression

    return LambdaExpression(
        parameters=list(data.get("parameters", [])),
        body=self._deserialize_expression(data["body"]),
    )


def _deser_pattern_match(self, data: dict[str, Any]):
    from yaraast.yarax.ast_nodes import PatternMatch

    return PatternMatch(
        value=self._deserialize_expression(data["value"]),
        cases=[self._deserialize_expression(case) for case in data.get("cases", [])],
        default=_deserialize_optional_expression(self, data.get("default")),
    )


def _deser_match_case(self, data: dict[str, Any]):
    from yaraast.yarax.ast_nodes import MatchCase

    return MatchCase(
        pattern=self._deserialize_expression(data["pattern"]),
        result=self._deserialize_expression(data["result"]),
    )


def _deser_spread_operator(self, data: dict[str, Any]):
    from yaraast.yarax.ast_nodes import SpreadOperator

    return SpreadOperator(
        expression=self._deserialize_expression(data["expression"]),
        is_dict=data.get("is_dict", False),
    )


_EXPR_DESERIALIZERS: dict[str, Any] = {
    "BinaryExpression": _deser_binary_expression,
    "UnaryExpression": _deser_unary_expression,
    "ParenthesesExpression": _deser_parentheses_expression,
    "SetExpression": _deser_set_expression,
    "RangeExpression": _deser_range_expression,
    "FunctionCall": _deser_function_call,
    "ArrayAccess": _deser_array_access,
    "MemberAccess": _deser_member_access,
    "Identifier": _deser_identifier,
    "StringIdentifier": _deser_string_identifier,
    "StringWildcard": _deser_string_wildcard,
    "StringCount": _deser_string_count,
    "StringOffset": _deser_string_offset,
    "StringLength": _deser_string_length,
    "IntegerLiteral": _deser_integer_literal,
    "DoubleLiteral": _deser_double_literal,
    "StringLiteral": _deser_string_literal,
    "RegexLiteral": _deser_regex_literal,
    "BooleanLiteral": _deser_boolean_literal,
    "ForExpression": _deser_for_expression,
    "ForOfExpression": _deser_for_of_expression,
    "AtExpression": _deser_at_expression,
    "InExpression": _deser_in_expression,
    "OfExpression": _deser_of_expression,
    "ModuleReference": _deser_module_reference,
    "DictionaryAccess": _deser_dictionary_access,
    "DefinedExpression": _deser_defined_expression,
    "StringOperatorExpression": _deser_string_operator_expression,
    "ExternRuleReference": _deser_extern_rule_reference,
    "WithStatement": _deser_with_statement,
    "WithDeclaration": _deser_with_declaration,
    "ArrayComprehension": _deser_array_comprehension,
    "DictComprehension": _deser_dict_comprehension,
    "TupleExpression": _deser_tuple_expression,
    "TupleIndexing": _deser_tuple_indexing,
    "ListExpression": _deser_list_expression,
    "DictExpression": _deser_dict_expression,
    "DictItem": _deser_dict_item,
    "SliceExpression": _deser_slice_expression,
    "LambdaExpression": _deser_lambda_expression,
    "PatternMatch": _deser_pattern_match,
    "MatchCase": _deser_match_case,
    "SpreadOperator": _deser_spread_operator,
}


class JsonSerializerDeserializeMixin:
    """Mixin with JSON deserialization helpers."""

    def _apply_node_metadata(self, node: ASTNode, data: dict[str, Any]) -> Any:
        return _apply_node_metadata(self, node, data)

    def _deserialize_import(self, data: dict[str, Any]):
        from yaraast.ast.rules import Import

        return self._apply_node_metadata(
            Import(
                module=_deserialize_string_field(data, "module", "Import"),
                alias=_deserialize_nullable_string_field(data, "alias", "Import"),
            ),
            data,
        )

    def _deserialize_include(self, data: dict[str, Any]):
        from yaraast.ast.rules import Include

        return self._apply_node_metadata(
            Include(path=_deserialize_string_field(data, "path", "Include")), data
        )

    def _deserialize_rule(self, data: dict[str, Any]):
        from yaraast.ast.rules import Rule

        meta_data = data.get("meta", [])
        if isinstance(meta_data, dict):
            meta = [
                self._deserialize_meta({"key": key, "value": value})
                for key, value in meta_data.items()
            ]
        elif isinstance(meta_data, list):
            meta = [self._deserialize_meta(m) for m in meta_data]
        else:
            meta = []

        strings = [self._deserialize_string(s) for s in data.get("strings", [])]
        condition = (
            self._deserialize_expression(data["condition"]) if data.get("condition") else None
        )

        tags = [self._deserialize_tag(t) for t in data.get("tags", [])]
        pragmas = [self._deserialize_in_rule_pragma(p) for p in data.get("pragmas", [])]

        return self._apply_node_metadata(
            Rule(
                name=_deserialize_string_field(data, "name", "Rule"),
                modifiers=data.get("modifiers", []),
                tags=tags,
                meta=meta,
                strings=strings,
                condition=condition,
                pragmas=pragmas,
            ),
            data,
        )

    def _deserialize_tag(self, data: dict[str, Any]):
        from yaraast.ast.rules import Tag

        return self._apply_node_metadata(
            Tag(name=_deserialize_string_field(data, "name", "Tag")), data
        )

    def _deserialize_meta(self, data: dict[str, Any]):
        from yaraast.ast.modifiers import MetaEntry

        if data.get("leading_comments") or data.get("trailing_comment") or data.get("location"):
            from yaraast.ast.meta import Meta

            return self._apply_node_metadata(
                Meta(
                    _deserialize_string_field(data, "key", "Meta"),
                    _deserialize_meta_value(data),
                ),
                data,
            )
        return MetaEntry.from_key_value(
            _deserialize_string_field(data, "key", "Meta"),
            _deserialize_meta_value(data),
            _deserialize_nullable_string_field(data, "scope", "Meta"),
        )

    def _deserialize_string(self, data: dict[str, Any]):
        string_type = data.get("type")
        modifiers = [self._deserialize_modifier(m) for m in data.get("modifiers", [])]

        if string_type == "PlainString":
            from yaraast.ast.strings import PlainString

            return self._apply_node_metadata(
                PlainString(
                    identifier=_deserialize_string_field(data, "identifier", "PlainString"),
                    value=_deserialize_plain_string_value(data),
                    modifiers=modifiers,
                    is_anonymous=_deserialize_is_anonymous(data),
                ),
                data,
            )
        if string_type == "HexString":
            from yaraast.ast.strings import HexString

            tokens = [self._deserialize_hex_token(t) for t in data.get("tokens", [])]
            return self._apply_node_metadata(
                HexString(
                    identifier=_deserialize_string_field(data, "identifier", "HexString"),
                    tokens=tokens,
                    modifiers=modifiers,
                    is_anonymous=_deserialize_is_anonymous(data),
                ),
                data,
            )
        if string_type == "RegexString":
            from yaraast.ast.strings import RegexString

            return self._apply_node_metadata(
                RegexString(
                    identifier=_deserialize_string_field(data, "identifier", "RegexString"),
                    regex=_deserialize_string_field(data, "regex", "RegexString"),
                    modifiers=modifiers,
                    is_anonymous=_deserialize_is_anonymous(data),
                ),
                data,
            )
        msg = f"Unknown string type: {string_type}"
        raise SerializationError(msg)

    def _deserialize_modifier_value(self, name: str, value: Any) -> Any:
        if name == "xor":
            if isinstance(value, list) and len(value) == 2:
                return (value[0], value[1])
            if isinstance(value, str) and "-" in value:
                low, high = value.split("-", maxsplit=1)
                if low.isdigit() and high.isdigit():
                    return (int(low), int(high))
            if isinstance(value, str) and value.isdigit():
                return int(value)
        return value

    def _format_unknown_modifier(self, name: str, value: Any) -> str:
        if value is None:
            return name
        if isinstance(value, tuple) and len(value) == 2:
            return f"{name}({value[0]}-{value[1]})"
        if isinstance(value, str):
            return f'{name}("{escape_string_source_value(value)}")'
        return f"{name}({value})"

    def _deserialize_modifier(self, data: Any):
        from yaraast.ast.modifiers import StringModifier

        if isinstance(data, dict):
            name = str(data["name"])
            value = self._deserialize_modifier_value(name, data.get("value"))
        else:
            name = str(data)
            value = None
        try:
            return StringModifier.from_name_value(name, value)
        except (ValueError, ValidationError):
            return self._format_unknown_modifier(name, value)

    def _deserialize_hex_token(self, data: dict[str, Any]):
        hex_kind = data.get("type")

        if hex_kind == "HexByte":
            from yaraast.ast.strings import HexByte

            return self._apply_node_metadata(
                HexByte(value=_deserialize_hex_byte_value(data, "HexByte")), data
            )
        if hex_kind == "HexWildcard":
            from yaraast.ast.strings import HexWildcard

            return self._apply_node_metadata(HexWildcard(), data)
        if hex_kind == "HexJump":
            from yaraast.ast.strings import HexJump

            min_jump, max_jump = _deserialize_hex_jump_bounds(data)
            return self._apply_node_metadata(
                HexJump(min_jump=min_jump, max_jump=max_jump),
                data,
            )
        if hex_kind == "HexNibble":
            from yaraast.ast.strings import HexNibble

            return self._apply_node_metadata(
                HexNibble(
                    high=_deserialize_hex_nibble_high(data),
                    value=_deserialize_hex_nibble_value(data),
                ),
                data,
            )
        if hex_kind == "HexNegatedByte":
            from yaraast.ast.strings import HexNegatedByte

            return self._apply_node_metadata(
                HexNegatedByte(value=_deserialize_hex_byte_value(data, "HexNegatedByte")),
                data,
            )
        if hex_kind == "HexAlternative":
            from yaraast.ast.strings import HexAlternative

            alternatives = [
                [self._deserialize_hex_token(t) for t in self._coerce_hex_alternative_branch(alt)]
                for alt in data.get("alternatives", [])
            ]
            return self._apply_node_metadata(HexAlternative(alternatives=alternatives), data)
        msg = f"Unknown hex token type: {hex_kind}"
        raise SerializationError(msg)

    def _coerce_hex_alternative_branch(self, alternative):
        if isinstance(alternative, list):
            return alternative
        return [alternative]

    def _deserialize_extern_import(self, data: dict[str, Any]):
        from yaraast.ast.extern import ExternImport

        module_path = data.get("module_path", data.get("module"))
        if module_path is None:
            msg = "ExternImport missing module_path"
            raise SerializationError(msg)
        if not isinstance(module_path, str):
            msg = "ExternImport module_path must be a string"
            raise SerializationError(msg)
        return self._apply_node_metadata(
            ExternImport(
                module_path=module_path,
                alias=_deserialize_nullable_string_field(data, "alias", "ExternImport"),
                rules=_deserialize_string_list_field(data, "rules", "ExternImport"),
            ),
            data,
        )

    def _deserialize_extern_rule(self, data: dict[str, Any]):
        from yaraast.ast.extern import ExternRule
        from yaraast.ast.rules import Rule

        return self._apply_node_metadata(
            ExternRule(
                name=_deserialize_string_field(data, "name", "ExternRule"),
                modifiers=Rule._normalize_modifiers(data.get("modifiers", [])),
                namespace=_deserialize_nullable_string_field(data, "namespace", "ExternRule"),
            ),
            data,
        )

    def _deserialize_extern_namespace(self, data: dict[str, Any]):
        from yaraast.ast.extern import ExternNamespace

        return self._apply_node_metadata(
            ExternNamespace(
                name=_deserialize_string_field(data, "name", "ExternNamespace"),
                extern_rules=[
                    self._deserialize_extern_rule(rule) for rule in data.get("extern_rules", [])
                ],
            ),
            data,
        )

    def _deserialize_pragma(self, data: dict[str, Any]):
        from yaraast.ast.pragmas import (
            ConditionalDirective,
            CustomPragma,
            DefineDirective,
            IncludeOncePragma,
            Pragma,
            PragmaScope,
            PragmaType,
            UndefDirective,
        )

        pragma_type = PragmaType.from_string(
            str(data.get("pragma_type", data.get("name", PragmaType.CUSTOM.value)))
        )
        scope = PragmaScope(data.get("scope", PragmaScope.FILE.value))
        name = data.get("name", pragma_type.value)
        arguments = list(data.get("arguments", []))

        if pragma_type == PragmaType.INCLUDE_ONCE:
            pragma = IncludeOncePragma()
        elif pragma_type == PragmaType.DEFINE and "macro_name" in data:
            pragma = DefineDirective(
                macro_name=str(data["macro_name"]),
                macro_value=data.get("macro_value"),
            )
        elif pragma_type == PragmaType.UNDEF and "macro_name" in data:
            pragma = UndefDirective(macro_name=str(data["macro_name"]))
        elif pragma_type in {PragmaType.IFDEF, PragmaType.IFNDEF, PragmaType.ENDIF}:
            pragma = ConditionalDirective(pragma_type, condition=data.get("condition"))
        elif pragma_type == PragmaType.CUSTOM:
            pragma = CustomPragma(
                name=name,
                arguments=arguments,
                parameters=dict(data.get("parameters", {})),
                scope=scope,
            )
        else:
            pragma = Pragma(
                pragma_type=pragma_type,
                name=name,
                arguments=arguments,
                scope=scope,
            )
        pragma.scope = scope
        return self._apply_node_metadata(pragma, data)

    def _deserialize_in_rule_pragma(self, data: dict[str, Any]):
        from yaraast.ast.pragmas import InRulePragma

        return self._apply_node_metadata(
            InRulePragma(
                pragma=self._deserialize_pragma(data["pragma"]),
                position=data.get("position", "before_strings"),
            ),
            data,
        )

    def _deserialize_pragma_block(self, data: dict[str, Any]):
        from yaraast.ast.pragmas import PragmaBlock, PragmaScope

        return self._apply_node_metadata(
            PragmaBlock(
                pragmas=[self._deserialize_pragma(pragma) for pragma in data.get("pragmas", [])],
                scope=PragmaScope(data.get("scope", PragmaScope.FILE.value)),
            ),
            data,
        )

    def _deserialize_expression(self, data: dict[str, Any]):
        if not data:
            return None

        expr_type = data.get("type")
        factory = _EXPR_DESERIALIZERS.get(expr_type)
        if factory:
            node = factory(self, data)
            if isinstance(node, ASTNode):
                return self._apply_node_metadata(node, data)
            return node

        msg = f"Unknown expression type: {expr_type}"
        raise SerializationError(msg)
