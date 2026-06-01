"""Helper functions for simple roundtrip serialization."""

from __future__ import annotations

import base64
import binascii
import json
import math
from pathlib import Path
from typing import Any

from yaraast.ast.base import ASTNode, Location, YaraFile
from yaraast.ast.comments import Comment, CommentGroup
from yaraast.ast.conditions import (
    AtExpression,
    ForExpression,
    ForOfExpression,
    InExpression,
    OfExpression,
)
from yaraast.ast.expressions import (
    ArrayAccess,
    BinaryExpression,
    BooleanLiteral,
    DoubleLiteral,
    Expression,
    FunctionCall,
    Identifier,
    IntegerLiteral,
    MemberAccess,
    ParenthesesExpression,
    RangeExpression,
    RegexLiteral,
    SetExpression,
    StringCount,
    StringIdentifier,
    StringLength,
    StringLiteral,
    StringOffset,
    StringWildcard,
    UnaryExpression,
)
from yaraast.ast.extern import ExternImport, ExternNamespace, ExternRule, ExternRuleReference
from yaraast.ast.meta import Meta
from yaraast.ast.modifiers import MetaEntry, RuleModifier, StringModifier
from yaraast.ast.modules import DictionaryAccess, ModuleReference
from yaraast.ast.operators import DefinedExpression, StringOperatorExpression
from yaraast.ast.pragmas import (
    ConditionalDirective,
    CustomPragma,
    DefineDirective,
    IncludeOncePragma,
    InRulePragma,
    Pragma,
    PragmaBlock,
    PragmaScope,
    PragmaType,
    UndefDirective,
)
from yaraast.ast.rules import Import, Include, Rule, Tag
from yaraast.ast.strings import (
    HexAlternative,
    HexByte,
    HexJump,
    HexNegatedByte,
    HexNibble,
    HexString,
    HexToken,
    HexWildcard,
    PlainString,
    RegexString,
    StringDefinition,
)
from yaraast.errors import SerializationError, ValidationError, YaraASTError
from yaraast.parser.hex_parser import HexParseError, HexStringParser
from yaraast.parser.source import parse_yara_source
from yaraast.serialization.meta_scopes import deserialize_meta_scope, serialize_meta_scope
from yaraast.serialization.modifier_values import deserialize_legacy_modifier_value
from yaraast.serialization.pragma_scopes import (
    deserialize_pragma_scope,
    serialize_pragma_scope,
)
from yaraast.string_escaping import escape_string_source_value
from yaraast.yarax.ast_nodes import (
    ArrayComprehension,
    DictComprehension,
    DictExpression,
    DictItem,
    LambdaExpression,
    ListExpression,
    MatchCase,
    PatternMatch,
    SliceExpression,
    SpreadOperator,
    TupleExpression,
    TupleIndexing,
    WithDeclaration,
    WithStatement,
)
from yaraast.yarax.generator import YaraXGenerator

_HEX_CHARS = frozenset("0123456789abcdefABCDEF")


def _deserialize_object(data: Any, context: str) -> dict[str, Any]:
    if isinstance(data, dict):
        return data
    msg = f"{context} must be an object"
    raise SerializationError(msg)


def _deserialize_required_field(data: dict[str, Any], field: str, context: str) -> Any:
    data = _deserialize_object(data, context)
    if field not in data:
        msg = f"{context} {field} is required"
        raise SerializationError(msg)
    return data[field]


def _validate_hex_byte_value(value: Any, context: str) -> int | str:
    if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 0xFF:
        return value
    if isinstance(value, str) and len(value) == 2 and all(char in _HEX_CHARS for char in value):
        return value
    msg = f"{context} value must be a byte"
    raise SerializationError(msg)


def _validate_hex_negated_value(value: Any) -> int | str:
    if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 0xFF:
        return value
    if isinstance(value, str):
        if len(value) == 2 and all(char in _HEX_CHARS for char in value):
            return value
        if _is_negated_nibble_pattern(value):
            return value
    msg = "HexNegatedByte value must be a byte or negated nibble"
    raise SerializationError(msg)


def _is_negated_nibble_pattern(value: str) -> bool:
    if len(value) != 2:
        return False
    first, second = value
    return (first == "?" and second in _HEX_CHARS) or (first in _HEX_CHARS and second == "?")


def _validate_hex_nibble_value(value: Any) -> int | str:
    if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 0xF:
        return value
    if isinstance(value, str) and len(value) == 1 and value in _HEX_CHARS:
        return value
    msg = "HexNibble value must be a nibble"
    raise SerializationError(msg)


def _validate_hex_nibble_high(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    msg = "HexNibble high must be a boolean"
    raise SerializationError(msg)


def _validate_hex_jump_bound(value: Any, field: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    msg = f"HexJump {field} must be a non-negative integer"
    raise SerializationError(msg)


def _validate_hex_jump_bounds(min_value: Any, max_value: Any) -> tuple[int | None, int | None]:
    min_jump = _validate_hex_jump_bound(min_value, "min_jump")
    max_jump = _validate_hex_jump_bound(max_value, "max_jump")
    if min_jump is not None and max_jump is not None and min_jump > max_jump:
        msg = "HexJump min_jump cannot exceed max_jump"
        raise SerializationError(msg)
    return min_jump, max_jump


def _serialize_hex_token(token: Any) -> dict[str, Any]:
    """Serialize a single hex token to a dictionary."""
    if isinstance(token, HexByte):
        return {"type": "HexByte", "value": _validate_hex_byte_value(token.value, "HexByte")}
    if isinstance(token, HexWildcard):
        return {"type": "HexWildcard"}
    if isinstance(token, HexJump):
        min_jump, max_jump = _validate_hex_jump_bounds(token.min_jump, token.max_jump)
        return {"type": "HexJump", "min_jump": min_jump, "max_jump": max_jump}
    if isinstance(token, HexNibble):
        return {
            "type": "HexNibble",
            "high": _validate_hex_nibble_high(token.high),
            "value": _validate_hex_nibble_value(token.value),
        }
    if isinstance(token, HexNegatedByte):
        return {
            "type": "HexNegatedByte",
            "value": _validate_hex_negated_value(token.value),
        }
    if isinstance(token, HexAlternative):
        return {
            "type": "HexAlternative",
            "alternatives": _serialize_hex_alternative_branches(token.alternatives),
        }
    msg = f"Unsupported hex token type: {type(token).__name__}"
    raise SerializationError(msg)


def _deserialize_hex_token(data: dict[str, Any]):
    """Deserialize a hex token from a dictionary."""
    data = _deserialize_object(data, "Hex token")
    hex_kind = data.get("type")
    if hex_kind == "HexByte":
        return HexByte(value=_deserialize_hex_byte_value(data, "HexByte"))
    if hex_kind == "HexWildcard":
        return HexWildcard()
    if hex_kind == "HexJump":
        min_jump, max_jump = _deserialize_hex_jump_bounds(data)
        return HexJump(min_jump=min_jump, max_jump=max_jump)
    if hex_kind == "HexNibble":
        return HexNibble(
            high=_deserialize_hex_nibble_high(data),
            value=_deserialize_hex_nibble_value(data),
        )
    if hex_kind == "HexNegatedByte":
        return HexNegatedByte(
            value=_validate_hex_negated_value(
                _deserialize_required_field(data, "value", "HexNegatedByte")
            )
        )
    if hex_kind == "HexAlternative":
        alternatives = [
            [_deserialize_hex_token(t) for t in _coerce_serialized_hex_alternative_branch(alt)]
            for alt in _deserialize_list_field(data, "alternatives", "HexAlternative")
        ]
        return HexAlternative(alternatives=alternatives)
    msg = f"Unknown hex token type: {hex_kind}"
    raise SerializationError(msg)


def _coerce_hex_alternative_branch(alternative) -> list:
    if isinstance(alternative, list):
        return alternative
    return [HexByte(alternative)]


def _serialize_hex_alternative_branches(alternatives: Any) -> list[list[dict[str, Any]]]:
    if not isinstance(alternatives, list):
        msg = "HexAlternative alternatives must be a list"
        raise SerializationError(msg)
    return [
        [_serialize_hex_token(token) for token in _coerce_hex_alternative_branch(alternative)]
        for alternative in alternatives
    ]


def _coerce_serialized_hex_alternative_branch(alternative) -> list:
    if isinstance(alternative, list):
        return alternative
    return [alternative]


def _deserialize_legacy_hex_tokens(raw_tokens: str) -> list[HexToken]:
    """Deserialize legacy hex tokens stored as YARA-style text."""
    hex_content = raw_tokens.strip()
    if hex_content.startswith("{") and hex_content.endswith("}"):
        hex_content = hex_content[1:-1]
    return HexStringParser().parse(hex_content)


def _serialize_modifier_value(value: Any) -> Any:
    if isinstance(value, tuple):
        return list(value)
    return value


def _serialize_plain_string_value(data: dict[str, Any], value: str | bytes) -> None:
    if isinstance(value, bytes):
        data["value"] = base64.b64encode(value).decode("ascii")
        data["value_encoding"] = "base64"
        return
    data["value"] = value


def _deserialize_plain_string_value(data: dict[str, Any]) -> str | bytes:
    value = _deserialize_required_field(data, "value", "PlainString")
    if data.get("value_encoding") != "base64":
        if isinstance(value, str | bytes):
            return value
        msg = "PlainString value must be a string or bytes"
        raise SerializationError(msg)
    if isinstance(value, bytes):
        return value
    if not isinstance(value, str):
        msg = "PlainString value must be a string or bytes"
        raise SerializationError(msg)
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError) as exc:
        msg = "Invalid base64-encoded plain string value"
        raise SerializationError(msg) from exc


def _deserialize_legacy_string_data(data: dict[str, Any]) -> str | bytes:
    value = data.get("data", "")
    if isinstance(value, str | bytes):
        return value
    msg = "String data must be a string or bytes"
    raise SerializationError(msg)


def _deserialize_is_anonymous(data: dict[str, Any]) -> bool:
    return data.get("is_anonymous") is True


def _deserialize_integer_literal_value(data: dict[str, Any]) -> int:
    value = _deserialize_required_field(data, "value", "IntegerLiteral")
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    msg = "IntegerLiteral value must be an integer"
    raise SerializationError(msg)


def _deserialize_boolean_literal_value(data: dict[str, Any]) -> bool:
    value = _deserialize_required_field(data, "value", "BooleanLiteral")
    if isinstance(value, bool):
        return value
    msg = "BooleanLiteral value must be a boolean"
    raise SerializationError(msg)


def _deserialize_double_literal_value(data: dict[str, Any]) -> float:
    value = _deserialize_required_field(data, "value", "DoubleLiteral")
    if isinstance(value, int | float) and not isinstance(value, bool):
        if isinstance(value, float) and not math.isfinite(value):
            msg = "DoubleLiteral value must be finite"
            raise SerializationError(msg)
        return float(value)
    msg = "DoubleLiteral value must be numeric"
    raise SerializationError(msg)


def _deserialize_hex_byte_value(data: dict[str, Any], context: str) -> int | str:
    return _validate_hex_byte_value(_deserialize_required_field(data, "value", context), context)


def _deserialize_hex_nibble_value(data: dict[str, Any]) -> int | str:
    return _validate_hex_nibble_value(_deserialize_required_field(data, "value", "HexNibble"))


def _deserialize_hex_nibble_high(data: dict[str, Any]) -> bool:
    return _validate_hex_nibble_high(data.get("high", True))


def _deserialize_hex_jump_bound(data: dict[str, Any], field: str) -> int | None:
    return _validate_hex_jump_bound(data.get(field), field)


def _deserialize_hex_jump_bounds(data: dict[str, Any]) -> tuple[int | None, int | None]:
    return _validate_hex_jump_bounds(
        _deserialize_hex_jump_bound(data, "min_jump"),
        _deserialize_hex_jump_bound(data, "max_jump"),
    )


def _deserialize_string_field(data: dict[str, Any], field: str, context: str) -> str:
    value = _deserialize_required_field(data, field, context)
    if isinstance(value, str):
        return value
    msg = f"{context} {field} must be a string"
    raise SerializationError(msg)


def _deserialize_nonempty_string_field(data: dict[str, Any], field: str, context: str) -> str:
    text = _deserialize_string_field(data, field, context)
    if not text:
        msg = f"{context} {field} must not be empty"
        raise SerializationError(msg)
    return text


def _deserialize_optional_string_field(
    data: dict[str, Any], field: str, context: str, default: str = ""
) -> str:
    data = _deserialize_object(data, context)
    value = data.get(field, default)
    if isinstance(value, str):
        return value
    msg = f"{context} {field} must be a string"
    raise SerializationError(msg)


def _deserialize_nullable_string_field(
    data: dict[str, Any], field: str, context: str
) -> str | None:
    data = _deserialize_object(data, context)
    value = data.get(field)
    if value is None or isinstance(value, str):
        return value
    msg = f"{context} {field} must be a string"
    raise SerializationError(msg)


def _deserialize_nullable_nonempty_string_field(
    data: dict[str, Any], field: str, context: str
) -> str | None:
    text = _deserialize_nullable_string_field(data, field, context)
    if text == "":
        msg = f"{context} {field} must not be empty"
        raise SerializationError(msg)
    return text


def _deserialize_optional_node_value(value: Any, context: str) -> ASTNode | None:
    if value is None:
        return None
    if value == {}:
        msg = f"{context} must be an expression"
        raise SerializationError(msg)
    return deserialize_node(value)


def _deserialize_optional_node_field(
    data: dict[str, Any], field: str, context: str
) -> ASTNode | None:
    value = data.get(field)
    return _deserialize_optional_node_value(value, context)


def _deserialize_required_node_value(value: Any, context: str) -> ASTNode:
    if value is None or value == {}:
        msg = f"{context} is required"
        raise SerializationError(msg)
    return deserialize_node(value)


def _deserialize_required_node(data: dict[str, Any], field: str, context: str) -> ASTNode:
    return _deserialize_required_node_value(
        _deserialize_required_field(data, field, context), f"{context} {field}"
    )


def _deserialize_node_list_field(data: dict[str, Any], field: str, context: str) -> list[ASTNode]:
    nodes = []
    for item in _deserialize_list_field(data, field, context):
        if item is None or item == {}:
            msg = f"{context} {field} must contain nodes"
            raise SerializationError(msg)
        nodes.append(deserialize_node(item))
    return nodes


def _deserialize_expected_node(
    data: Any, expected_type: type[Any], context: str, expected_name: str
) -> Any:
    node = deserialize_node(data)
    if isinstance(node, expected_type):
        return node
    msg = f"{context} must contain {expected_name} nodes"
    raise SerializationError(msg)


def _deserialize_extern_rule_item(data: Any, context: str) -> ExternRule:
    data = _deserialize_object(data, "ExternRule")
    node_type = data.get("type")
    if node_type is not None and node_type != "ExternRule":
        msg = f"{context} must contain ExternRule nodes"
        raise SerializationError(msg)
    return deserialize_extern_rule(data)


def _deserialize_pragma_item(data: Any, context: str) -> Pragma:
    data = _deserialize_object(data, "Pragma")
    node_type = data.get("type")
    if node_type is not None and node_type != "Pragma":
        msg = f"{context} must contain Pragma nodes"
        raise SerializationError(msg)
    return deserialize_pragma(data)


def _deserialize_dictionary_key(data: dict[str, Any]) -> str | ASTNode:
    if "key" not in data:
        msg = "DictionaryAccess key must be a string or expression"
        raise SerializationError(msg)
    value = data["key"]
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return _deserialize_required_node_value(value, "DictionaryAccess key")
    msg = "DictionaryAccess key must be a string or expression"
    raise SerializationError(msg)


def _deserialize_string_list_field(data: dict[str, Any], field: str, context: str) -> list[str]:
    data = _deserialize_object(data, context)
    value = data.get(field, [])
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return value
    msg = f"{context} {field} must be a list of strings"
    raise SerializationError(msg)


def _deserialize_nonempty_string_list_field(
    data: dict[str, Any], field: str, context: str
) -> list[str]:
    items = _deserialize_string_list_field(data, field, context)
    if any(not item for item in items):
        msg = f"{context} {field} must contain non-empty strings"
        raise SerializationError(msg)
    return items


def _serialize_required_string(value: Any, context: str) -> str:
    if isinstance(value, str):
        return value
    msg = f"{context} must be a string"
    raise SerializationError(msg)


def _serialize_required_nonempty_string(value: Any, context: str) -> str:
    text = _serialize_required_string(value, context)
    if not text:
        msg = f"{context} must not be empty"
        raise SerializationError(msg)
    return text


def _serialize_string_or_expression(value: Any, context: str) -> str | dict[str, Any]:
    if isinstance(value, str):
        return _serialize_required_nonempty_string(value, context)
    if isinstance(value, Expression):
        return serialize_node(value)
    msg = f"{context} must be a string"
    raise SerializationError(msg)


def _serialize_nullable_string(value: Any, context: str) -> str | None:
    if value is None:
        return None
    return _serialize_required_string(value, context)


def _serialize_nullable_nonempty_string(value: Any, context: str) -> str | None:
    text = _serialize_nullable_string(value, context)
    if text == "":
        msg = f"{context} must not be empty"
        raise SerializationError(msg)
    return text


def _serialize_string_list(values: Any, context: str) -> list[str]:
    if isinstance(values, list | tuple) and all(isinstance(item, str) for item in values):
        return list(values)
    msg = f"{context} must be a list of strings"
    raise SerializationError(msg)


def _serialize_nonempty_string_list(values: Any, context: str) -> list[str]:
    items = _serialize_string_list(values, context)
    if any(not item for item in items):
        msg = f"{context} must contain non-empty strings"
        raise SerializationError(msg)
    return items


def _serialize_string_key_dict(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        msg = f"{context} must be a dictionary"
        raise SerializationError(msg)
    if not all(isinstance(key, str) for key in value):
        msg = f"{context} keys must be strings"
        raise SerializationError(msg)
    return {key: _serialize_pragma_parameter_value(item) for key, item in value.items()}


def _serialize_pragma_parameter_value(value: Any) -> str | int | bool | float:
    if isinstance(value, str | bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float) and math.isfinite(value):
        return value
    msg = "Pragma parameter value must be a string, integer, boolean, or finite float"
    raise SerializationError(msg)


def _serialize_enum_value(value: Any, context: str) -> str:
    if isinstance(value, str):
        return value
    return _serialize_required_string(getattr(value, "value", None), context)


def _serialize_required_int(value: Any, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        msg = f"{context} must be an integer"
        raise SerializationError(msg)
    return value


def _serialize_nullable_int(value: Any, context: str) -> int | None:
    if value is None:
        return None
    return _serialize_required_int(value, context)


def _serialize_required_number(value: Any, context: str) -> int | float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        msg = f"{context} must be numeric"
        raise SerializationError(msg)
    if isinstance(value, float) and not math.isfinite(value):
        msg = f"{context} must be finite"
        raise SerializationError(msg)
    return value


def _serialize_required_bool(value: Any, context: str) -> bool:
    if not isinstance(value, bool):
        msg = f"{context} must be a boolean"
        raise SerializationError(msg)
    return value


def _deserialize_list_field(data: dict[str, Any], field: str, context: str) -> list[Any]:
    data = _deserialize_object(data, context)
    value = data.get(field, [])
    if isinstance(value, list):
        return value
    msg = f"{context} {field} must be a list"
    raise SerializationError(msg)


def _deserialize_bool_field(
    data: dict[str, Any], field: str, context: str, default: bool = False
) -> bool:
    data = _deserialize_object(data, context)
    value = data.get(field, default)
    if isinstance(value, bool):
        return value
    msg = f"{context} {field} must be a boolean"
    raise SerializationError(msg)


def _deserialize_dict_field(data: dict[str, Any], field: str, context: str) -> dict[str, Any]:
    data = _deserialize_object(data, context)
    value = data.get(field, {})
    if isinstance(value, dict):
        if all(isinstance(key, str) for key in value):
            return {
                key: _deserialize_pragma_parameter_value(item, f"{context} {field}")
                for key, item in value.items()
            }
        msg = f"{context} {field} keys must be strings"
        raise SerializationError(msg)
    msg = f"{context} {field} must be a dictionary"
    raise SerializationError(msg)


def _deserialize_pragma_parameter_value(value: Any, context: str) -> str | int | bool | float:
    if isinstance(value, str | bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float) and math.isfinite(value):
        return value
    msg = f"{context} value must be scalar"
    raise SerializationError(msg)


def _deserialize_pragma_type(data: dict[str, Any]) -> PragmaType:
    if "pragma_type" in data:
        value = data["pragma_type"]
        field = "pragma_type"
    elif "name" in data:
        value = data["name"]
        field = "name"
    else:
        value = PragmaType.CUSTOM.value
        field = "pragma_type"
    if isinstance(value, str):
        return PragmaType.from_string(value)
    msg = f"Pragma {field} must be a string"
    raise SerializationError(msg)


def _deserialize_meta_value(data: dict[str, Any]) -> str | int | bool:
    value = _deserialize_required_field(data, "value", "Meta")
    if isinstance(value, str | bool):
        return value
    if isinstance(value, int):
        return value
    msg = "Meta value must be a string, integer, or boolean"
    raise SerializationError(msg)


def _deserialize_meta_entry_value(data: dict[str, Any]) -> str | int | bool | float:
    value = _deserialize_required_field(data, "value", "Meta")
    if isinstance(value, str | bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float) and math.isfinite(value):
        return value
    msg = "Meta value must be a string, integer, boolean, or finite float"
    raise SerializationError(msg)


def _serialize_meta_value(value: Any) -> str | int | bool:
    if isinstance(value, str | bool):
        return value
    if isinstance(value, int):
        return value
    msg = "Meta value must be a string, integer, or boolean"
    raise SerializationError(msg)


def _serialize_meta_entry_value(value: Any) -> str | int | bool | float:
    if isinstance(value, str | bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float) and math.isfinite(value):
        return value
    msg = "Meta value must be a string, integer, boolean, or finite float"
    raise SerializationError(msg)


def _deserialize_rule_tag(value: Any) -> Tag:
    if isinstance(value, Tag):
        _serialize_required_nonempty_string(value.name, "Tag name")
        return value
    if isinstance(value, str):
        if not value:
            msg = "Tag name must not be empty"
            raise SerializationError(msg)
        return Tag(name=value)
    if isinstance(value, dict):
        node_type = value.get("type")
        if node_type is not None and node_type != "Tag":
            msg = "Rule tags must contain Tag nodes"
            raise SerializationError(msg)
        return Tag(name=_deserialize_nonempty_string_field(value, "name", "Tag"))
    msg = "Tag name must be a string"
    raise SerializationError(msg)


def _deserialize_modifier_value(name: str, value: Any) -> Any:
    return deserialize_legacy_modifier_value(name, value)


def _serialize_string_modifier_name(modifier: Any) -> str:
    if isinstance(modifier, str):
        return _serialize_required_nonempty_string(modifier, "StringModifier name")
    if isinstance(modifier, StringModifier):
        return _serialize_required_nonempty_string(
            getattr(modifier.modifier_type, "value", None),
            "StringModifier name",
        )
    try:
        name = modifier.name
    except AttributeError:
        name = None
    return _serialize_required_nonempty_string(name, "StringModifier name")


def _serialize_modifiers(modifiers: Any, context: str) -> list[dict[str, Any]]:
    if not isinstance(modifiers, list | tuple):
        msg = f"{context} modifiers must be a list"
        raise SerializationError(msg)
    return [
        {
            "name": _serialize_string_modifier_name(modifier),
            "value": _serialize_modifier_value(getattr(modifier, "value", None)),
        }
        for modifier in modifiers
    ]


def _expected_type_names(expected_type: type[Any] | tuple[type[Any], ...]) -> str:
    expected_types = expected_type if isinstance(expected_type, tuple) else (expected_type,)
    return " or ".join(item_type.__name__ for item_type in expected_types)


def _validated_node_collection(
    values: Any,
    context: str,
    expected_type: type[Any] | tuple[type[Any], ...],
) -> list[Any]:
    if not isinstance(values, list | tuple):
        msg = f"{context} must be a list"
        raise SerializationError(msg)

    for value in values:
        if not isinstance(value, expected_type):
            msg = f"{context} must contain {_expected_type_names(expected_type)} nodes"
            raise SerializationError(msg)
    return list(values)


def _serialize_meta_entries(values: Any) -> list[dict[str, Any]]:
    if not isinstance(values, list | tuple):
        msg = "Rule meta must be a list"
        raise SerializationError(msg)

    serialized = []
    for value in values:
        if not isinstance(value, Meta | MetaEntry):
            msg = "Rule meta must contain Meta or MetaEntry nodes"
            raise SerializationError(msg)
        serialized.append(serialize_meta(value))
    return serialized


def _serialize_string_definitions(values: Any) -> list[dict[str, Any]]:
    if not isinstance(values, list | tuple):
        msg = "Rule strings must be a list"
        raise SerializationError(msg)

    serialized = []
    for value in values:
        if not isinstance(value, StringDefinition):
            msg = "Rule strings must contain StringDefinition nodes"
            raise SerializationError(msg)
        serialized.append(serialize_string(value))
    return serialized


def _format_unknown_modifier(name: str, value: Any) -> str:
    if value is None:
        return name
    if isinstance(value, tuple) and len(value) == 2:
        return f"{name}({value[0]}-{value[1]})"
    if isinstance(value, str):
        return f'{name}("{escape_string_source_value(value)}")'
    return f"{name}({value})"


def _deserialize_modifier(modifier: Any) -> Any:
    if isinstance(modifier, dict):
        name = _deserialize_nonempty_string_field(modifier, "name", "StringModifier")
        value = _deserialize_modifier_value(name, modifier.get("value"))
    elif isinstance(modifier, str):
        if not modifier:
            msg = "StringModifier name must not be empty"
            raise SerializationError(msg)
        name = modifier
        value = None
    else:
        msg = "StringModifier must be a string or object"
        raise SerializationError(msg)

    try:
        return StringModifier.from_name_value(name, value)
    except (ValueError, ValidationError):
        return _format_unknown_modifier(name, value)


def _deserialize_modifiers(modifiers: list[Any]) -> list[Any]:
    return [_deserialize_modifier(modifier) for modifier in modifiers]


def _serialize_ast_value(value: Any) -> Any:
    if isinstance(value, ASTNode):
        return serialize_node(value)
    if isinstance(value, list | tuple):
        return [_serialize_ast_value(item) for item in value]
    if isinstance(value, set | frozenset):
        return [_serialize_ast_value(item) for item in sorted(value, key=str)]
    return value


def _deserialize_ast_value(value: Any, context: str = "AST value") -> Any:
    if value is None or value == {}:
        msg = f"{context} is required"
        raise SerializationError(msg)
    if isinstance(value, dict):
        return deserialize_node(value)
    if isinstance(value, list):
        values = []
        for item in value:
            if item is None or item == {}:
                msg = f"{context} must contain values"
                raise SerializationError(msg)
            values.append(_deserialize_ast_value(item, context))
        return values
    return value


def _deserialize_required_ast_value(data: dict[str, Any], field: str, context: str) -> Any:
    return _deserialize_ast_value(
        _deserialize_required_field(data, field, context), f"{context} {field}"
    )


def _deserialize_required_quantifier(data: dict[str, Any], field: str, context: str) -> Any:
    value = _deserialize_required_field(data, field, context)
    if isinstance(value, bool | list):
        msg = f"{context} {field} must be a string, number, or expression"
        raise SerializationError(msg)
    if isinstance(value, float) and not math.isfinite(value):
        msg = f"{context} {field} must be finite"
        raise SerializationError(msg)
    return _deserialize_ast_value(value, f"{context} {field}")


def _deserialize_string_set_item(value: Any, context: str) -> Any:
    if value is None or value == {}:
        msg = f"{context} must contain values"
        raise SerializationError(msg)
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return _deserialize_required_node_value(value, context)
    msg = f"{context} must contain strings or expressions"
    raise SerializationError(msg)


def _deserialize_required_string_set(data: dict[str, Any], field: str, context: str) -> Any:
    value = _deserialize_required_field(data, field, context)
    field_context = f"{context} {field}"
    if value is None or value == {}:
        msg = f"{field_context} is required"
        raise SerializationError(msg)
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return _deserialize_required_node_value(value, field_context)
    if isinstance(value, list):
        return [_deserialize_string_set_item(item, field_context) for item in value]
    msg = f"{field_context} must be a string, expression, or list of strings/expressions"
    raise SerializationError(msg)


def _serialize_location(location: Location) -> dict[str, Any]:
    data: dict[str, Any] = {
        "line": _serialize_required_int(location.line, "Location line"),
        "column": _serialize_required_int(location.column, "Location column"),
    }
    file = _serialize_nullable_string(location.file, "Location file")
    if file is not None:
        data["file"] = file
    end_line = _serialize_nullable_int(location.end_line, "Location end_line")
    if end_line is not None:
        data["end_line"] = end_line
    end_column = _serialize_nullable_int(location.end_column, "Location end_column")
    if end_column is not None:
        data["end_column"] = end_column
    return data


def _deserialize_location_int_field(data: dict[str, Any], field: str) -> int:
    value = _deserialize_required_field(data, field, "Location")
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    msg = f"Location {field} must be an integer"
    raise SerializationError(msg)


def _deserialize_location_optional_int_field(data: dict[str, Any], field: str) -> int | None:
    value = data.get(field)
    if value is None:
        return None
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    msg = f"Location {field} must be an integer"
    raise SerializationError(msg)


def _deserialize_comment_multiline(data: dict[str, Any]) -> bool:
    value = data.get("is_multiline", False)
    if isinstance(value, bool):
        return value
    msg = "Comment is_multiline must be a boolean"
    raise SerializationError(msg)


def _deserialize_comment_text(data: dict[str, Any]) -> str:
    return _deserialize_string_field(data, "text", "Comment")


def _deserialize_location(data: dict[str, Any]) -> Location:
    return Location(
        line=_deserialize_location_int_field(data, "line"),
        column=_deserialize_location_int_field(data, "column"),
        file=_deserialize_nullable_string_field(data, "file", "Location"),
        end_line=_deserialize_location_optional_int_field(data, "end_line"),
        end_column=_deserialize_location_optional_int_field(data, "end_column"),
    )


def _deserialize_comment_node(data: Any) -> ASTNode:
    data = _deserialize_object(data, "Comment metadata")
    node_type = data.get("type")
    if node_type == "Comment":
        return _apply_node_metadata(
            Comment(
                _deserialize_comment_text(data),
                is_multiline=_deserialize_comment_multiline(data),
            ),
            data,
        )
    if node_type == "CommentGroup":
        return _apply_node_metadata(
            CommentGroup(
                [
                    cast_comment(_deserialize_comment_node(comment))
                    for comment in _deserialize_list_field(data, "comments", "CommentGroup")
                ]
            ),
            data,
        )
    msg = f"Unknown comment metadata type: {node_type}"
    raise SerializationError(msg)


def _with_node_metadata(node: ASTNode, data: dict[str, Any]) -> dict[str, Any]:
    if node.location is not None:
        data["location"] = _serialize_location(node.location)
    leading_comments = _validated_node_collection(
        node.leading_comments,
        "leading_comments",
        (Comment, CommentGroup),
    )
    if leading_comments:
        data["leading_comments"] = [serialize_node(comment) for comment in leading_comments]
    if node.trailing_comment is not None:
        if not isinstance(node.trailing_comment, Comment | CommentGroup):
            msg = "trailing_comment must be a Comment or CommentGroup node"
            raise SerializationError(msg)
        data["trailing_comment"] = serialize_node(node.trailing_comment)
    return data


def _apply_node_metadata(node: ASTNode, data: dict[str, Any]) -> ASTNode:
    location = data.get("location")
    if isinstance(location, dict):
        node.location = _deserialize_location(location)
    elif location is not None:
        msg = "location must be an object"
        raise SerializationError(msg)
    if "leading_comments" in data:
        leading_comments = data["leading_comments"]
        if not isinstance(leading_comments, list):
            msg = "leading_comments must be a list"
            raise SerializationError(msg)
        node.leading_comments = [
            cast_leading_comment(_deserialize_comment_node(comment)) for comment in leading_comments
        ]
    trailing_comment = data.get("trailing_comment")
    if isinstance(trailing_comment, dict):
        node.trailing_comment = cast_trailing_comment(_deserialize_comment_node(trailing_comment))
    elif trailing_comment is not None:
        msg = "trailing_comment must be an object"
        raise SerializationError(msg)
    return node


def serialize_node(node: ASTNode) -> dict[str, Any]:
    return _with_node_metadata(node, _serialize_node_payload(node))


def _serialize_node_payload(node: ASTNode) -> dict[str, Any]:
    """Serialize an AST node to a dictionary."""
    if isinstance(node, YaraFile):
        return serialize_yarafile(node)
    if isinstance(node, Rule):
        return serialize_rule(node)
    if isinstance(node, Import):
        return {
            "type": "Import",
            "module": _serialize_required_nonempty_string(node.module, "Import module"),
            "alias": _serialize_nullable_nonempty_string(node.alias, "Import alias"),
        }
    if isinstance(node, Include):
        return {
            "type": "Include",
            "path": _serialize_required_nonempty_string(node.path, "Include path"),
        }
    if isinstance(node, Tag):
        return {
            "type": "Tag",
            "name": _serialize_required_nonempty_string(node.name, "Tag name"),
        }
    if isinstance(node, Meta):
        return serialize_meta(node)
    if isinstance(node, Comment):
        return {
            "type": "Comment",
            "text": _serialize_required_string(node.text, "Comment text"),
            "is_multiline": _serialize_required_bool(node.is_multiline, "Comment is_multiline"),
        }
    if isinstance(node, CommentGroup):
        comments = _validated_node_collection(
            node.comments,
            "CommentGroup comments",
            Comment,
        )
        return {
            "type": "CommentGroup",
            "comments": [serialize_node(comment) for comment in comments],
        }
    if isinstance(node, PlainString | HexString | RegexString | StringDefinition):
        return serialize_string(node)
    if isinstance(node, HexToken):
        return _serialize_hex_token(node)
    if isinstance(node, StringModifier):
        return {
            "type": "StringModifier",
            "name": _serialize_string_modifier_name(node),
            "value": _serialize_modifier_value(node.value),
        }
    if isinstance(node, ExternRule):
        return serialize_extern_rule(node)
    if isinstance(node, ExternRuleReference):
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
    if isinstance(node, ExternImport):
        return {
            "type": "ExternImport",
            "module_path": _serialize_required_nonempty_string(
                node.module_path,
                "ExternImport module_path",
            ),
            "alias": _serialize_nullable_nonempty_string(node.alias, "ExternImport alias"),
            "rules": _serialize_nonempty_string_list(node.rules, "ExternImport rules"),
        }
    if isinstance(node, ExternNamespace):
        extern_rules = _validated_node_collection(
            node.extern_rules,
            "ExternNamespace extern_rules",
            ExternRule,
        )
        return {
            "type": "ExternNamespace",
            "name": _serialize_required_nonempty_string(node.name, "ExternNamespace name"),
            "extern_rules": [serialize_extern_rule(rule) for rule in extern_rules],
        }
    if isinstance(node, InRulePragma):
        return {
            "type": "InRulePragma",
            "pragma": serialize_pragma(node.pragma),
            "position": _serialize_required_nonempty_string(
                node.position,
                "InRulePragma position",
            ),
        }
    if isinstance(node, PragmaBlock):
        pragmas = _validated_node_collection(
            node.pragmas,
            "PragmaBlock pragmas",
            Pragma,
        )
        return {
            "type": "PragmaBlock",
            "pragmas": [serialize_pragma(pragma) for pragma in pragmas],
            "scope": serialize_pragma_scope(node.scope, "PragmaBlock"),
        }
    if isinstance(node, Pragma):
        return serialize_pragma(node)
    if isinstance(node, BooleanLiteral):
        return {
            "type": "BooleanLiteral",
            "value": _serialize_required_bool(node.value, "BooleanLiteral value"),
        }
    if isinstance(node, IntegerLiteral):
        return {
            "type": "IntegerLiteral",
            "value": _serialize_required_int(node.value, "IntegerLiteral value"),
        }
    if isinstance(node, DoubleLiteral):
        return {
            "type": "DoubleLiteral",
            "value": _serialize_required_number(node.value, "DoubleLiteral value"),
        }
    if isinstance(node, StringLiteral):
        return {
            "type": "StringLiteral",
            "value": _serialize_required_string(node.value, "StringLiteral value"),
        }
    if isinstance(node, RegexLiteral):
        return {
            "type": "RegexLiteral",
            "pattern": _serialize_required_nonempty_string(
                node.pattern,
                "RegexLiteral pattern",
            ),
            "modifiers": _serialize_required_string(node.modifiers, "RegexLiteral modifiers"),
        }
    if isinstance(node, Identifier):
        return {
            "type": "Identifier",
            "name": _serialize_required_nonempty_string(node.name, "Identifier name"),
        }
    if isinstance(node, StringIdentifier):
        return {
            "type": "StringIdentifier",
            "name": _serialize_required_nonempty_string(node.name, "StringIdentifier name"),
        }
    if isinstance(node, StringWildcard):
        return {
            "type": "StringWildcard",
            "pattern": _serialize_required_nonempty_string(
                node.pattern,
                "StringWildcard pattern",
            ),
        }
    if isinstance(node, StringCount):
        return {
            "type": "StringCount",
            "string_id": _serialize_required_nonempty_string(
                node.string_id,
                "StringCount string_id",
            ),
        }
    if isinstance(node, StringOffset):
        return {
            "type": "StringOffset",
            "string_id": _serialize_required_nonempty_string(
                node.string_id,
                "StringOffset string_id",
            ),
            "index": serialize_node(node.index) if node.index is not None else None,
        }
    if isinstance(node, StringLength):
        return {
            "type": "StringLength",
            "string_id": _serialize_required_nonempty_string(
                node.string_id,
                "StringLength string_id",
            ),
            "index": serialize_node(node.index) if node.index is not None else None,
        }
    if isinstance(node, BinaryExpression):
        return {
            "type": "BinaryExpression",
            "left": serialize_node(node.left),
            "operator": _serialize_required_nonempty_string(
                node.operator,
                "BinaryExpression operator",
            ),
            "right": serialize_node(node.right),
        }
    if isinstance(node, UnaryExpression):
        return {
            "type": "UnaryExpression",
            "operator": _serialize_required_nonempty_string(
                node.operator,
                "UnaryExpression operator",
            ),
            "operand": serialize_node(node.operand),
        }
    if isinstance(node, ParenthesesExpression):
        return {"type": "ParenthesesExpression", "expression": serialize_node(node.expression)}
    if isinstance(node, SetExpression):
        elements = _validated_node_collection(node.elements, "SetExpression elements", Expression)
        return {
            "type": "SetExpression",
            "elements": [serialize_node(element) for element in elements],
        }
    if isinstance(node, RangeExpression):
        return {
            "type": "RangeExpression",
            "low": serialize_node(node.low),
            "high": serialize_node(node.high),
        }
    if isinstance(node, FunctionCall):
        arguments = _validated_node_collection(
            node.arguments,
            "FunctionCall arguments",
            Expression,
        )
        return {
            "type": "FunctionCall",
            "function": _serialize_required_nonempty_string(
                node.function,
                "FunctionCall function",
            ),
            "arguments": [serialize_node(argument) for argument in arguments],
        }
    if isinstance(node, ArrayAccess):
        return {
            "type": "ArrayAccess",
            "array": serialize_node(node.array),
            "index": serialize_node(node.index),
        }
    if isinstance(node, MemberAccess):
        return {
            "type": "MemberAccess",
            "object": serialize_node(node.object),
            "member": _serialize_required_nonempty_string(node.member, "MemberAccess member"),
        }
    if isinstance(node, ForExpression):
        return {
            "type": "ForExpression",
            "quantifier": _serialize_ast_value(node.quantifier),
            "variable": _serialize_required_nonempty_string(
                node.variable,
                "ForExpression variable",
            ),
            "iterable": serialize_node(node.iterable),
            "body": serialize_node(node.body),
        }
    if isinstance(node, ForOfExpression):
        return {
            "type": "ForOfExpression",
            "quantifier": _serialize_ast_value(node.quantifier),
            "string_set": _serialize_ast_value(node.string_set),
            "condition": serialize_node(node.condition) if node.condition is not None else None,
        }
    if isinstance(node, AtExpression):
        return {
            "type": "AtExpression",
            "string_id": _serialize_string_or_expression(
                node.string_id,
                "AtExpression string_id",
            ),
            "offset": serialize_node(node.offset),
        }
    if isinstance(node, InExpression):
        return {
            "type": "InExpression",
            "subject": _serialize_ast_value(node.subject),
            "range": serialize_node(node.range),
        }
    if isinstance(node, OfExpression):
        return {
            "type": "OfExpression",
            "quantifier": _serialize_ast_value(node.quantifier),
            "string_set": _serialize_ast_value(node.string_set),
        }
    if isinstance(node, ModuleReference):
        return {
            "type": "ModuleReference",
            "module": _serialize_required_nonempty_string(node.module, "ModuleReference module"),
        }
    if isinstance(node, DictionaryAccess):
        return {
            "type": "DictionaryAccess",
            "object": serialize_node(node.object),
            "key": _serialize_ast_value(node.key),
        }
    if isinstance(node, DefinedExpression):
        return {"type": "DefinedExpression", "expression": serialize_node(node.expression)}
    if isinstance(node, StringOperatorExpression):
        return {
            "type": "StringOperatorExpression",
            "left": serialize_node(node.left),
            "operator": _serialize_required_nonempty_string(
                node.operator,
                "StringOperatorExpression operator",
            ),
            "right": serialize_node(node.right),
        }
    if isinstance(node, WithStatement):
        declarations = _validated_node_collection(
            node.declarations,
            "WithStatement declarations",
            WithDeclaration,
        )
        return {
            "type": "WithStatement",
            "declarations": [serialize_node(declaration) for declaration in declarations],
            "body": serialize_node(node.body),
        }
    if isinstance(node, WithDeclaration):
        return {
            "type": "WithDeclaration",
            "identifier": _serialize_required_nonempty_string(
                node.identifier,
                "WithDeclaration identifier",
            ),
            "value": serialize_node(node.value),
        }
    if isinstance(node, ArrayComprehension):
        return {
            "type": "ArrayComprehension",
            "expression": serialize_node(node.expression) if node.expression is not None else None,
            "variable": _serialize_required_nonempty_string(
                node.variable,
                "ArrayComprehension variable",
            ),
            "iterable": serialize_node(node.iterable) if node.iterable is not None else None,
            "condition": serialize_node(node.condition) if node.condition is not None else None,
        }
    if isinstance(node, DictComprehension):
        return {
            "type": "DictComprehension",
            "key_expression": (
                serialize_node(node.key_expression) if node.key_expression is not None else None
            ),
            "value_expression": (
                serialize_node(node.value_expression) if node.value_expression is not None else None
            ),
            "key_variable": _serialize_required_nonempty_string(
                node.key_variable,
                "DictComprehension key_variable",
            ),
            "value_variable": _serialize_nullable_nonempty_string(
                node.value_variable,
                "DictComprehension value_variable",
            ),
            "iterable": serialize_node(node.iterable) if node.iterable is not None else None,
            "condition": serialize_node(node.condition) if node.condition is not None else None,
        }
    if isinstance(node, TupleExpression):
        elements = _validated_node_collection(
            node.elements,
            "TupleExpression elements",
            Expression,
        )
        return {
            "type": "TupleExpression",
            "elements": [serialize_node(element) for element in elements],
        }
    if isinstance(node, TupleIndexing):
        return {
            "type": "TupleIndexing",
            "tuple_expr": serialize_node(node.tuple_expr),
            "index": serialize_node(node.index),
        }
    if isinstance(node, ListExpression):
        elements = _validated_node_collection(node.elements, "ListExpression elements", Expression)
        return {
            "type": "ListExpression",
            "elements": [serialize_node(element) for element in elements],
        }
    if isinstance(node, DictExpression):
        items = _validated_node_collection(node.items, "DictExpression items", DictItem)
        return {
            "type": "DictExpression",
            "items": [serialize_node(item) for item in items],
        }
    if isinstance(node, DictItem):
        return {
            "type": "DictItem",
            "key": serialize_node(node.key),
            "value": serialize_node(node.value),
        }
    if isinstance(node, SliceExpression):
        return {
            "type": "SliceExpression",
            "target": serialize_node(node.target),
            "start": serialize_node(node.start) if node.start is not None else None,
            "stop": serialize_node(node.stop) if node.stop is not None else None,
            "step": serialize_node(node.step) if node.step is not None else None,
        }
    if isinstance(node, LambdaExpression):
        return {
            "type": "LambdaExpression",
            "parameters": _serialize_nonempty_string_list(
                node.parameters,
                "LambdaExpression parameters",
            ),
            "body": serialize_node(node.body),
        }
    if isinstance(node, PatternMatch):
        cases = _validated_node_collection(node.cases, "PatternMatch cases", MatchCase)
        return {
            "type": "PatternMatch",
            "value": serialize_node(node.value),
            "cases": [serialize_node(case) for case in cases],
            "default": serialize_node(node.default) if node.default is not None else None,
        }
    if isinstance(node, MatchCase):
        return {
            "type": "MatchCase",
            "pattern": serialize_node(node.pattern),
            "result": serialize_node(node.result),
        }
    if isinstance(node, SpreadOperator):
        return {
            "type": "SpreadOperator",
            "expression": serialize_node(node.expression),
            "is_dict": _serialize_required_bool(node.is_dict, "SpreadOperator is_dict"),
        }
    msg = f"Unsupported simple AST node type: {type(node).__name__}"
    raise SerializationError(msg)


def serialize_yarafile(yf: YaraFile) -> dict[str, Any]:
    """Serialize a YaraFile."""
    imports = _validated_node_collection(yf.imports, "YaraFile imports", Import)
    includes = _validated_node_collection(yf.includes, "YaraFile includes", Include)
    rules = _validated_node_collection(yf.rules, "YaraFile rules", Rule)
    extern_rules = _validated_node_collection(
        yf.extern_rules,
        "YaraFile extern_rules",
        ExternRule,
    )
    extern_imports = _validated_node_collection(
        yf.extern_imports,
        "YaraFile extern_imports",
        ExternImport,
    )
    pragmas = _validated_node_collection(yf.pragmas, "YaraFile pragmas", Pragma)
    namespaces = _validated_node_collection(
        yf.namespaces,
        "YaraFile namespaces",
        ExternNamespace,
    )
    data = {
        "type": "YaraFile",
        "imports": [serialize_node(imp) for imp in imports],
        "includes": [serialize_node(inc) for inc in includes],
        "rules": [serialize_node(rule) for rule in rules],
    }
    if extern_rules:
        data["extern_rules"] = [serialize_extern_rule(rule) for rule in extern_rules]
    if extern_imports:
        data["extern_imports"] = [serialize_node(imp) for imp in extern_imports]
    if pragmas:
        data["pragmas"] = [serialize_pragma(pragma) for pragma in pragmas]
    if namespaces:
        data["namespaces"] = [serialize_node(namespace) for namespace in namespaces]
    return data


def serialize_rule(rule: Rule) -> dict[str, Any]:
    """Serialize a Rule."""
    data: dict[str, Any] = {
        "type": "Rule",
        "name": _serialize_required_nonempty_string(rule.name, "Rule name"),
        "modifiers": _serialize_rule_modifiers(rule.modifiers, "Rule"),
        "condition": serialize_node(rule.condition) if rule.condition is not None else None,
    }

    tags = _serialize_rule_tags(rule.tags)
    if tags:
        data["tags"] = tags

    meta = _serialize_meta_entries(rule.meta)
    if meta:
        data["meta"] = meta

    strings = _serialize_string_definitions(rule.strings)
    if strings:
        data["strings"] = strings

    pragmas = _validated_node_collection(rule.pragmas, "Rule pragmas", InRulePragma)
    if pragmas:
        data["pragmas"] = [serialize_node(pragma) for pragma in pragmas]

    return data


def serialize_extern_rule(extern_rule: ExternRule) -> dict[str, Any]:
    return {
        "type": "ExternRule",
        "name": _serialize_required_nonempty_string(extern_rule.name, "ExternRule name"),
        "modifiers": _serialize_rule_modifiers(extern_rule.modifiers, "ExternRule"),
        "namespace": _serialize_nullable_nonempty_string(
            extern_rule.namespace,
            "ExternRule namespace",
        ),
    }


def _serialize_rule_modifiers(modifiers: Any, context: str) -> list[str]:
    if not isinstance(modifiers, list | tuple):
        msg = f"{context} modifiers must be a list"
        raise SerializationError(msg)

    serialized = []
    for modifier in modifiers:
        if isinstance(modifier, RuleModifier):
            serialized.append(str(modifier))
            continue
        if isinstance(modifier, str):
            serialized.append(modifier)
            continue
        msg = f"{context} modifiers must contain strings or RuleModifier nodes"
        raise SerializationError(msg)
    if any(not modifier for modifier in serialized):
        msg = f"{context} modifiers must contain non-empty strings"
        raise SerializationError(msg)
    return serialized


def _serialize_rule_tags(tags: Any) -> list[str]:
    if not isinstance(tags, list | tuple):
        msg = "Rule tags must be a list"
        raise SerializationError(msg)

    serialized = []
    for tag in tags:
        if isinstance(tag, Tag):
            serialized.append(_serialize_required_nonempty_string(tag.name, "Tag name"))
            continue
        if isinstance(tag, str):
            serialized.append(_serialize_required_nonempty_string(tag, "Tag name"))
            continue
        msg = "Rule tags must contain Tag nodes or strings"
        raise SerializationError(msg)
    return serialized


def serialize_pragma(pragma: Pragma) -> dict[str, Any]:
    data = {
        "type": "Pragma",
        "pragma_type": _serialize_enum_value(pragma.pragma_type, "Pragma pragma_type"),
        "name": _serialize_required_nonempty_string(pragma.name, "Pragma name"),
        "arguments": _serialize_string_list(pragma.arguments, "Pragma arguments"),
        "scope": serialize_pragma_scope(pragma.scope),
    }
    if hasattr(pragma, "macro_name"):
        macro_name = _serialize_required_nonempty_string(
            pragma.macro_name,
            "Pragma macro_name",
        )
    else:
        macro_name = ""
    if macro_name:
        data["macro_name"] = macro_name
    macro_value = _serialize_nullable_string(
        getattr(pragma, "macro_value", None), "Pragma macro_value"
    )
    if macro_value is not None:
        data["macro_value"] = macro_value
    if hasattr(pragma, "condition"):
        if pragma.pragma_type in {PragmaType.IFDEF, PragmaType.IFNDEF}:
            condition = _serialize_required_nonempty_string(
                pragma.condition,
                "Pragma condition",
            )
        else:
            condition = _serialize_nullable_nonempty_string(
                pragma.condition,
                "Pragma condition",
            )
        if condition is not None:
            data["condition"] = condition
    parameters = None
    if hasattr(pragma, "parameters"):
        parameters = _serialize_string_key_dict(pragma.parameters, "Pragma parameters")
    if parameters:
        data["parameters"] = parameters
    return data


def serialize_meta(meta: Meta | MetaEntry) -> dict[str, Any]:
    """Serialize a Meta item."""
    value = (
        _serialize_meta_entry_value(meta.value)
        if isinstance(meta, MetaEntry)
        else _serialize_meta_value(meta.value)
    )
    data = {
        "type": "Meta",
        "key": _serialize_required_nonempty_string(meta.key, "Meta key"),
        "value": value,
    }
    scope = getattr(meta, "scope", None)
    if scope is not None:
        data["type"] = "MetaEntry"
        data["scope"] = serialize_meta_scope(scope)
    if isinstance(meta, ASTNode):
        return _with_node_metadata(meta, data)
    return data


def serialize_string(string_def: Any) -> dict[str, Any]:
    """Serialize a string definition."""
    if isinstance(string_def, PlainString):
        data = {
            "type": "PlainString",
            "identifier": _serialize_required_nonempty_string(
                string_def.identifier,
                "PlainString identifier",
            ),
            "modifiers": _serialize_modifiers(string_def.modifiers, "PlainString"),
        }
        if string_def.is_anonymous:
            data["is_anonymous"] = True
        _serialize_plain_string_value(data, string_def.value)
        return _with_node_metadata(string_def, data)
    if isinstance(string_def, HexString):
        data = {
            "type": "HexString",
            "identifier": _serialize_required_nonempty_string(
                string_def.identifier,
                "HexString identifier",
            ),
            "tokens": [_serialize_hex_token(t) for t in string_def.tokens],
            "modifiers": _serialize_modifiers(string_def.modifiers, "HexString"),
        }
        if string_def.is_anonymous:
            data["is_anonymous"] = True
        return _with_node_metadata(string_def, data)
    if isinstance(string_def, RegexString):
        data = {
            "type": "RegexString",
            "identifier": _serialize_required_nonempty_string(
                string_def.identifier,
                "RegexString identifier",
            ),
            "regex": _serialize_required_nonempty_string(
                string_def.regex,
                "RegexString regex",
            ),
            "modifiers": _serialize_modifiers(string_def.modifiers, "RegexString"),
        }
        if string_def.is_anonymous:
            data["is_anonymous"] = True
        return _with_node_metadata(string_def, data)
    if isinstance(string_def, StringDefinition):
        data = {
            "type": "StringDefinition",
            "identifier": _serialize_required_nonempty_string(
                string_def.identifier,
                "StringDefinition identifier",
            ),
            "modifiers": _serialize_modifiers(string_def.modifiers, "StringDefinition"),
        }
        if string_def.is_anonymous:
            data["is_anonymous"] = True
        return _with_node_metadata(string_def, data)
    data = {"type": "StringDefinition", "data": str(string_def)}
    if isinstance(string_def, ASTNode):
        return _with_node_metadata(string_def, data)
    return data


def deserialize_node(data: dict[str, Any]) -> ASTNode:
    data = _deserialize_object(data, "Serialized node")
    return _apply_node_metadata(_deserialize_node_payload(data), data)


def _deserialize_node_payload(data: dict[str, Any]) -> ASTNode:
    """Deserialize a dictionary to an AST node."""
    node_type = data.get("type")
    if node_type is not None and not isinstance(node_type, str):
        msg = "Serialized node type must be a string"
        raise SerializationError(msg)

    if node_type == "YaraFile":
        return deserialize_yarafile(data)
    if node_type == "Rule":
        return deserialize_rule(data)
    if node_type == "Import":
        return Import(
            _deserialize_nonempty_string_field(data, "module", "Import"),
            alias=_deserialize_nullable_nonempty_string_field(data, "alias", "Import"),
        )
    if node_type == "Include":
        return Include(_deserialize_nonempty_string_field(data, "path", "Include"))
    if node_type == "Tag":
        return Tag(_deserialize_nonempty_string_field(data, "name", "Tag"))
    if node_type == "Meta":
        return Meta(
            _deserialize_nonempty_string_field(data, "key", "Meta"),
            _deserialize_meta_value(data),
        )
    if node_type == "Comment":
        return Comment(
            _deserialize_comment_text(data),
            is_multiline=_deserialize_comment_multiline(data),
        )
    if node_type == "CommentGroup":
        return CommentGroup(
            [
                cast_comment(_deserialize_comment_node(comment))
                for comment in _deserialize_list_field(data, "comments", "CommentGroup")
            ]
        )
    if node_type in {"PlainString", "HexString", "RegexString"}:
        return deserialize_string(data)
    if node_type in {
        "HexByte",
        "HexWildcard",
        "HexJump",
        "HexNibble",
        "HexNegatedByte",
        "HexAlternative",
    }:
        return _deserialize_hex_token(data)
    if node_type == "StringModifier":
        return _deserialize_modifier(data)
    if node_type == "ExternRule":
        return deserialize_extern_rule(data)
    if node_type == "ExternRuleReference":
        return ExternRuleReference(
            rule_name=_deserialize_nonempty_string_field(
                data,
                "rule_name",
                "ExternRuleReference",
            ),
            namespace=_deserialize_nullable_nonempty_string_field(
                data,
                "namespace",
                "ExternRuleReference",
            ),
        )
    if node_type == "ExternImport":
        return ExternImport(
            module_path=_deserialize_nonempty_string_field(
                data,
                "module_path",
                "ExternImport",
            ),
            alias=_deserialize_nullable_nonempty_string_field(data, "alias", "ExternImport"),
            rules=_deserialize_nonempty_string_list_field(data, "rules", "ExternImport"),
        )
    if node_type == "ExternNamespace":
        return ExternNamespace(
            name=_deserialize_nonempty_string_field(data, "name", "ExternNamespace"),
            extern_rules=[
                deserialize_extern_rule(rule)
                for rule in _deserialize_list_field(data, "extern_rules", "ExternNamespace")
            ],
        )
    if node_type == "InRulePragma":
        return InRulePragma(
            pragma=deserialize_pragma(_deserialize_required_field(data, "pragma", "InRulePragma")),
            position=_deserialize_in_rule_pragma_position(data),
        )
    if node_type == "PragmaBlock":
        return PragmaBlock(
            pragmas=[
                deserialize_pragma(pragma)
                for pragma in _deserialize_list_field(data, "pragmas", "PragmaBlock")
            ],
            scope=_deserialize_pragma_scope(data.get("scope"), "PragmaBlock"),
        )
    if node_type == "Pragma":
        return deserialize_pragma(data)
    if node_type == "BooleanLiteral":
        return BooleanLiteral(_deserialize_boolean_literal_value(data))
    if node_type == "IntegerLiteral":
        return IntegerLiteral(_deserialize_integer_literal_value(data))
    if node_type == "DoubleLiteral":
        return DoubleLiteral(_deserialize_double_literal_value(data))
    if node_type == "StringLiteral":
        return StringLiteral(_deserialize_string_field(data, "value", "StringLiteral"))
    if node_type == "RegexLiteral":
        return RegexLiteral(
            _deserialize_nonempty_string_field(data, "pattern", "RegexLiteral"),
            _deserialize_optional_string_field(data, "modifiers", "RegexLiteral"),
        )
    if node_type == "Identifier":
        return Identifier(_deserialize_nonempty_string_field(data, "name", "Identifier"))
    if node_type == "StringIdentifier":
        return StringIdentifier(
            _deserialize_nonempty_string_field(data, "name", "StringIdentifier")
        )
    if node_type == "StringWildcard":
        return StringWildcard(_deserialize_nonempty_string_field(data, "pattern", "StringWildcard"))
    if node_type == "StringCount":
        return StringCount(_deserialize_nonempty_string_field(data, "string_id", "StringCount"))
    if node_type == "StringOffset":
        return StringOffset(
            _deserialize_nonempty_string_field(data, "string_id", "StringOffset"),
            _deserialize_optional_node_field(data, "index", "StringOffset index"),
        )
    if node_type == "StringLength":
        return StringLength(
            _deserialize_nonempty_string_field(data, "string_id", "StringLength"),
            _deserialize_optional_node_field(data, "index", "StringLength index"),
        )
    if node_type == "BinaryExpression":
        return BinaryExpression(
            _deserialize_required_node(data, "left", "BinaryExpression"),
            _deserialize_nonempty_string_field(data, "operator", "BinaryExpression"),
            _deserialize_required_node(data, "right", "BinaryExpression"),
        )
    if node_type == "UnaryExpression":
        return UnaryExpression(
            _deserialize_nonempty_string_field(data, "operator", "UnaryExpression"),
            _deserialize_required_node(data, "operand", "UnaryExpression"),
        )
    if node_type == "ParenthesesExpression":
        return ParenthesesExpression(
            _deserialize_required_node(data, "expression", "ParenthesesExpression")
        )
    if node_type == "SetExpression":
        return SetExpression(_deserialize_node_list_field(data, "elements", "SetExpression"))
    if node_type == "RangeExpression":
        return RangeExpression(
            _deserialize_required_node(data, "low", "RangeExpression"),
            _deserialize_required_node(data, "high", "RangeExpression"),
        )
    if node_type == "FunctionCall":
        return FunctionCall(
            _deserialize_nonempty_string_field(data, "function", "FunctionCall"),
            _deserialize_node_list_field(data, "arguments", "FunctionCall"),
        )
    if node_type == "ArrayAccess":
        return ArrayAccess(
            _deserialize_required_node(data, "array", "ArrayAccess"),
            _deserialize_required_node(data, "index", "ArrayAccess"),
        )
    if node_type == "MemberAccess":
        return MemberAccess(
            _deserialize_required_node(data, "object", "MemberAccess"),
            _deserialize_nonempty_string_field(data, "member", "MemberAccess"),
        )
    if node_type == "ForExpression":
        variable = _deserialize_optional_string_field(data, "variable", "ForExpression", "i")
        if not variable:
            msg = "ForExpression variable must not be empty"
            raise SerializationError(msg)
        return ForExpression(
            _deserialize_required_quantifier(data, "quantifier", "ForExpression"),
            variable,
            _deserialize_required_node(data, "iterable", "ForExpression"),
            _deserialize_required_node(data, "body", "ForExpression"),
        )
    if node_type == "ForOfExpression":
        return ForOfExpression(
            _deserialize_required_quantifier(data, "quantifier", "ForOfExpression"),
            _deserialize_required_string_set(data, "string_set", "ForOfExpression"),
            _deserialize_optional_node_field(data, "condition", "ForOfExpression condition"),
        )
    if node_type == "AtExpression":
        raw_subject = data.get("string_id")
        if isinstance(raw_subject, dict):
            subject = _deserialize_required_node_value(raw_subject, "AtExpression string_id")
        elif isinstance(raw_subject, str):
            subject = _deserialize_nonempty_string_field(data, "string_id", "AtExpression")
        else:
            subject = _deserialize_string_field(data, "string_id", "AtExpression")
        return AtExpression(
            subject,
            _deserialize_required_node(data, "offset", "AtExpression"),
        )
    if node_type == "InExpression":
        raw_subject = data.get("subject")
        if raw_subject is None and "string_id" in data:
            raw_subject = data["string_id"]
        if isinstance(raw_subject, dict):
            subject = _deserialize_required_node_value(raw_subject, "InExpression subject")
        elif isinstance(raw_subject, str):
            subject = raw_subject
        else:
            msg = "InExpression subject must be a string or expression"
            raise SerializationError(msg)
        return InExpression(subject, _deserialize_required_node(data, "range", "InExpression"))
    if node_type == "OfExpression":
        return OfExpression(
            _deserialize_required_quantifier(data, "quantifier", "OfExpression"),
            _deserialize_required_string_set(data, "string_set", "OfExpression"),
        )
    if node_type == "ModuleReference":
        return ModuleReference(
            _deserialize_nonempty_string_field(data, "module", "ModuleReference")
        )
    if node_type == "DictionaryAccess":
        return DictionaryAccess(
            _deserialize_required_node(data, "object", "DictionaryAccess"),
            _deserialize_dictionary_key(data),
        )
    if node_type == "DefinedExpression":
        expression = data.get("expression")
        if expression is None and "identifier" in data:
            expression = {"type": "Identifier", "name": data["identifier"]}
        return DefinedExpression(
            _deserialize_required_node_value(expression, "DefinedExpression expression")
        )
    if node_type == "StringOperatorExpression":
        left = data.get("left")
        right = data.get("right")
        if left is None and "subject" in data:
            left = data["subject"]
        if right is None and "pattern" in data:
            right = {"type": "StringLiteral", "value": data.get("pattern", "")}
        if left is None:
            left = {"type": "Identifier", "name": "true"}
        if right is None:
            right = {"type": "Identifier", "name": "true"}
        return StringOperatorExpression(
            _deserialize_required_node_value(left, "StringOperatorExpression left"),
            _deserialize_nonempty_string_field(data, "operator", "StringOperatorExpression"),
            _deserialize_required_node_value(right, "StringOperatorExpression right"),
        )
    if node_type == "WithStatement":
        return WithStatement(
            declarations=_deserialize_node_list_field(data, "declarations", "WithStatement"),
            body=_deserialize_required_node(data, "body", "WithStatement"),
        )
    if node_type == "WithDeclaration":
        return WithDeclaration(
            identifier=_deserialize_nonempty_string_field(data, "identifier", "WithDeclaration"),
            value=_deserialize_required_node(data, "value", "WithDeclaration"),
        )
    if node_type == "ArrayComprehension":
        variable = _deserialize_optional_string_field(data, "variable", "ArrayComprehension")
        if "variable" in data and not variable:
            msg = "ArrayComprehension variable must not be empty"
            raise SerializationError(msg)
        return ArrayComprehension(
            expression=_deserialize_optional_node_field(
                data, "expression", "ArrayComprehension expression"
            ),
            variable=variable,
            iterable=_deserialize_optional_node_field(
                data, "iterable", "ArrayComprehension iterable"
            ),
            condition=_deserialize_optional_node_field(
                data, "condition", "ArrayComprehension condition"
            ),
        )
    if node_type == "DictComprehension":
        key_variable = _deserialize_optional_string_field(data, "key_variable", "DictComprehension")
        if "key_variable" in data and not key_variable:
            msg = "DictComprehension key_variable must not be empty"
            raise SerializationError(msg)
        value_variable = _deserialize_nullable_nonempty_string_field(
            data,
            "value_variable",
            "DictComprehension",
        )
        return DictComprehension(
            key_expression=_deserialize_optional_node_field(
                data, "key_expression", "DictComprehension key_expression"
            ),
            value_expression=_deserialize_optional_node_field(
                data, "value_expression", "DictComprehension value_expression"
            ),
            key_variable=key_variable,
            value_variable=value_variable,
            iterable=_deserialize_optional_node_field(
                data, "iterable", "DictComprehension iterable"
            ),
            condition=_deserialize_optional_node_field(
                data, "condition", "DictComprehension condition"
            ),
        )
    if node_type == "TupleExpression":
        return TupleExpression(
            elements=_deserialize_node_list_field(data, "elements", "TupleExpression"),
        )
    if node_type == "TupleIndexing":
        return TupleIndexing(
            tuple_expr=_deserialize_required_node(data, "tuple_expr", "TupleIndexing"),
            index=_deserialize_required_node(data, "index", "TupleIndexing"),
        )
    if node_type == "ListExpression":
        return ListExpression(
            elements=_deserialize_node_list_field(data, "elements", "ListExpression"),
        )
    if node_type == "DictExpression":
        return DictExpression(
            items=_deserialize_node_list_field(data, "items", "DictExpression"),
        )
    if node_type == "DictItem":
        return DictItem(
            key=_deserialize_required_node(data, "key", "DictItem"),
            value=_deserialize_required_node(data, "value", "DictItem"),
        )
    if node_type == "SliceExpression":
        return SliceExpression(
            target=_deserialize_required_node(data, "target", "SliceExpression"),
            start=_deserialize_optional_node_field(data, "start", "SliceExpression start"),
            stop=_deserialize_optional_node_field(data, "stop", "SliceExpression stop"),
            step=_deserialize_optional_node_field(data, "step", "SliceExpression step"),
        )
    if node_type == "LambdaExpression":
        return LambdaExpression(
            parameters=_deserialize_nonempty_string_list_field(
                data,
                "parameters",
                "LambdaExpression",
            ),
            body=_deserialize_required_node(data, "body", "LambdaExpression"),
        )
    if node_type == "PatternMatch":
        return PatternMatch(
            value=_deserialize_required_node(data, "value", "PatternMatch"),
            cases=_deserialize_node_list_field(data, "cases", "PatternMatch"),
            default=_deserialize_optional_node_field(data, "default", "PatternMatch default"),
        )
    if node_type == "MatchCase":
        return MatchCase(
            pattern=_deserialize_required_node(data, "pattern", "MatchCase"),
            result=_deserialize_required_node(data, "result", "MatchCase"),
        )
    if node_type == "SpreadOperator":
        return SpreadOperator(
            expression=_deserialize_required_node(data, "expression", "SpreadOperator"),
            is_dict=_deserialize_bool_field(data, "is_dict", "SpreadOperator"),
        )
    return Identifier(
        _deserialize_optional_string_field(data, "data", "Serialized node", "unknown")
    )


def deserialize_yarafile(data: dict[str, Any]) -> YaraFile:
    """Deserialize a YaraFile."""
    yf = YaraFile()
    yf.imports = [
        _deserialize_expected_node(imp, Import, "YaraFile imports", "Import")
        for imp in _deserialize_list_field(data, "imports", "YaraFile")
    ]
    yf.includes = [
        _deserialize_expected_node(inc, Include, "YaraFile includes", "Include")
        for inc in _deserialize_list_field(data, "includes", "YaraFile")
    ]
    yf.rules = [
        _deserialize_expected_node(rule, Rule, "YaraFile rules", "Rule")
        for rule in _deserialize_list_field(data, "rules", "YaraFile")
    ]
    yf.extern_rules = [
        _deserialize_extern_rule_item(rule, "YaraFile extern_rules")
        for rule in _deserialize_list_field(data, "extern_rules", "YaraFile")
    ]
    yf.extern_imports = [
        _deserialize_expected_node(imp, ExternImport, "YaraFile extern_imports", "ExternImport")
        for imp in _deserialize_list_field(data, "extern_imports", "YaraFile")
    ]
    yf.pragmas = [
        _deserialize_pragma_item(pragma, "YaraFile pragmas")
        for pragma in _deserialize_list_field(data, "pragmas", "YaraFile")
    ]
    yf.namespaces = [
        _deserialize_expected_node(
            namespace,
            ExternNamespace,
            "YaraFile namespaces",
            "ExternNamespace",
        )
        for namespace in _deserialize_list_field(data, "namespaces", "YaraFile")
    ]
    return yf


def deserialize_rule(data: dict[str, Any]) -> Rule:
    """Deserialize a Rule."""
    data = _deserialize_object(data, "Rule")
    condition_data = data.get("condition")
    condition = _deserialize_optional_node_value(condition_data, "Rule condition")
    rule = Rule(
        name=_deserialize_nonempty_string_field(data, "name", "Rule"),
        modifiers=_deserialize_rule_modifiers(
            _deserialize_nonempty_string_list_field(data, "modifiers", "Rule")
        ),
        condition=condition if condition is not None else BooleanLiteral(True),
    )

    if "tags" in data:
        rule.tags = [
            _deserialize_rule_tag(tag) for tag in _deserialize_list_field(data, "tags", "Rule")
        ]

    if "meta" in data:
        rule.meta = [deserialize_meta(m) for m in _deserialize_list_field(data, "meta", "Rule")]

    if "strings" in data:
        rule.strings = [
            deserialize_string(s) for s in _deserialize_list_field(data, "strings", "Rule")
        ]

    if "pragmas" in data:
        rule.pragmas = [
            cast_in_rule_pragma(deserialize_node(pragma))
            for pragma in _deserialize_list_field(data, "pragmas", "Rule")
        ]

    return rule


def _deserialize_rule_modifiers(modifiers: list[Any]) -> list[Any]:
    normalized = []
    for modifier in modifiers:
        if isinstance(modifier, str):
            try:
                normalized.append(RuleModifier.from_string(modifier))
            except (ValueError, ValidationError):
                normalized.append(modifier)
        else:
            normalized.append(modifier)
    return normalized


def deserialize_extern_rule(data: dict[str, Any]) -> ExternRule:
    return ExternRule(
        name=_deserialize_nonempty_string_field(data, "name", "ExternRule"),
        modifiers=_deserialize_rule_modifiers(
            _deserialize_nonempty_string_list_field(data, "modifiers", "ExternRule")
        ),
        namespace=_deserialize_nullable_nonempty_string_field(data, "namespace", "ExternRule"),
    )


def _deserialize_pragma_scope(value: Any, context: str = "Pragma") -> PragmaScope:
    return deserialize_pragma_scope(value, context)


def _deserialize_in_rule_pragma_position(data: dict[str, Any]) -> str:
    position = _deserialize_optional_string_field(
        data,
        "position",
        "InRulePragma",
        "before_strings",
    )
    if not position:
        msg = "InRulePragma position must not be empty"
        raise SerializationError(msg)
    return position


def deserialize_pragma(data: dict[str, Any]) -> Pragma:
    data = _deserialize_object(data, "Pragma")
    pragma_type = _deserialize_pragma_type(data)
    scope = _deserialize_pragma_scope(data.get("scope"))
    name = _deserialize_optional_string_field(data, "name", "Pragma", pragma_type.value)
    if not name:
        msg = "Pragma name must not be empty"
        raise SerializationError(msg)
    arguments = _deserialize_string_list_field(data, "arguments", "Pragma")

    if pragma_type == PragmaType.INCLUDE_ONCE:
        pragma = IncludeOncePragma()
    elif pragma_type == PragmaType.DEFINE and "macro_name" in data:
        pragma = DefineDirective(
            macro_name=_deserialize_nonempty_string_field(data, "macro_name", "Pragma"),
            macro_value=_deserialize_nullable_string_field(data, "macro_value", "Pragma"),
        )
    elif pragma_type == PragmaType.UNDEF and "macro_name" in data:
        pragma = UndefDirective(
            macro_name=_deserialize_nonempty_string_field(data, "macro_name", "Pragma")
        )
    elif pragma_type in {PragmaType.IFDEF, PragmaType.IFNDEF, PragmaType.ENDIF}:
        condition = (
            _deserialize_nonempty_string_field(data, "condition", "Pragma")
            if pragma_type in {PragmaType.IFDEF, PragmaType.IFNDEF}
            else _deserialize_nullable_nonempty_string_field(data, "condition", "Pragma")
        )
        pragma = ConditionalDirective(
            pragma_type,
            condition=condition,
        )
    elif pragma_type == PragmaType.CUSTOM:
        pragma = CustomPragma(
            name=name,
            arguments=arguments,
            parameters=_deserialize_dict_field(data, "parameters", "Pragma"),
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
    return pragma


def cast_in_rule_pragma(node: ASTNode) -> InRulePragma:
    if isinstance(node, InRulePragma):
        return node
    msg = "Rule pragmas must contain InRulePragma nodes"
    raise SerializationError(msg)


def cast_comment(node: ASTNode) -> Comment:
    if isinstance(node, Comment):
        return node
    msg = "CommentGroup comments must contain Comment nodes"
    raise SerializationError(msg)


def cast_leading_comment(node: ASTNode) -> Any:
    if isinstance(node, Comment | CommentGroup):
        return node
    msg = "leading_comments must contain Comment or CommentGroup nodes"
    raise SerializationError(msg)


def cast_trailing_comment(node: ASTNode) -> Any:
    if isinstance(node, Comment | CommentGroup):
        return node
    msg = "trailing_comment must contain Comment or CommentGroup nodes"
    raise SerializationError(msg)


def deserialize_meta(data: dict[str, Any]) -> Meta | MetaEntry:
    """Deserialize a Meta item."""
    data = _deserialize_object(data, "Meta")
    node_type = data.get("type")
    if node_type is not None and node_type not in {"Meta", "MetaEntry"}:
        msg = "Meta type must be Meta or MetaEntry"
        raise SerializationError(msg)
    scope = data.get("scope")
    if data.get("type") == "MetaEntry" or scope is not None:
        return MetaEntry.from_key_value(
            _deserialize_nonempty_string_field(data, "key", "Meta"),
            _deserialize_meta_entry_value(data),
            deserialize_meta_scope(_deserialize_nullable_string_field(data, "scope", "Meta")),
        )
    return _apply_node_metadata(
        Meta(
            _deserialize_nonempty_string_field(data, "key", "Meta"),
            _deserialize_meta_value(data),
        ),
        data,
    )


def deserialize_string(data: dict[str, Any]) -> Any:
    """Deserialize a string definition."""
    data = _deserialize_object(data, "String")
    string_type = data.get("type")
    if string_type is not None and not isinstance(string_type, str):
        msg = "String type must be a string"
        raise SerializationError(msg)
    context = string_type if string_type is not None else "String"
    modifiers = _deserialize_modifiers(_deserialize_list_field(data, "modifiers", context))

    if string_type == "PlainString":
        return _apply_node_metadata(
            PlainString(
                identifier=_deserialize_nonempty_string_field(data, "identifier", "PlainString"),
                value=_deserialize_plain_string_value(data),
                modifiers=modifiers,
                is_anonymous=_deserialize_is_anonymous(data),
            ),
            data,
        )
    if string_type == "HexString":
        raw_tokens = data.get("tokens", [])
        if isinstance(raw_tokens, list):
            tokens = [_deserialize_hex_token(t) for t in raw_tokens]
            return _apply_node_metadata(
                HexString(
                    identifier=_deserialize_nonempty_string_field(
                        data,
                        "identifier",
                        "HexString",
                    ),
                    tokens=tokens,
                    modifiers=modifiers,
                    is_anonymous=_deserialize_is_anonymous(data),
                ),
                data,
            )
        if isinstance(raw_tokens, str):
            try:
                return _apply_node_metadata(
                    HexString(
                        identifier=_deserialize_nonempty_string_field(
                            data,
                            "identifier",
                            "HexString",
                        ),
                        tokens=_deserialize_legacy_hex_tokens(raw_tokens),
                        modifiers=modifiers,
                        is_anonymous=_deserialize_is_anonymous(data),
                    ),
                    data,
                )
            except HexParseError as exc:
                msg = f"Invalid legacy HexString tokens: {exc}"
                raise SerializationError(msg) from exc

        # Legacy format with invalid token payloads: preserve type but do not invent tokens.
        import warnings

        identifier = _deserialize_nonempty_string_field(data, "identifier", "HexString")
        warnings.warn(
            f"HexString '{identifier}' has non-list tokens in serialized data, "
            "tokens will be empty after deserialization",
            stacklevel=2,
        )
        return _apply_node_metadata(
            HexString(
                identifier=identifier,
                tokens=[],
                modifiers=modifiers,
                is_anonymous=_deserialize_is_anonymous(data),
            ),
            data,
        )
    if string_type == "RegexString":
        return _apply_node_metadata(
            RegexString(
                identifier=_deserialize_nonempty_string_field(
                    data,
                    "identifier",
                    "RegexString",
                ),
                regex=_deserialize_nonempty_string_field(data, "regex", "RegexString"),
                modifiers=modifiers,
                is_anonymous=_deserialize_is_anonymous(data),
            ),
            data,
        )
    if string_type == "StringDefinition":
        return _apply_node_metadata(
            StringDefinition(
                identifier=_deserialize_nonempty_string_field(
                    data,
                    "identifier",
                    "StringDefinition",
                ),
                modifiers=modifiers,
                is_anonymous=_deserialize_is_anonymous(data),
            ),
            data,
        )
    if string_type in {None, "Unknown"}:
        return _apply_node_metadata(
            PlainString(
                identifier=_deserialize_optional_string_field(
                    data, "identifier", "String", "$unknown"
                ),
                value=_deserialize_legacy_string_data(data),
            ),
            data,
        )
    msg = f"Unknown string type: {string_type}"
    raise SerializationError(msg)


def serialize_to_file(node: ASTNode, file_path: str | Path) -> None:
    """Serialize an AST node to a JSON file."""
    data = serialize_node(node)
    file_path = Path(file_path)
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def deserialize_from_file(file_path: str | Path) -> ASTNode:
    """Deserialize an AST node from a JSON file."""
    file_path = Path(file_path)
    with open(file_path, encoding="utf-8") as f:
        data = json.load(f)
    return deserialize_node(data)


def validate_roundtrip(node: ASTNode) -> tuple[bool, dict[str, Any]]:
    """Validate roundtrip serialization."""
    generator = YaraXGenerator()
    try:
        serialized = serialize_node(node)
        deserialized = deserialize_node(serialized)
        original_code = generator.generate(node)
        roundtrip_code = generator.generate(deserialized)
        is_valid = original_code.strip() == roundtrip_code.strip()
        diff = {
            "original_code": original_code,
            "roundtrip_code": roundtrip_code,
            "differences": [] if is_valid else ["Code differs after roundtrip"],
        }
        return is_valid, diff
    except (YaraASTError, ValueError, TypeError) as e:  # serialization + codegen roundtrip errors
        return False, {"error": str(e)}


def simple_roundtrip_report(yara_source: str) -> dict[str, Any]:
    """Perform a simple roundtrip test."""
    generator = YaraXGenerator()
    try:
        original_ast = parse_yara_source(yara_source)
        reconstructed = generator.generate(original_ast)
        original_normalized = yara_source.strip()
        reconstructed_normalized = reconstructed.strip()
        success, differences = _compare_normalized(original_normalized, reconstructed_normalized)
        reconstructed_ast = parse_yara_source(reconstructed)
        return {
            "original_source": original_normalized,
            "reconstructed_source": reconstructed_normalized,
            "round_trip_successful": success,
            "differences": differences,
            "metadata": {
                "original_rule_count": len(original_ast.rules) if original_ast else 0,
                "reconstructed_rule_count": (
                    len(reconstructed_ast.rules) if reconstructed_ast else 0
                ),
            },
        }
    except (YaraASTError, ValueError, TypeError) as e:  # parse + codegen roundtrip errors
        return {
            "original_source": yara_source,
            "reconstructed_source": "",
            "round_trip_successful": False,
            "differences": [f"Error during roundtrip: {e!s}"],
            "metadata": {},
        }


def _compare_normalized(original: str, reconstructed: str) -> tuple[bool, list[str]]:
    """Compare normalized YARA source lines."""
    differences: list[str] = []
    original_lines = [line.strip() for line in original.split("\n") if line.strip()]
    reconstructed_lines = [line.strip() for line in reconstructed.split("\n") if line.strip()]

    if original_lines == reconstructed_lines:
        return True, differences

    if len(original_lines) != len(reconstructed_lines):
        differences.append(
            f"Line count differs: {len(original_lines)} vs {len(reconstructed_lines)}",
        )

    for i, (orig, recon) in enumerate(
        zip(original_lines, reconstructed_lines, strict=False),
    ):
        if orig != recon:
            differences.append(f"Line {i + 1} differs: '{orig}' vs '{recon}'")
            if len(differences) > 5:
                differences.append("... more differences")
                break

    return False, differences
