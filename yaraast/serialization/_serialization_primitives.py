"""Serialization primitives shared across the JSON, protobuf and round-trip layers.

These field-extraction, location, literal-value, hex, enum and empty-text helpers
were byte-identical copies scattered across the serialization modules. They are
defined once here and imported where needed.
"""

from __future__ import annotations

import base64
import binascii
import math
from typing import Any

from yaraast.ast.base import Location
from yaraast.ast.modifiers import RuleModifier, require_rule_modifier_identifier
from yaraast.codegen.generator_formatting import validate_yara_identifier
from yaraast.errors import SerializationError, ValidationError
from yaraast.shared.local_scope import local_name_variants, validate_local_identifier
from yaraast.string_references import normalize_string_reference_id

_HEX_CHARS = frozenset("0123456789abcdefABCDEF")


_WHITESPACE_SIGNIFICANT_NONEMPTY_CONTEXTS = frozenset(
    {
        "RegexLiteral pattern",
        "RegexString regex",
    }
)


def _is_empty_nonempty_text(text: str, context: str) -> bool:
    return not text or (
        not text.strip() and context not in _WHITESPACE_SIGNIFICANT_NONEMPTY_CONTEXTS
    )


def _expected_type_names(expected_type: type[Any] | tuple[type[Any], ...]) -> str:
    expected_types = expected_type if isinstance(expected_type, tuple) else (expected_type,)
    return " or ".join(item_type.__name__ for item_type in expected_types)


def _normalize_rule_modifier_text(value: str, context: str) -> str:
    try:
        return str(RuleModifier.from_string(value))
    except (ValueError, ValidationError):
        try:
            if context in {"Rule", "Rule modifier"}:
                require_rule_modifier_identifier(value, "Rule modifier", "rule modifier")
            elif context in {"ExternRule", "ExternRule modifier"}:
                require_rule_modifier_identifier(value, "ExternRule modifier")
            else:
                require_rule_modifier_identifier(value, f"{context} modifier")
        except ValidationError as exc:
            raise SerializationError(str(exc)) from exc
        return value


def _validate_local_identifier_text(
    value: str,
    *,
    allow_string_identifier: bool = False,
) -> str:
    try:
        return validate_local_identifier(
            value,
            allow_string_identifier=allow_string_identifier,
        )
    except (TypeError, ValueError) as exc:
        raise SerializationError(str(exc)) from exc


def _validate_loop_variable_text(value: str) -> str:
    try:
        local_name_variants(value)
    except (TypeError, ValueError) as exc:
        raise SerializationError(str(exc)) from exc
    return value


def _validate_local_identifier_list(values: list[str]) -> list[str]:
    for value in values:
        _validate_local_identifier_text(value)
    return values


def _validate_yara_identifier_text(value: str, kind: str) -> str:
    try:
        return validate_yara_identifier(value, kind)
    except (TypeError, ValueError) as exc:
        raise SerializationError(str(exc)) from exc


def _validate_unique_rule_identifiers(rules: list[Any] | tuple[Any, ...]) -> None:
    seen: set[str] = set()
    for rule in rules:
        try:
            name = validate_yara_identifier(getattr(rule, "name", None), "rule")
        except (TypeError, ValueError):
            continue
        if name in seen:
            msg = f"Duplicate rule identifier '{name}' for libyara output"
            raise SerializationError(msg)
        seen.add(name)


def _validate_unique_rule_tags(tags: list[Any] | tuple[Any, ...]) -> None:
    seen: set[str] = set()
    for tag in tags:
        name = tag if isinstance(tag, str) else getattr(tag, "name", None)
        try:
            validated_name = validate_yara_identifier(name, "tag")
        except (TypeError, ValueError):
            continue
        if validated_name in seen:
            msg = f"Duplicate tag identifier '{validated_name}' for libyara output"
            raise SerializationError(msg)
        seen.add(validated_name)


def _validate_string_reference_text(
    value: str,
    *,
    allow_wildcard: bool = False,
    allow_placeholder: bool = False,
) -> str:
    if allow_placeholder and value == "$":
        return value
    try:
        normalize_string_reference_id(value, allow_wildcard=allow_wildcard)
    except (TypeError, ValueError) as exc:
        raise SerializationError(str(exc)) from exc
    return value


def _validate_location_metadata(
    location: Any,
    *,
    validate_structure: bool = True,
) -> Location:
    if not isinstance(location, Location):
        msg = "location must be a Location"
        raise SerializationError(msg)
    if not validate_structure:
        return location
    try:
        location.validate_structure()
    except (TypeError, ValueError) as exc:
        raise SerializationError(str(exc)) from exc
    return location


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
    location = Location(
        line=_deserialize_location_int_field(data, "line"),
        column=_deserialize_location_int_field(data, "column"),
        file=_deserialize_nullable_string_field(data, "file", "Location"),
        end_line=_deserialize_location_optional_int_field(data, "end_line"),
        end_column=_deserialize_location_optional_int_field(data, "end_column"),
    )
    try:
        location.validate_structure()
    except (TypeError, ValueError) as exc:
        raise SerializationError(str(exc)) from exc
    return location


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


def _deserialize_plain_string_raw_bytes(data: dict[str, Any]) -> bytes | None:
    if "raw_value" not in data:
        return None
    if data.get("raw_value_encoding") != "base64":
        msg = "PlainString raw_value must use base64 encoding"
        raise SerializationError(msg)
    value = data["raw_value"]
    if not isinstance(value, str):
        msg = "PlainString raw_value must be a base64 string"
        raise SerializationError(msg)
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError) as exc:
        msg = "Invalid base64-encoded plain string raw_value"
        raise SerializationError(msg) from exc


def _deserialize_is_anonymous(data: dict[str, Any]) -> bool:
    if "is_anonymous" not in data:
        return False
    value = data["is_anonymous"]
    if isinstance(value, bool):
        return value
    msg = "is_anonymous must be a boolean"
    raise SerializationError(msg)


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


def _deserialize_string_field(data: dict[str, Any], field: str, context: str) -> str:
    value = _deserialize_required_field(data, field, context)
    if isinstance(value, str):
        return value
    msg = f"{context} {field} must be a string"
    raise SerializationError(msg)


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


def _deserialize_string_list_field(data: dict[str, Any], field: str, context: str) -> list[str]:
    data = _deserialize_object(data, context)
    value = data.get(field, [])
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return value
    msg = f"{context} {field} must be a list of strings"
    raise SerializationError(msg)


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


def _is_negated_nibble_pattern(value: str) -> bool:
    if len(value) != 2:
        return False
    first = value[0]
    second = value[1]
    return (first == "?" and second in _HEX_CHARS) or (first in _HEX_CHARS and second == "?")
