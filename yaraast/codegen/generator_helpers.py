"""Helper functions for code generation formatting."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import fields
from decimal import Decimal
import math
import re
from typing import Any, NamedTuple

from yaraast.ast.base import ASTNode
from yaraast.ast.conditions import ForExpression, ForOfExpression, InExpression, OfExpression
from yaraast.ast.expressions import (
    ParenthesesExpression,
    RangeExpression,
    SetExpression,
    StringWildcard,
)
from yaraast.ast.modifiers import StringModifier
from yaraast.ast.strings import (
    HexAlternative,
    HexByte,
    HexJump,
    HexNegatedByte,
    HexNibble,
    HexString,
    HexWildcard,
    PlainString,
    RegexString,
)
from yaraast.limits import LIBYARA_HEX_JUMP_MAX
from yaraast.regex_literals import (
    REGEX_MODIFIER_ORDER,
    VALID_REGEX_MODIFIERS,
    escape_regex_delimiter as _escape_regex_delimiter,
    validate_regex_modifiers,
)
from yaraast.xor_keys import parse_xor_key_text

REGEX_SUFFIX_MODIFIERS = VALID_REGEX_MODIFIERS
REGEX_SUFFIX_NAMES = {"dotall": "s"}
_UNSUPPORTED_REGEX_MODIFIERS = frozenset({"m", "multiline"})
_UNSUPPORTED_SPACED_STRING_MODIFIERS = frozenset(
    {
        "case",
        "dotall",
        "i",
        "m",
        "multiline",
        "s",
        "utf8",
        "utf16",
        "utf16le",
        "utf16be",
    }
)
_KNOWN_STRING_MODIFIERS = frozenset(
    {
        "ascii",
        "base64",
        "base64wide",
        "case",
        "dotall",
        "fullword",
        "i",
        "m",
        "multiline",
        "nocase",
        "private",
        "s",
        "utf8",
        "utf16",
        "utf16be",
        "utf16le",
        "wide",
        "xor",
    }
)
_HEX_ALLOWED_MODIFIERS = frozenset({"private"})
_REGEX_DISALLOWED_MODIFIERS = frozenset({"base64", "base64wide", "xor"})
_BASE64_INCOMPATIBLE_MODIFIERS = frozenset({"fullword", "nocase", "xor"})
_XOR_INCOMPATIBLE_MODIFIERS = frozenset({"base64", "base64wide", "nocase"})
BASE64_MODIFIERS = frozenset({"base64", "base64wide"})
_PARAMETERIZED_STRING_MODIFIERS = BASE64_MODIFIERS | {"xor"}
_HEX_CHARS = frozenset("0123456789abcdefABCDEF")
_STRING_IDENTIFIER_BODY_RE = re.compile(r"^[A-Za-z0-9_]+$")
_YARA_INTEGER_TEXT_RE = re.compile(r"^[+-]?(?:0[xX][0-9A-Fa-f]+|0[oO][0-7]+|[0-9]+(?:KB|MB))$")
_STRING_PLACEHOLDER_REFERENCES = frozenset({"", "$"})
_YARA_INTEGER_MIN = -(2**63) + 1
_YARA_INTEGER_MAX = 2**63 - 1


class _XorKey(NamedTuple):
    key: int
    text: str


def _escape_plain_byte(value: int) -> str:
    if value == 0x5C:
        return "\\\\"
    if value == 0x22:
        return '\\"'
    if value == 0x0A:
        return "\\n"
    if value == 0x0D:
        return "\\r"
    if value == 0x09:
        return "\\t"
    if 0x20 <= value <= 0x7E:
        return chr(value)
    return f"\\x{value:02x}"


def escape_plain_string_value(value: str | bytes) -> str:
    """Escape plain string content for YARA output."""
    if isinstance(value, bytes):
        return "".join(_escape_plain_byte(byte) for byte in value)
    if not isinstance(value, str):
        msg = "Plain string value must be a string or bytes for libyara output"
        raise TypeError(msg)

    escaped_value = value.replace("\\", "\\\\")
    escaped_value = escaped_value.replace('"', '\\"')
    escaped_value = escaped_value.replace("\n", "\\n")
    escaped_value = escaped_value.replace("\r", "\\r")
    escaped_value = escaped_value.replace("\t", "\\t")
    escaped_value = escaped_value.replace("\x00", "\\x00")
    return re.sub(
        r"[\x01-\x1f\x7f-\x9f]",
        lambda m: f"\\x{ord(m.group(0)):02x}",
        escaped_value,
    )


def plain_string_render_source(node: Any) -> str | bytes:
    """Return the faithful escape source for a plain string.

    The lexer records the exact matched bytes in ``raw_bytes`` so high-byte
    escapes (\\xHH, 0x80-0xFF) round-trip without being re-encoded as UTF-8;
    fall back to the decoded ``value`` for programmatically built nodes.
    """
    raw_bytes = getattr(node, "raw_bytes", None)
    if isinstance(raw_bytes, bytes):
        return raw_bytes
    value: str | bytes = node.value
    return value


def escape_regex_delimiter(pattern: str) -> str:
    """Escape unescaped '/' characters without double-escaping existing escapes."""
    if not isinstance(pattern, str):
        msg = "Regex pattern must be a string for libyara output"
        raise TypeError(msg)
    if pattern == "":
        msg = "Regex pattern must not be empty for libyara output"
        raise ValueError(msg)
    if "\n" in pattern or "\r" in pattern:
        msg = "Regex pattern must not contain line breaks for libyara output"
        raise ValueError(msg)
    if "\x00" in pattern:
        msg = "Regex pattern must not contain NUL bytes for libyara output"
        raise ValueError(msg)
    return _escape_regex_delimiter(pattern)


def output_string_identifier(string_def: Any) -> str:
    """Return the YARA source identifier for a string definition."""
    if getattr(string_def, "is_anonymous", False):
        return "$"
    return validate_string_identifier_text(getattr(string_def, "identifier", ""))


def _require_string_text(value: Any, context: str) -> str:
    if isinstance(value, str):
        return value
    msg = f"{context} must be a string for libyara output"
    raise TypeError(msg)


def validate_string_identifier_text(identifier: Any) -> str:
    """Return a normalized string identifier or reject invalid libyara output."""
    text = _require_string_text(identifier, "String identifier")
    normalized = text if text.startswith("$") else f"${text}"
    body = normalized.removeprefix("$")
    if not body or _STRING_IDENTIFIER_BODY_RE.fullmatch(body) is None:
        msg = f"Invalid string identifier '{normalized}' for libyara output"
        raise ValueError(msg)
    return normalized


def format_string_reference_identifier(identifier: Any, *, allow_placeholder: bool) -> str:
    """Return a string identifier, allowing the for-of placeholder when requested."""
    text = _require_string_text(identifier, "String identifier")
    if allow_placeholder and text in _STRING_PLACEHOLDER_REFERENCES:
        return "$"
    return validate_string_identifier_text(identifier)


def format_string_reference_suffix(identifier: Any, *, allow_placeholder: bool) -> str:
    """Return the suffix for #/@/! string references."""
    raw_text = _require_string_text(identifier, "String identifier")
    if raw_text.startswith(("#", "@", "!")):
        msg = f"Invalid string reference '{raw_text}' for libyara output"
        raise ValueError(msg)
    text = raw_text.removeprefix("$")
    if allow_placeholder and text in _STRING_PLACEHOLDER_REFERENCES:
        return ""
    return validate_string_identifier_text(text).removeprefix("$")


def validate_string_wildcard_text(pattern: Any) -> str:
    """Return a normalized string wildcard or reject invalid libyara output."""
    text = _require_string_text(pattern, "String wildcard")
    normalized = text if text.startswith("$") else f"${text}"
    body = normalized.removeprefix("$")
    if body == "*":
        return normalized
    if body.endswith("*"):
        prefix = body[:-1]
        if prefix and _STRING_IDENTIFIER_BODY_RE.fullmatch(prefix) is not None:
            return normalized
    msg = f"Invalid string wildcard '{normalized}' for libyara output"
    raise ValueError(msg)


def validate_string_set_item_text(item: Any) -> str:
    """Return a normalized string-set item or reject invalid libyara output."""
    text = _require_string_text(item, "String set item")
    if "*" in text:
        return validate_string_wildcard_text(text)
    return validate_string_identifier_text(text)


def validate_string_identifiers(strings: object) -> None:
    """Reject duplicate named string identifiers that libyara rejects."""
    if not isinstance(strings, list | tuple):
        msg = "Rule strings must be a list or tuple for libyara output"
        raise TypeError(msg)
    if not strings:
        return

    seen: set[str] = set()
    for string_def in strings:
        _validate_supported_string_definition(string_def)
        if getattr(string_def, "is_anonymous", False):
            continue
        identifier = output_string_identifier(string_def)
        validate_string_identifier_text(identifier)
        if identifier in seen:
            msg = f"Duplicate string identifier '{identifier}' for libyara output"
            raise ValueError(msg)
        seen.add(identifier)


def validate_rule_string_references(rule: object) -> None:
    """Reject condition string references that are not declared in the rule."""
    if getattr(rule, "condition", None) is None:
        rule_name = getattr(rule, "name", "<unknown>")
        msg = f"Rule '{rule_name}' must have a condition for libyara output"
        raise ValueError(msg)

    from yaraast.analysis.string_usage import StringUsageAnalyzer
    from yaraast.ast.rules import Rule

    if not isinstance(rule, Rule):
        return

    analyzer = StringUsageAnalyzer()
    try:
        analyzer.visit_rule(rule)
    except (TypeError, ValueError):
        return

    contextual_errors = _collect_contextual_expression_errors(rule.condition)
    if contextual_errors:
        raise ValueError(sorted(contextual_errors)[0])

    undefined = sorted(
        {
            string_id
            for rule_undefined in analyzer.get_undefined_strings().values()
            for string_id in rule_undefined
        }
    )
    rule_name = getattr(rule, "name", "<unknown>")
    if undefined:
        msg = (
            f"Undefined string references in rule '{rule_name}': {', '.join(undefined)} "
            "for libyara output"
        )
        raise ValueError(msg)

    if not _rule_string_definitions_are_renderable(rule.strings):
        return

    unreferenced = sorted(
        {
            string_id
            for rule_unused in analyzer.get_unused_strings().values()
            for string_id in rule_unused
        }
    )
    if unreferenced:
        msg = (
            f"Unreferenced string definitions in rule '{rule_name}': "
            f"{', '.join(unreferenced)} for libyara output"
        )
        raise ValueError(msg)

    invalid_comparisons = sorted(
        {
            string_id
            for rule_invalid in analyzer.invalid_comparison_string_references.values()
            for string_id in rule_invalid
        }
    )
    if invalid_comparisons:
        msg = (
            f"String identifiers cannot be used with comparison operators in rule "
            f"'{rule_name}': {', '.join(invalid_comparisons)} for libyara output"
        )
        raise ValueError(msg)


def _collect_contextual_expression_errors(
    value: object,
    *,
    in_string_set: bool = False,
    in_iterable: bool = False,
    in_range: bool = False,
) -> set[str]:
    if isinstance(value, StringWildcard):
        if in_string_set:
            return set()
        wildcard = validate_string_wildcard_text(value.pattern)
        return {
            "String wildcard expressions are only valid in string sets for "
            f"libyara output: {wildcard}"
        }

    if isinstance(value, SetExpression):
        errors: set[str] = set()
        if not value.elements:
            errors.add("Set expression must contain at least one element for libyara output")
        if not (in_string_set or in_iterable):
            errors.add(
                "Set expressions are only valid in string set or iterable contexts "
                "for libyara output"
            )
        errors.update(
            _collect_contextual_expression_errors(
                value.elements,
                in_string_set=in_string_set,
            )
        )
        return errors

    if isinstance(value, RangeExpression):
        if in_iterable or in_range:
            return _collect_contextual_expression_errors([value.low, value.high])
        return {
            "Range expressions are only valid in iterable or range contexts " "for libyara output"
        }

    if isinstance(value, ASTNode):
        node_errors: set[str] = set()
        for field in fields(value):
            if field.name in ASTNode._METADATA_FIELDS:
                continue
            child = getattr(value, field.name)
            child_in_string_set = in_string_set or (
                isinstance(value, OfExpression | ForOfExpression) and field.name == "string_set"
            )
            child_in_iterable = in_iterable or (
                isinstance(value, ForExpression) and field.name == "iterable"
            )
            child_in_range = in_range or (isinstance(value, InExpression) and field.name == "range")
            if not isinstance(value, ParenthesesExpression):
                child_in_iterable = child_in_iterable and field.name == "iterable"
                child_in_range = child_in_range and field.name == "range"
            node_errors.update(
                _collect_contextual_expression_errors(
                    child,
                    in_string_set=child_in_string_set,
                    in_iterable=child_in_iterable,
                    in_range=child_in_range,
                )
            )
        return node_errors

    if isinstance(value, dict):
        dict_errors: set[str] = set()
        for item in value.values():
            dict_errors.update(
                _collect_contextual_expression_errors(
                    item,
                    in_string_set=in_string_set,
                    in_iterable=in_iterable,
                    in_range=in_range,
                )
            )
        return dict_errors

    if isinstance(value, list | tuple | set | frozenset):
        sequence_errors: set[str] = set()
        for item in value:
            sequence_errors.update(
                _collect_contextual_expression_errors(
                    item,
                    in_string_set=in_string_set,
                    in_iterable=in_iterable,
                    in_range=in_range,
                )
            )
        return sequence_errors

    return set()


def _rule_string_definitions_are_renderable(strings: object) -> bool:
    if not isinstance(strings, list | tuple):
        return False
    try:
        for string_def in strings:
            _validate_renderable_string_definition(string_def)
    except (TypeError, ValueError, AttributeError):
        return False
    return True


def _validate_renderable_string_definition(string_def: object) -> None:
    if isinstance(string_def, PlainString):
        output_string_identifier(string_def)
        validate_plain_string_modifiers(string_def.modifiers)
        escape_plain_string_value(plain_string_render_source(string_def))
        return
    if isinstance(string_def, HexString):
        output_string_identifier(string_def)
        validate_hex_string_modifiers(string_def.modifiers)
        validate_hex_string_tokens(string_def.tokens)
        for token in string_def.tokens:
            _validate_renderable_hex_token(token)
        return
    if isinstance(string_def, RegexString):
        output_string_identifier(string_def)
        validate_regex_string_modifiers(string_def.modifiers)
        escape_regex_delimiter(string_def.regex)
        format_regex_modifiers(string_def.modifiers)
        return
    _validate_supported_string_definition(string_def)


def _validate_renderable_hex_token(token: object) -> None:
    if isinstance(token, HexByte):
        format_hex_byte_value(token.value, uppercase=True)
        return
    if isinstance(token, HexNegatedByte):
        format_hex_negated_value(token.value, uppercase=True)
        return
    if isinstance(token, HexNibble):
        format_hex_nibble_value(token.value, uppercase=True)
        return
    if isinstance(token, HexJump):
        format_hex_jump_bounds(token.min_jump, token.max_jump)
        return
    if isinstance(token, HexWildcard):
        return
    if isinstance(token, HexAlternative):
        validate_hex_alternative_token(token)
        for alternative in token.alternatives:
            branch = alternative if isinstance(alternative, list) else [alternative]
            for branch_token in branch:
                _validate_renderable_hex_token(branch_token)
        return
    msg = f"Unsupported hex token '{type(token).__name__}' for libyara output"
    raise TypeError(msg)


def _validate_supported_string_definition(string_def: object) -> None:
    if isinstance(string_def, PlainString | HexString | RegexString):
        return
    msg = f"Unsupported string definition '{type(string_def).__name__}' for libyara output"
    raise TypeError(msg)


def format_integer_literal(value: object) -> str:
    """Format integer literals with common hex values preserved."""
    if isinstance(value, bool):
        msg = "Integer literal value must be an integer"
        raise TypeError(msg)
    if isinstance(value, str):
        int_value = _parse_integer_literal_text(value)
        if int_value is None:
            msg = "Integer literal value must be an integer"
            raise TypeError(msg)
        _validate_integer_literal_range(_integer_literal_numeric_value(value))
        if isinstance(int_value, str):
            return _normalize_integer_literal_text(int_value)
    elif isinstance(value, int):
        int_value = value
    else:
        msg = "Integer literal value must be an integer"
        raise TypeError(msg)

    _validate_integer_literal_range(int_value)

    hex_values = {
        0x4D5A: "0x4D5A",
        0x5A4D: "0x5A4D",
        0x00004550: "0x00004550",
        0x50450000: "0x50450000",
        0x14C: "0x14c",
        0x3C: "0x3c",
        1024: "0x400",
    }

    if int_value in hex_values:
        return hex_values[int_value]

    if int_value >= 256 and (int_value % 256 == 0 or int_value % 16 == 0):
        return hex(int_value)

    return str(int_value)


def _parse_integer_literal_text(value: str) -> int | str | None:
    if _YARA_INTEGER_TEXT_RE.fullmatch(value) is not None:
        return value
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return int(value, 0)
    except ValueError:
        return None


def _integer_literal_numeric_value(value: str) -> int:
    text = value.strip()
    multiplier = 1
    upper_text = text.upper()
    if upper_text.endswith("KB"):
        multiplier = 1024
        text = text[:-2]
    elif upper_text.endswith("MB"):
        multiplier = 1024 * 1024
        text = text[:-2]

    unsigned = text.lstrip("+-")
    base = 0 if unsigned.lower().startswith(("0x", "0o")) else 10
    return int(text, base) * multiplier


def _normalize_integer_literal_text(value: str) -> str:
    text = value.strip()
    sign = ""
    if text.startswith(("+", "-")):
        if text.startswith("-"):
            sign = "-"
        text = text[1:]

    if text.lower().startswith("0x"):
        return f"{sign}0x{text[2:]}"
    if text.lower().startswith("0o"):
        return f"{sign}0o{text[2:]}"
    return f"{sign}{text}"


def _validate_integer_literal_range(value: int) -> None:
    if _YARA_INTEGER_MIN <= value <= _YARA_INTEGER_MAX:
        return
    msg = "Integer literal value is outside libyara range"
    raise ValueError(msg)


def format_double_literal(value: int | float) -> str:
    """Format a validated numeric double literal."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        msg = "Double literal value must be numeric"
        raise TypeError(msg)
    if not math.isfinite(value):
        msg = "Double literal value must be finite"
        raise ValueError(msg)
    if isinstance(value, int):
        return str(value)
    text = format(Decimal.from_float(value), "f")
    if "." in text:
        return text
    return f"{text}.0"


def format_hex_byte_value(value: int | str, *, uppercase: bool, context: str = "HexByte") -> str:
    """Format a validated hex byte value."""
    value = _validate_hex_byte_value(value, context)
    if isinstance(value, str):
        return value.upper() if uppercase else value.lower()
    return f"{value:02X}" if uppercase else f"{value:02x}"


def format_hex_negated_value(value: int | str, *, uppercase: bool) -> str:
    """Format a negated byte or nibble value."""
    value = _validate_hex_negated_value(value)
    if isinstance(value, str):
        return value.upper() if uppercase else value.lower()
    return f"{value:02X}" if uppercase else f"{value:02x}"


def format_hex_nibble_value(value: int | str, *, uppercase: bool) -> str:
    """Format a validated hex nibble value."""
    value = _validate_hex_nibble_value(value)
    if isinstance(value, str):
        return value.upper() if uppercase else value.lower()
    return f"{value:X}" if uppercase else f"{value:x}"


def format_hex_jump_bounds(min_jump: int | None, max_jump: int | None) -> str:
    """Format validated hex jump bounds."""
    min_jump = _validate_hex_jump_bound(min_jump, "min_jump")
    max_jump = _validate_hex_jump_bound(max_jump, "max_jump")

    if min_jump is not None and max_jump is not None and min_jump > max_jump:
        msg = "HexJump min_jump cannot exceed max_jump"
        raise TypeError(msg)
    if min_jump is None and max_jump is None:
        return "[-]"
    if min_jump == max_jump:
        if min_jump == 0:
            return "[0-0]"
        return f"[{min_jump}]"
    if min_jump is None:
        return f"[0-{max_jump}]"
    if max_jump is None:
        return f"[{min_jump}-]"
    return f"[{min_jump}-{max_jump}]"


def validate_hex_string_tokens(tokens: Any) -> None:
    """Reject hex token sequences that libyara cannot parse."""
    if not isinstance(tokens, list | tuple) or not tokens:
        msg = "Hex string must contain at least one token for libyara output"
        raise ValueError(msg)
    _validate_hex_token_sequence(tokens, context="hex string", inside_alternative=False)


def validate_hex_alternative_token(token: HexAlternative) -> None:
    """Reject hex alternatives that libyara cannot parse."""
    _validate_hex_alternative(token)


def _validate_hex_alternative(token: HexAlternative) -> None:
    alternatives = token.alternatives
    if not isinstance(alternatives, list | tuple) or not alternatives:
        msg = "HexAlternative must contain at least one branch for libyara output"
        raise ValueError(msg)

    for alternative in alternatives:
        branch = alternative if isinstance(alternative, list) else [alternative]
        if not branch:
            msg = "HexAlternative branches must not be empty for libyara output"
            raise ValueError(msg)
        _validate_hex_token_sequence(
            branch,
            context="hex alternative branch",
            inside_alternative=True,
        )


def _validate_hex_token_sequence(
    tokens: list[Any] | tuple[Any, ...],
    *,
    context: str,
    inside_alternative: bool,
) -> None:
    for token in tokens:
        if inside_alternative and isinstance(token, int | str):
            _validate_hex_byte_value(token, "HexByte")
        elif isinstance(token, HexJump):
            format_hex_jump_bounds(token.min_jump, token.max_jump)
        elif isinstance(token, HexAlternative):
            _validate_hex_alternative(token)
        elif not isinstance(token, HexByte | HexNegatedByte | HexNibble | HexWildcard):
            msg = f"Unsupported hex token '{type(token).__name__}' for libyara output"
            raise TypeError(msg)

    if isinstance(tokens[0], HexJump) or isinstance(tokens[-1], HexJump):
        msg = f"HexJump cannot appear at the beginning or end of {context} for libyara output"
        raise ValueError(msg)

    if not inside_alternative:
        return

    for token in tokens:
        if isinstance(token, HexJump) and token.max_jump is None:
            msg = "Unbounded HexJump is not allowed inside hex alternatives for libyara output"
            raise ValueError(msg)


def _validate_hex_byte_value(value: int | str, context: str) -> int | str:
    if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 0xFF:
        return value
    if isinstance(value, str) and len(value) == 2 and all(char in _HEX_CHARS for char in value):
        return value
    msg = f"{context} value must be a byte"
    raise TypeError(msg)


def _validate_hex_negated_value(value: int | str) -> int | str:
    if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 0xFF:
        return value
    if isinstance(value, str):
        if len(value) == 2 and all(char in _HEX_CHARS for char in value):
            return value
        if _is_negated_nibble_pattern(value):
            return value
    msg = "HexNegatedByte value must be a byte or negated nibble"
    raise TypeError(msg)


def _is_negated_nibble_pattern(value: str) -> bool:
    if len(value) != 2:
        return False
    first = value[0]
    second = value[1]
    return (first == "?" and second in _HEX_CHARS) or (first in _HEX_CHARS and second == "?")


def _validate_hex_nibble_value(value: int | str) -> int | str:
    if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 0xF:
        return value
    if isinstance(value, str) and len(value) == 1 and value in _HEX_CHARS:
        return value
    msg = "HexNibble value must be a nibble"
    raise TypeError(msg)


def _validate_hex_jump_bound(value: int | None, field: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, int) and not isinstance(value, bool):
        if value < 0:
            msg = f"HexJump {field} must be a non-negative integer"
            raise TypeError(msg)
        if value > LIBYARA_HEX_JUMP_MAX:
            msg = f"HexJump {field} must not exceed {LIBYARA_HEX_JUMP_MAX}"
            raise ValueError(msg)
        return value
    msg = f"HexJump {field} must be a non-negative integer"
    raise TypeError(msg)


def format_modifier(modifier: Any, visit: Callable[[Any], str] | None = None) -> str:
    """Format one string modifier for YARA output."""
    if visit is not None and isinstance(modifier, StringModifier):
        return visit(modifier)

    if isinstance(modifier, StringModifier):
        name = modifier.name
        value = modifier.value
        _validate_spaced_string_modifier(name)
        _validate_string_modifier_value(name, value)
        if value is not None:
            if name == "xor":
                return f"{name}({_format_xor_modifier_value(value)})"
            if name in BASE64_MODIFIERS:
                return _format_base64_modifier_value(name, value)
            if isinstance(value, tuple):
                return f"{name}({value[0]}-{value[1]})"
            if isinstance(value, str):
                return f'{name}("{escape_plain_string_value(value)}")'
            return f"{name}({value})"
        return str(name)

    if not isinstance(modifier, str):
        msg = "String modifiers must contain strings or StringModifier nodes for libyara output"
        raise TypeError(msg)
    text = modifier
    _validate_spaced_string_modifier(text)
    return text


def _format_base64_modifier_value(name: str, value: object) -> str:
    if not isinstance(value, str):
        msg = f"{name} value must be a string"
        raise TypeError(msg)
    try:
        encoded_value = value.encode("ascii")
    except UnicodeEncodeError:
        encoded_value = b""
    if len(encoded_value) != 64:
        msg = f"{name} alphabet must be 64 bytes"
        raise TypeError(msg)
    return f'{name}("{escape_plain_string_value(value)}")'


def _validate_spaced_string_modifier(name: str) -> None:
    if name in _UNSUPPORTED_SPACED_STRING_MODIFIERS or name not in _KNOWN_STRING_MODIFIERS:
        msg = f"Unsupported string modifier for libyara output: {name}"
        raise ValueError(msg)


def _validate_string_modifier_value(name: str, value: object) -> None:
    if value is None or name in _PARAMETERIZED_STRING_MODIFIERS:
        return
    msg = f"String modifier '{name}' does not accept a value for libyara output"
    raise ValueError(msg)


def _format_xor_modifier_value(value: object) -> str:
    if isinstance(value, tuple | list) and len(value) == 2:
        low = _parse_xor_key(value[0])
        high = _parse_xor_key(value[1])
        if low is None or high is None:
            msg = "xor range value must contain byte bounds"
            raise TypeError(msg)
        if low.key > high.key:
            msg = "xor range value must be ascending"
            raise TypeError(msg)
        return f"{low.text}-{high.text}"

    if isinstance(value, str) and "-" in value:
        low_text, high_text = value.split("-", maxsplit=1)
        low = _parse_xor_key(low_text)
        high = _parse_xor_key(high_text)
        if low is None or high is None:
            msg = "xor range value must contain byte bounds"
            raise TypeError(msg)
        if low.key > high.key:
            msg = "xor range value must be ascending"
            raise TypeError(msg)
        return f"{low.text}-{high.text}"

    key = _parse_xor_key(value)
    if key is None:
        msg = "xor value must be a byte"
        raise TypeError(msg)
    return key.text


def _parse_xor_key(value: object) -> _XorKey | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        if 0 <= value <= 0xFF:
            return _XorKey(value, str(value))
        return None
    if isinstance(value, str):
        text = value.strip()
        key = parse_xor_key_text(text)
        if key is None:
            return None
        if 0 <= key <= 0xFF:
            return _XorKey(key, text)
    return None


def format_modifiers(
    modifiers: object,
    visit: Callable[[Any], str] | None = None,
) -> str:
    """Format modifiers into a string with leading spaces."""
    _validate_string_modifier_collection(modifiers)
    if not modifiers:
        return ""
    if not isinstance(modifiers, list | tuple):
        return ""
    validate_duplicate_string_modifiers(modifiers)
    parts = []
    for mod in modifiers:
        parts.append(format_modifier(mod, visit))
    return "".join(f" {part}" for part in parts)


def validate_plain_string_modifiers(modifiers: object) -> None:
    """Reject plain string modifier combinations that libyara rejects."""
    _validate_string_modifier_collection(modifiers)
    validate_string_modifier_values(modifiers)
    validate_duplicate_string_modifiers(modifiers)
    names = _modifier_names(modifiers)
    for base64_name in sorted(names & BASE64_MODIFIERS):
        for incompatible_name in sorted(names & _BASE64_INCOMPATIBLE_MODIFIERS):
            msg = (
                f"String modifier '{incompatible_name}' cannot be combined with "
                f"'{base64_name}' for libyara output"
            )
            raise ValueError(msg)

    if "xor" not in names:
        return

    for incompatible_name in sorted(names & _XOR_INCOMPATIBLE_MODIFIERS):
        msg = (
            f"String modifier '{incompatible_name}' cannot be combined with "
            "'xor' for libyara output"
        )
        raise ValueError(msg)


def validate_hex_string_modifiers(modifiers: object) -> None:
    """Reject hex string modifiers that libyara rejects."""
    _validate_string_modifier_collection(modifiers)
    validate_string_modifier_values(modifiers)
    validate_duplicate_string_modifiers(modifiers)
    for name in sorted(_modifier_names(modifiers)):
        if name in _HEX_ALLOWED_MODIFIERS:
            continue
        msg = f"String modifier '{name}' is not valid on hex strings for libyara output"
        raise ValueError(msg)


def validate_regex_string_modifiers(modifiers: object) -> None:
    """Reject regex string modifiers that libyara rejects."""
    _validate_string_modifier_collection(modifiers)
    validate_string_modifier_values(modifiers)
    validate_duplicate_string_modifiers(modifiers)
    for name in sorted(_modifier_names(modifiers)):
        if name not in _REGEX_DISALLOWED_MODIFIERS:
            continue
        msg = f"String modifier '{name}' is not valid on regex strings for libyara output"
        raise ValueError(msg)


def _modifier_names(modifiers: object) -> set[str]:
    if not isinstance(modifiers, list | tuple):
        return set()
    return {_regex_modifier_name(modifier) for modifier in modifiers}


def _validate_string_modifier_collection(modifiers: object) -> None:
    if modifiers is None:
        return
    if isinstance(modifiers, list | tuple):
        return
    msg = "String modifiers must be a list or tuple for libyara output"
    raise TypeError(msg)


def validate_duplicate_string_modifiers(modifiers: object) -> None:
    """Reject duplicate string modifiers that libyara rejects."""
    if not isinstance(modifiers, list | tuple):
        return

    seen: set[str] = set()
    for modifier in modifiers:
        if isinstance(modifier, str) and len(modifier) == 1 and modifier in VALID_REGEX_MODIFIERS:
            continue
        name = _regex_modifier_name(modifier)
        if name in seen:
            msg = f"Duplicate string modifier '{name}' for libyara output"
            raise ValueError(msg)
        seen.add(name)


def validate_string_modifier_values(modifiers: object) -> None:
    """Reject parameter values on modifiers that libyara treats as flags."""
    if not isinstance(modifiers, list | tuple):
        return
    for modifier in modifiers:
        if not isinstance(modifier, StringModifier):
            continue
        _validate_string_modifier_value(modifier.name, modifier.value)


def split_regex_modifiers(
    modifiers: object,
    visit: Callable[[Any], str] | None = None,
) -> tuple[str, list[str]]:
    """Split regex inline flags from spaced string modifiers."""
    _validate_string_modifier_collection(modifiers)
    if not modifiers:
        return "", []
    if not isinstance(modifiers, list | tuple):
        return "", []

    suffix_parts: list[str] = []
    spaced_parts: list[str] = []
    for mod in modifiers:
        name = _regex_modifier_name(mod)
        if name in _UNSUPPORTED_REGEX_MODIFIERS:
            msg = f"Unsupported regex modifier: {name}"
            raise ValueError(msg)
        if isinstance(mod, str) and len(mod) == 1:
            validate_regex_modifiers(mod)
            suffix_parts.append(mod)
        elif name in REGEX_SUFFIX_NAMES:
            suffix_parts.append(REGEX_SUFFIX_NAMES[name])
        else:
            spaced_parts.append(format_modifier(mod, visit))

    suffix = _canonical_regex_suffix(suffix_parts)
    validate_regex_modifiers(suffix)
    return suffix, spaced_parts


def _canonical_regex_suffix(suffix_parts: list[str]) -> str:
    seen: set[str] = set()
    for modifier in suffix_parts:
        if modifier in seen:
            msg = f"Duplicate regex modifier: {modifier}"
            raise ValueError(msg)
        seen.add(modifier)
    return "".join(modifier for modifier in REGEX_MODIFIER_ORDER if modifier in seen)


def _regex_modifier_name(modifier: object) -> str:
    if isinstance(modifier, str):
        return modifier
    if isinstance(modifier, StringModifier):
        return modifier.name
    msg = "String modifiers must contain strings or StringModifier nodes for libyara output"
    raise TypeError(msg)


def format_regex_modifiers(
    modifiers: object,
    visit: Callable[[Any], str] | None = None,
) -> str:
    """Format regex modifiers, keeping inline regex flags adjacent to the literal."""
    validate_regex_string_modifiers(modifiers)
    suffix, spaced_parts = split_regex_modifiers(modifiers, visit)
    spaced = "".join(f" {part}" for part in spaced_parts)
    return f"{suffix}{spaced}"
