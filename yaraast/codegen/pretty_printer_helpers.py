"""Helpers for pretty printer formatting."""

from __future__ import annotations

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
from yaraast.codegen.generator_helpers import (
    escape_plain_string_value,
    escape_regex_delimiter,
    format_modifier,
    format_regex_modifiers,
    output_string_identifier,
)


def build_hex_pattern(node: HexString, *, hex_uppercase: bool, hex_spacing: bool) -> str:
    hex_parts = [_format_hex_token(token, hex_uppercase, hex_spacing) for token in node.tokens]
    return " ".join(hex_parts) if hex_spacing else "".join(hex_parts)


def _format_hex_token(token, hex_uppercase: bool, hex_spacing: bool) -> str:
    if isinstance(token, HexByte):
        return _format_hex_byte_value(token.value, hex_uppercase)
    if isinstance(token, HexWildcard):
        return "??"
    if isinstance(token, HexJump):
        return _format_hex_jump(token)
    if isinstance(token, HexNegatedByte):
        return f"~{_format_hex_byte_value(token.value, hex_uppercase)}"
    if isinstance(token, HexNibble):
        value = _format_hex_nibble_value(token.value, hex_uppercase)
        return f"{value}?" if token.high else f"?{value}"
    if isinstance(token, HexAlternative):
        separator = " " if hex_spacing else ""
        alt_separator = " | " if hex_spacing else "|"
        alternatives = [
            separator.join(
                _format_hex_token(nested_token, hex_uppercase, hex_spacing)
                for nested_token in _coerce_hex_alternative_branch(alternative)
            )
            for alternative in token.alternatives
        ]
        return f"({alt_separator.join(alternatives)})"
    return "??"


def _format_hex_byte_value(value: int | str, hex_uppercase: bool) -> str:
    if isinstance(value, str):
        return value.upper() if hex_uppercase else value.lower()
    return f"{value:02X}" if hex_uppercase else f"{value:02x}"


def _format_hex_nibble_value(value: int | str, hex_uppercase: bool) -> str:
    if isinstance(value, str):
        return value.upper() if hex_uppercase else value.lower()
    return f"{value:X}" if hex_uppercase else f"{value:x}"


def _format_hex_jump(token: HexJump) -> str:
    lo = token.min_jump if token.min_jump is not None else ""
    hi = token.max_jump if token.max_jump is not None else ""
    if lo == hi and lo != "":
        return f"[{lo}]"
    return f"[{lo}-{hi}]"


def _coerce_hex_alternative_branch(alternative) -> list:
    if isinstance(alternative, list):
        return alternative
    return [HexByte(alternative)]


def format_plain_string(node: PlainString, quote: str, padding: int) -> str:
    escaped_value = escape_plain_string_value(node.value)
    identifier = output_string_identifier(node)
    if padding > 0:
        return f"{identifier}{' ' * padding} = {quote}{escaped_value}{quote}"
    return f"{identifier} = {quote}{escaped_value}{quote}"


def format_regex_string(node: RegexString, padding: int) -> str:
    escaped = escape_regex_delimiter(node.regex)
    identifier = output_string_identifier(node)
    if padding > 0:
        return f"{identifier}{' ' * padding} = /{escaped}/"
    return f"{identifier} = /{escaped}/"


def modifiers_to_string(modifiers) -> str:
    if not modifiers:
        return ""
    return "".join(f" {format_modifier(mod)}" for mod in modifiers)


def regex_modifiers_to_string(modifiers) -> str:
    if not modifiers:
        return ""
    return format_regex_modifiers(modifiers)


def calculate_string_alignment_column(ast) -> int:
    """Calculate alignment column for string identifiers."""
    max_length = 0
    for rule in ast.rules:
        for string_def in rule.strings:
            max_length = max(max_length, len(output_string_identifier(string_def)))
    return max_length + 1


def calculate_meta_alignment_column(ast, min_alignment_column: int) -> int:
    """Calculate alignment column for meta values."""
    max_length = 0
    for rule in ast.rules:
        for entry in rule.meta:
            if hasattr(entry, "key"):
                max_length = max(max_length, len(f"{entry.key} ="))
    return max(max_length + 2, min_alignment_column)


def expression_to_string(expr) -> str:
    """Render an expression with the comment-aware generator."""
    from yaraast.codegen.comment_aware_generator import CommentAwareCodeGenerator

    generator = CommentAwareCodeGenerator()
    return generator.visit(expr).strip()
