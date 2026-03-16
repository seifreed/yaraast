"""Helpers for pretty printer formatting."""

from __future__ import annotations

from yaraast.ast.strings import HexString, PlainString, RegexString


def build_hex_pattern(node: HexString, *, hex_uppercase: bool, hex_spacing: bool) -> str:
    hex_parts: list[str] = []
    for token in node.tokens:
        if hasattr(token, "value"):  # HexByte
            if isinstance(token.value, str):
                hex_val = token.value.upper() if hex_uppercase else token.value.lower()
            else:
                hex_val = f"{token.value:02X}" if hex_uppercase else f"{token.value:02x}"
            hex_parts.append(hex_val)
        elif hasattr(token, "min_jump"):  # HexJump
            if token.min_jump == token.max_jump:
                hex_parts.append(f"[{token.min_jump}]")
            else:
                hex_parts.append(f"[{token.min_jump}-{token.max_jump}]")
        else:
            hex_parts.append("??")

    return " ".join(hex_parts) if hex_spacing else "".join(hex_parts)


def format_plain_string(node: PlainString, quote: str, padding: int) -> str:
    if padding > 0:
        return f"{node.identifier}{' ' * padding} = {quote}{node.value}{quote}"
    return f"{node.identifier} = {quote}{node.value}{quote}"


def format_regex_string(node: RegexString, padding: int) -> str:
    if padding > 0:
        return f"{node.identifier}{' ' * padding} = /{node.regex}/"
    return f"{node.identifier} = /{node.regex}/"


def modifiers_to_string(modifiers) -> str:
    if not modifiers:
        return ""
    return " " + " ".join(mod.name for mod in modifiers)


def calculate_string_alignment_column(ast) -> int:
    """Calculate alignment column for string identifiers."""
    max_length = 0
    for rule in ast.rules:
        for string_def in rule.strings:
            max_length = max(max_length, len(string_def.identifier))
    return max_length + 1


def calculate_meta_alignment_column(ast, min_alignment_column: int) -> int:
    """Calculate alignment column for meta values."""
    max_length = 0
    for rule in ast.rules:
        if isinstance(rule.meta, dict):
            for key in rule.meta:
                max_length = max(max_length, len(f"{key} ="))
    return max(max_length + 2, min_alignment_column)


def expression_to_string(expr) -> str:
    """Render an expression with CodeGenerator."""
    from yaraast.codegen.generator import CodeGenerator

    generator = CodeGenerator()
    return generator.visit(expr).strip()
