"""Expression rendering helpers for the main code generator."""

from __future__ import annotations

import re

from yaraast.codegen.generator_formatting import validate_yara_identifier
from yaraast.codegen.generator_helpers import (
    validate_string_identifier_text,
    validate_string_set_item_text,
)

_INTEGER_QUANTIFIER_RE = re.compile(r"^-?\d+$")
_PERCENTAGE_QUANTIFIER_RE = re.compile(r"^(\d+)%$")
_QUANTIFIER_PERCENT_MIN = 1
_QUANTIFIER_PERCENT_MAX = 100


def _render_string_set(gen, string_set) -> str:
    from yaraast.ast.expressions import (
        Identifier,
        ParenthesesExpression,
        SetExpression,
        StringIdentifier,
        StringLiteral,
        StringWildcard,
    )

    if isinstance(string_set, StringLiteral):
        return _render_single_string_set_text(string_set.value)
    if isinstance(string_set, StringIdentifier):
        return f"({gen.visit(string_set)})"
    if isinstance(string_set, StringWildcard):
        return f"({gen.visit(string_set)})"
    if isinstance(string_set, Identifier):
        return _render_single_string_set_text(string_set.name)
    if isinstance(string_set, ParenthesesExpression):
        return _render_string_set(gen, string_set.expression)
    if isinstance(string_set, SetExpression):
        rendered_items = [_render_string_set_item(gen, item) for item in string_set.elements]
        return f"({', '.join(rendered_items)})"
    if hasattr(string_set, "accept"):
        return gen.visit(string_set)
    if isinstance(string_set, list | tuple):
        rendered_items = [_render_string_set_item(gen, item) for item in string_set]
        return f"({', '.join(rendered_items)})"
    if isinstance(string_set, set | frozenset):
        rendered_items = [
            _render_string_set_item(gen, item) for item in sorted(string_set, key=str)
        ]
        return f"({', '.join(rendered_items)})"
    return _render_single_string_set_text(string_set)


def _render_single_string_set_text(string_set: object) -> str:
    text = str(string_set)
    if text == "them":
        return text
    return f"({validate_string_set_item_text(text)})"


def _render_string_set_item(gen, item) -> str:
    from yaraast.ast.expressions import StringLiteral

    if isinstance(item, StringLiteral):
        return validate_string_set_item_text(item.value)
    if hasattr(item, "accept"):
        return gen.visit(item)
    return validate_string_set_item_text(item)


def _render_quantifier(gen, quantifier, *, allow_percentage: bool = False) -> str:
    from yaraast.ast.expressions import (
        BooleanLiteral,
        DoubleLiteral,
        Identifier,
        IntegerLiteral,
        StringLiteral,
    )

    if isinstance(quantifier, bool):
        msg = f"Invalid quantifier '{quantifier}' for libyara output"
        raise ValueError(msg)
    if isinstance(quantifier, int):
        if quantifier < 0:
            msg = f"Invalid quantifier '{quantifier}' for libyara output"
            raise ValueError(msg)
        return str(quantifier)
    if isinstance(quantifier, str):
        return _validate_quantifier_text(quantifier, allow_percentage=allow_percentage)
    if isinstance(quantifier, float) and allow_percentage:
        return _format_fractional_percentage_quantifier(quantifier)
    if isinstance(quantifier, IntegerLiteral):
        return _validate_quantifier_text(str(quantifier.value), allow_percentage=allow_percentage)
    if isinstance(quantifier, BooleanLiteral):
        msg = f"Invalid quantifier '{gen.visit(quantifier)}' for libyara output"
        raise ValueError(msg)
    if isinstance(quantifier, StringLiteral):
        return _validate_quantifier_text(quantifier.value, allow_percentage=allow_percentage)
    if isinstance(quantifier, DoubleLiteral) and allow_percentage:
        return _format_fractional_percentage_quantifier(quantifier.value)
    if isinstance(quantifier, Identifier):
        return _validate_quantifier_text(quantifier.name, allow_percentage=allow_percentage)
    return gen.visit(quantifier)


def _validate_quantifier_text(text: str, *, allow_percentage: bool) -> str:
    if text in {"all", "any", "none"}:
        return text

    integer = _INTEGER_QUANTIFIER_RE.fullmatch(text)
    if integer is not None:
        if int(text) < 0:
            msg = f"Invalid quantifier '{text}' for libyara output"
            raise ValueError(msg)
        return text

    percentage = _PERCENTAGE_QUANTIFIER_RE.fullmatch(text)
    if percentage is not None:
        if not allow_percentage:
            msg = f"Invalid quantifier '{text}' for libyara output"
            raise ValueError(msg)
        _validate_percentage_quantifier(int(percentage.group(1)), text)
        return text

    return validate_yara_identifier(text, "quantifier")


def _format_fractional_percentage_quantifier(value: float) -> str:
    percent = round(value * 100)
    _validate_percentage_quantifier(percent, value)
    return f"{percent}%"


def _validate_percentage_quantifier(percent: int, raw_value: object) -> None:
    if _QUANTIFIER_PERCENT_MIN <= percent <= _QUANTIFIER_PERCENT_MAX:
        return
    msg = f"Invalid quantifier '{raw_value}' for libyara output"
    raise ValueError(msg)


def render_for_of_expression(gen, node) -> str:
    """Render a for-of expression."""
    quantifier = _render_quantifier(gen, node.quantifier, allow_percentage=True)
    string_set = _render_string_set(gen, node.string_set)
    if node.condition:
        previous = getattr(gen, "_allow_string_placeholder", False)
        gen._allow_string_placeholder = True
        try:
            condition = gen.visit(node.condition)
        finally:
            gen._allow_string_placeholder = previous
        return f"for {quantifier} of {string_set} : ({condition})"
    return f"{quantifier} of {string_set}"


def render_in_expression(gen, node) -> str:
    """Render an in-expression with parenthesis normalization."""
    from yaraast.ast.expressions import (
        ParenthesesExpression,
        RangeExpression,
        StringCount,
        StringLength,
        StringOffset,
    )

    subject = (
        validate_string_identifier_text(node.subject)
        if isinstance(node.subject, str)
        else gen.visit(node.subject)
    )

    if isinstance(node.range, RangeExpression):
        range_expr = gen.visit(node.range)
        return f"{subject} in ({range_expr})"

    if isinstance(node.range, ParenthesesExpression):
        inner = node.range.expression
        if isinstance(inner, RangeExpression):
            range_expr = gen.visit(inner)
            return f"{subject} in ({range_expr})"
        if isinstance(inner, StringOffset | StringCount | StringLength):
            range_expr = gen.visit(inner)
            return f"{subject} in {range_expr}"
        range_expr = gen.visit(node.range)
        return f"{subject} in {range_expr}"
    range_expr = gen.visit(node.range)
    return f"{subject} in {range_expr}"


def render_of_expression(gen, node) -> str:
    """Render an of-expression."""
    quantifier = _render_quantifier(gen, node.quantifier, allow_percentage=True)
    string_set = _render_string_set(gen, node.string_set)
    return f"{quantifier} of {string_set}"
