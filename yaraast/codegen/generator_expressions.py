"""Expression rendering helpers for the main code generator."""

from __future__ import annotations

import re
from typing import Any, cast

from yaraast.codegen.generator_formatting import validate_yara_identifier
from yaraast.codegen.generator_helpers import (
    format_string_reference_identifier,
    validate_string_set_item_text,
)

_INTEGER_QUANTIFIER_RE = re.compile(r"^-?\d+$")
_PERCENTAGE_QUANTIFIER_RE = re.compile(r"^(\d+)%$")
_QUANTIFIER_PERCENT_MIN = 1
_QUANTIFIER_PERCENT_MAX = 100


def _render_string_set(gen: Any, string_set: Any) -> str:
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
        if not string_set.pattern.startswith("$"):
            return f"({_render_rule_wildcard(string_set.pattern)})"
        return f"({gen.visit(string_set)})"
    if isinstance(string_set, Identifier):
        if string_set.name != "them" and not string_set.name.startswith("$"):
            return f"({_render_rule_identifier(string_set.name)})"
        return _render_single_string_set_text(string_set.name)
    if isinstance(string_set, ParenthesesExpression):
        return _render_string_set(gen, string_set.expression)
    if isinstance(string_set, SetExpression):
        if _is_rule_set_items(string_set.elements):
            rendered_items = [_render_rule_set_item(item) for item in string_set.elements]
            return f"({', '.join(rendered_items)})"
        if _has_mixed_rule_and_string_set_items(string_set.elements):
            msg = "Mixed string and rule set items are not valid for libyara output"
            raise ValueError(msg)
        rendered_items = [_render_string_set_item(gen, item) for item in string_set.elements]
        return f"({', '.join(rendered_items)})"
    if hasattr(string_set, "accept"):
        return cast(str, gen.visit(string_set))
    if isinstance(string_set, list | tuple):
        rendered_items = [_render_string_set_item(gen, item) for item in string_set]
        return f"({', '.join(rendered_items)})"
    if isinstance(string_set, set | frozenset):
        rendered_items = [
            _render_string_set_item(gen, item) for item in sorted(string_set, key=str)
        ]
        return f"({', '.join(rendered_items)})"
    return _render_single_string_set_text(string_set)


def _is_rule_set_items(items: list[Any] | tuple[Any, ...]) -> bool:
    return bool(items) and all(_is_rule_set_item(item) for item in items)


def _has_mixed_rule_and_string_set_items(items: list[Any] | tuple[Any, ...]) -> bool:
    has_rule_item = any(_is_rule_set_item(item) for item in items)
    has_string_item = any(_is_string_set_item(item) for item in items)
    return has_rule_item and has_string_item


def _is_rule_set_item(item: Any) -> bool:
    from yaraast.ast.expressions import Identifier, StringWildcard

    if isinstance(item, Identifier):
        return item.name != "them" and not item.name.startswith("$")
    return isinstance(item, StringWildcard) and not item.pattern.startswith("$")


def _is_string_set_item(item: Any) -> bool:
    from yaraast.ast.expressions import Identifier, StringIdentifier, StringLiteral, StringWildcard

    if isinstance(item, Identifier):
        return item.name == "them" or item.name.startswith("$")
    if isinstance(item, StringIdentifier):
        return True
    if isinstance(item, StringWildcard):
        return item.pattern.startswith("$")
    if isinstance(item, StringLiteral):
        return item.value == "them" or item.value.startswith("$")
    return bool(isinstance(item, str))


def _render_rule_set_item(item: Any) -> str:
    from yaraast.ast.expressions import Identifier, StringWildcard

    if isinstance(item, Identifier):
        return _render_rule_identifier(item.name)
    if isinstance(item, StringWildcard):
        return _render_rule_wildcard(item.pattern)
    msg = f"Unsupported rule set item '{type(item).__name__}' for libyara output"
    raise ValueError(msg)


def _render_rule_identifier(name: object) -> str:
    text = str(name)
    try:
        return validate_yara_identifier(text, "rule")
    except ValueError as exc:
        msg = f"Invalid string or rule set identifier '{text}' for libyara output"
        raise ValueError(msg) from exc


def _render_rule_wildcard(pattern: object) -> str:
    text = str(pattern)
    if text.startswith("$") or not text.endswith("*") or text == "*":
        msg = f"Invalid string or rule set wildcard '{text}' for libyara output"
        raise ValueError(msg)
    _render_rule_identifier(text[:-1])
    return text


def _render_single_string_set_text(string_set: object) -> str:
    text = str(string_set)
    if text == "them":
        return text
    return f"({validate_string_set_item_text(text)})"


def _render_string_set_item(gen: Any, item: Any) -> str:
    from yaraast.ast.expressions import StringLiteral

    if isinstance(item, StringLiteral):
        return validate_string_set_item_text(item.value)
    if hasattr(item, "accept"):
        return cast(str, gen.visit(item))
    return validate_string_set_item_text(item)


def _render_quantifier(gen: Any, quantifier: Any, *, allow_percentage: bool = False) -> str:
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
    return cast(str, gen.visit(quantifier))


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


def render_for_of_expression(gen: Any, node: Any) -> str:
    """Render a for-of expression."""
    quantifier = _render_quantifier(gen, node.quantifier, allow_percentage=True)
    string_set = _render_string_set(gen, node.string_set)
    if node.condition is not None:
        previous = getattr(gen, "_allow_string_placeholder", False)
        gen._allow_string_placeholder = True
        try:
            condition = gen.visit(node.condition)
        finally:
            gen._allow_string_placeholder = previous
        return f"for {quantifier} of {string_set} : ({condition})"
    return f"{quantifier} of {string_set}"


def render_in_expression(gen: Any, node: Any) -> str:
    """Render an in-expression with parenthesis normalization."""
    from yaraast.ast.expressions import (
        ParenthesesExpression,
        RangeExpression,
        StringCount,
        StringLength,
        StringOffset,
    )

    subject = (
        format_string_reference_identifier(
            node.subject,
            allow_placeholder=getattr(gen, "_allow_string_placeholder", False),
        )
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


def render_of_expression(gen: Any, node: Any) -> str:
    """Render an of-expression."""
    quantifier = _render_quantifier(gen, node.quantifier, allow_percentage=True)
    string_set = _render_string_set(gen, node.string_set)
    return f"{quantifier} of {string_set}"
