"""Expression rendering helpers for the main code generator."""

from __future__ import annotations

import math
import re
from typing import Any, cast

from yaraast.codegen.generator_formatting import validate_yara_identifier
from yaraast.codegen.generator_helpers import (
    format_integer_literal,
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
        pattern = _require_string_set_field(string_set.pattern, "String wildcard")
        if not pattern.startswith("$"):
            return f"({_render_rule_wildcard(pattern)})"
        return f"({gen.visit(string_set)})"
    if isinstance(string_set, Identifier):
        name = _require_string_set_field(string_set.name, "String set identifier")
        if name != "them" and not name.startswith("$"):
            return f"({_render_rule_identifier(name)})"
        return _render_single_string_set_text(name)
    if isinstance(string_set, ParenthesesExpression):
        return _render_string_set(gen, string_set.expression)
    if isinstance(string_set, SetExpression):
        _validate_non_empty_string_set(string_set.elements)
        if _is_rule_set_items(string_set.elements):
            rendered_items = [_render_rule_set_item(item) for item in string_set.elements]
            return f"({', '.join(rendered_items)})"
        if _has_mixed_rule_and_string_set_items(string_set.elements):
            msg = "Mixed string and rule set items are not valid for libyara output"
            raise ValueError(msg)
        rendered_items = [_render_string_set_item(gen, item) for item in string_set.elements]
        return f"({', '.join(rendered_items)})"
    if isinstance(string_set, list | tuple):
        _validate_non_empty_string_set(string_set)
        if _is_rule_set_items(string_set):
            rendered_items = [_render_rule_set_item(item) for item in string_set]
            return f"({', '.join(rendered_items)})"
        if _has_mixed_rule_and_string_set_items(string_set):
            msg = "Mixed string and rule set items are not valid for libyara output"
            raise ValueError(msg)
        rendered_items = [_render_string_set_item(gen, item) for item in string_set]
        return f"({', '.join(rendered_items)})"
    if isinstance(string_set, set | frozenset):
        _validate_non_empty_string_set(string_set)
        sorted_items = sorted(string_set, key=str)
        if _is_rule_set_items(sorted_items):
            rendered_items = [_render_rule_set_item(item) for item in sorted_items]
            return f"({', '.join(rendered_items)})"
        if _has_mixed_rule_and_string_set_items(sorted_items):
            msg = "Mixed string and rule set items are not valid for libyara output"
            raise ValueError(msg)
        rendered_items = [_render_string_set_item(gen, item) for item in sorted_items]
        return f"({', '.join(rendered_items)})"
    if hasattr(string_set, "accept"):
        _reject_invalid_string_set_item()
    return _render_single_string_set_text(string_set)


def _is_rule_set_items(items: list[Any] | tuple[Any, ...]) -> bool:
    return bool(items) and all(_is_rule_set_item(item) for item in items)


def _validate_non_empty_string_set(items: Any) -> None:
    if items:
        return
    msg = "String set must contain at least one item for libyara output"
    raise ValueError(msg)


def _has_mixed_rule_and_string_set_items(items: list[Any] | tuple[Any, ...]) -> bool:
    has_rule_item = any(_is_rule_set_item(item) for item in items)
    has_string_item = any(_is_string_set_item(item) for item in items)
    return has_rule_item and has_string_item


def _is_rule_set_item(item: Any) -> bool:
    from yaraast.ast.expressions import Identifier, StringWildcard

    if isinstance(item, Identifier):
        return isinstance(item.name, str) and item.name != "them" and not item.name.startswith("$")
    return (
        isinstance(item, StringWildcard)
        and isinstance(item.pattern, str)
        and not item.pattern.startswith("$")
    )


def _is_string_set_item(item: Any) -> bool:
    from yaraast.ast.expressions import Identifier, StringIdentifier, StringLiteral, StringWildcard

    if isinstance(item, Identifier):
        return isinstance(item.name, str) and (item.name == "them" or item.name.startswith("$"))
    if isinstance(item, StringIdentifier):
        return True
    if isinstance(item, StringWildcard):
        return isinstance(item.pattern, str) and item.pattern.startswith("$")
    if isinstance(item, StringLiteral):
        return isinstance(item.value, str) and (item.value == "them" or item.value.startswith("$"))
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
    text = _require_string_set_field(name, "String or rule set identifier")
    try:
        return validate_yara_identifier(text, "rule")
    except ValueError as exc:
        msg = f"Invalid string or rule set identifier '{text}' for libyara output"
        raise ValueError(msg) from exc


def _render_rule_wildcard(pattern: object) -> str:
    text = _require_string_set_field(pattern, "String or rule set wildcard")
    if text.startswith("$") or not text.endswith("*") or text == "*":
        msg = f"Invalid string or rule set wildcard '{text}' for libyara output"
        raise ValueError(msg)
    _render_rule_identifier(text[:-1])
    return text


def _render_single_string_set_text(string_set: object) -> str:
    text = _require_string_set_field(string_set, "String set item")
    if text == "them":
        return text
    return f"({validate_string_set_item_text(text)})"


def _require_string_set_field(value: object, field_name: str) -> str:
    if not isinstance(value, str):
        msg = f"{field_name} must be a string for libyara output"
        raise TypeError(msg)
    return value


def _render_string_set_item(gen: Any, item: Any) -> str:
    from yaraast.ast.expressions import Identifier, StringLiteral, StringWildcard

    if isinstance(item, StringLiteral):
        return validate_string_set_item_text(item.value)
    if isinstance(item, Identifier):
        name = _require_string_set_field(item.name, "String set identifier")
        if name.startswith("$"):
            return validate_string_set_item_text(name)
        return cast(str, gen.visit(item))
    if isinstance(item, StringWildcard):
        return cast(str, gen.visit(item))
    if not _is_string_set_item(item):
        _reject_invalid_string_set_item()
    if hasattr(item, "accept"):
        return cast(str, gen.visit(item))
    return validate_string_set_item_text(item)


def _reject_invalid_string_set_item() -> None:
    msg = "String set items must be string or rule identifiers for libyara output"
    raise ValueError(msg)


def _render_quantifier(
    gen: Any,
    quantifier: Any,
    *,
    allow_percentage: bool = False,
    context: str = "quantifier",
) -> str:
    """Render an of/for quantifier.

    ``allow_percentage`` enables percentage quantifiers (``of`` only; ``for``
    loops reject them). ``context`` labels error messages ("quantifier" vs
    "for quantifier").
    """
    from yaraast.ast.expressions import (
        BooleanLiteral,
        DoubleLiteral,
        Identifier,
        IntegerLiteral,
        RegexLiteral,
        StringLiteral,
        UnaryExpression,
    )

    if isinstance(quantifier, bool):
        msg = f"Invalid {context} '{quantifier}' for libyara output"
        raise ValueError(msg)
    if isinstance(quantifier, int):
        if quantifier < 0:
            msg = f"Invalid {context} '{quantifier}' for libyara output"
            raise ValueError(msg)
        return format_integer_literal(quantifier)
    if isinstance(quantifier, str):
        return _validate_quantifier_text(
            quantifier, allow_percentage=allow_percentage, context=context
        )
    if isinstance(quantifier, float):
        if allow_percentage:
            return _format_fractional_percentage_quantifier(quantifier)
        msg = f"Invalid {context} '{quantifier}' for libyara output"
        raise ValueError(msg)
    if isinstance(quantifier, IntegerLiteral):
        value = quantifier.value
        if isinstance(value, bool) or not isinstance(value, int):
            msg = f"Invalid {context} '{value}' for libyara output"
            raise ValueError(msg)
        if value < 0:
            msg = f"Invalid {context} '{value}' for libyara output"
            raise ValueError(msg)
        return format_integer_literal(value)
    if isinstance(quantifier, BooleanLiteral):
        msg = f"Invalid {context} '{gen.visit(quantifier)}' for libyara output"
        raise ValueError(msg)
    if isinstance(quantifier, StringLiteral):
        return _validate_quantifier_text(
            quantifier.value,
            allow_percentage=allow_percentage,
            context=context,
            allow_identifier=False,
        )
    if isinstance(quantifier, DoubleLiteral):
        if allow_percentage:
            return _format_fractional_percentage_quantifier(quantifier.value)
        msg = f"Invalid {context} '{gen.visit(quantifier)}' for libyara output"
        raise ValueError(msg)
    if isinstance(quantifier, RegexLiteral):
        msg = f"Invalid {context} '{gen.visit(quantifier)}' for libyara output"
        raise ValueError(msg)
    if isinstance(quantifier, UnaryExpression) and quantifier.operator == "%":
        if not allow_percentage:
            msg = f"Invalid {context} '{gen.visit(quantifier.operand)}%' for libyara output"
            raise ValueError(msg)
        _validate_static_percentage_expression_quantifier(quantifier)
        operand = gen.visit(quantifier.operand)
        if _needs_percentage_quantifier_parentheses(quantifier.operand):
            operand = f"({operand})"
        return f"{operand}%"
    if isinstance(quantifier, Identifier):
        # filesize and entrypoint are reserved words that libyara nonetheless
        # accepts as integer quantifiers; the strict identifier validator would
        # reject them, so emit those directly. Other identifiers still go through
        # validation, which rejects non-count keywords such as true.
        if quantifier.name in {"filesize", "entrypoint"}:
            return quantifier.name
        return _validate_quantifier_text(
            quantifier.name, allow_percentage=allow_percentage, context=context
        )
    # Any remaining quantifier is a primary expression libyara accepts as a
    # count (e.g. uint8(0), pe.number_of_sections); render it directly.
    return cast(str, gen.visit(quantifier))


def _validate_quantifier_text(
    text: str,
    *,
    allow_percentage: bool,
    context: str = "quantifier",
    allow_identifier: bool = True,
) -> str:
    if not isinstance(text, str):
        msg = f"Invalid {context} '{text}' for libyara output"
        raise ValueError(msg)
    if text in {"all", "any", "none"}:
        return text

    integer = _INTEGER_QUANTIFIER_RE.fullmatch(text)
    if integer is not None:
        if int(text) < 0:
            msg = f"Invalid {context} '{text}' for libyara output"
            raise ValueError(msg)
        return format_integer_literal(text)

    percentage = _PERCENTAGE_QUANTIFIER_RE.fullmatch(text)
    if percentage is not None:
        if not allow_percentage:
            msg = f"Invalid {context} '{text}' for libyara output"
            raise ValueError(msg)
        _validate_percentage_quantifier(int(percentage.group(1)), text)
        return text

    if not allow_identifier:
        msg = f"Invalid {context} '{text}' for libyara output"
        raise ValueError(msg)

    return validate_yara_identifier(text, context)


def _format_fractional_percentage_quantifier(value: float) -> str:
    if isinstance(value, bool) or not isinstance(value, int | float) or not math.isfinite(value):
        msg = f"Invalid quantifier '{value}' for libyara output"
        raise ValueError(msg)
    percent = round(value * 100)
    _validate_percentage_quantifier(percent, value)
    return f"{percent}%"


def _validate_percentage_quantifier(percent: int, raw_value: object) -> None:
    if _QUANTIFIER_PERCENT_MIN <= percent <= _QUANTIFIER_PERCENT_MAX:
        return
    msg = f"Invalid quantifier '{raw_value}' for libyara output"
    raise ValueError(msg)


def _validate_static_percentage_expression_quantifier(quantifier: Any) -> None:
    if _has_invalid_static_percentage_operand(quantifier.operand):
        msg = f"Invalid quantifier '{quantifier.operand}' for libyara output"
        raise ValueError(msg)
    value = _static_integer_quantifier_value(quantifier.operand)
    if value is not None:
        _validate_percentage_quantifier(value, f"{value}%")


def _has_invalid_static_percentage_operand(value: Any) -> bool:
    from yaraast.ast.expressions import (
        BinaryExpression,
        BooleanLiteral,
        DoubleLiteral,
        ParenthesesExpression,
        RegexLiteral,
        StringIdentifier,
        StringLiteral,
        UnaryExpression,
    )

    if isinstance(
        value,
        bool | float | BooleanLiteral | DoubleLiteral | RegexLiteral | StringIdentifier | str,
    ):
        return True
    if isinstance(value, StringLiteral):
        return True
    if isinstance(value, ParenthesesExpression):
        return _has_invalid_static_percentage_operand(value.expression)
    if isinstance(value, UnaryExpression):
        return _has_invalid_static_percentage_operand(value.operand)
    if isinstance(value, BinaryExpression):
        return _has_invalid_static_percentage_operand(
            value.left
        ) or _has_invalid_static_percentage_operand(value.right)
    return False


def _static_integer_quantifier_value(value: Any) -> int | None:
    from yaraast.ast.expressions import (
        BinaryExpression,
        IntegerLiteral,
        ParenthesesExpression,
        UnaryExpression,
    )

    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if (
        isinstance(value, IntegerLiteral)
        and isinstance(value.value, int)
        and not isinstance(value.value, bool)
    ):
        return value.value
    if isinstance(value, ParenthesesExpression):
        return _static_integer_quantifier_value(value.expression)
    if isinstance(value, UnaryExpression):
        operand = _static_integer_quantifier_value(value.operand)
        if operand is None:
            return None
        if value.operator == "-":
            return -operand
        if value.operator == "~":
            return ~operand
    if isinstance(value, BinaryExpression) and value.operator in {
        "+",
        "-",
        "*",
        "%",
        "<<",
        ">>",
        "&",
        "|",
        "^",
    }:
        right = _static_integer_quantifier_value(value.right)
        if right is not None and value.operator in {"<<", ">>"}:
            if right < 0:
                return None
            if right >= _INT64_BITS:
                return 0
        left = _static_integer_quantifier_value(value.left)
        if left is None or right is None:
            return None
        if value.operator == "+":
            return left + right
        if value.operator == "-":
            return left - right
        if value.operator == "*":
            return left * right
        if value.operator == "%":
            if right == 0:
                return None
            return _integer_remainder(left, right)
        if value.operator == "<<":
            if right < 0:
                return None
            return left << right
        if value.operator == ">>":
            if right < 0:
                return None
            return left >> right
        if value.operator == "&":
            return left & right
        if value.operator == "|":
            return left | right
        if value.operator == "^":
            return left ^ right
    return None


def _needs_percentage_quantifier_parentheses(value: Any) -> bool:
    from yaraast.ast.expressions import BinaryExpression

    return isinstance(value, BinaryExpression)


def _integer_remainder(left: int, right: int) -> int:
    quotient = abs(left) // abs(right)
    if (left < 0) != (right < 0):
        quotient = -quotient
    return left - quotient * right


_INT64_BITS = 64


def render_for_of_expression(gen: Any, node: Any) -> str:
    """Render a for-of expression."""
    quantifier = _render_quantifier(
        gen,
        node.quantifier,
        allow_percentage=node.condition is None,
        context="for quantifier" if node.condition is not None else "quantifier",
    )
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
    from yaraast.ast.expressions import ParenthesesExpression, RangeExpression

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

    if isinstance(node.range, ParenthesesExpression) and isinstance(
        node.range.expression, RangeExpression
    ):
        range_expr = gen.visit(node.range.expression)
        return f"{subject} in ({range_expr})"

    msg = "In expression range must be a range expression for libyara output"
    raise ValueError(msg)


def render_of_expression(gen: Any, node: Any) -> str:
    """Render an of-expression."""
    quantifier = _render_quantifier(gen, node.quantifier, allow_percentage=True)
    string_set = _render_string_set(gen, node.string_set)
    return f"{quantifier} of {string_set}"
