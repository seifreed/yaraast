"""Expression rendering helpers for the main code generator."""

from __future__ import annotations

from yaraast.codegen.generator_helpers import validate_string_identifier_text


def _render_string_set(gen, string_set) -> str:
    from yaraast.ast.expressions import (
        ParenthesesExpression,
        SetExpression,
        StringLiteral,
        StringWildcard,
    )

    if isinstance(string_set, StringLiteral):
        return string_set.value
    if isinstance(string_set, StringWildcard):
        return f"({gen.visit(string_set)})"
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
    return str(string_set)


def _render_string_set_item(gen, item) -> str:
    from yaraast.ast.expressions import StringLiteral

    if isinstance(item, StringLiteral):
        return item.value
    if hasattr(item, "accept"):
        return gen.visit(item)
    return str(item)


def _render_quantifier(gen, quantifier, *, allow_percentage: bool = False) -> str:
    from yaraast.ast.expressions import DoubleLiteral, StringLiteral

    if isinstance(quantifier, str | int):
        return str(quantifier)
    if isinstance(quantifier, float) and allow_percentage:
        return f"{int(quantifier * 100)}%"
    if isinstance(quantifier, StringLiteral):
        return quantifier.value
    if isinstance(quantifier, DoubleLiteral) and allow_percentage:
        return f"{int(quantifier.value * 100)}%"
    return gen.visit(quantifier)


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
