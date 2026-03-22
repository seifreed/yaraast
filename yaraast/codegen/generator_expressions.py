"""Expression rendering helpers for the main code generator."""

from __future__ import annotations


def render_for_of_expression(gen, node) -> str:
    """Render a for-of expression."""
    if hasattr(node.quantifier, "accept"):
        quantifier = gen.visit(node.quantifier)
    else:
        quantifier = str(node.quantifier)

    string_set = gen.visit(node.string_set)
    if node.condition:
        condition = gen.visit(node.condition)
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

    subject = node.string_id if isinstance(node.subject, str) else gen.visit(node.subject)

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
    from yaraast.ast.expressions import DoubleLiteral, StringLiteral

    if isinstance(node.quantifier, str | int):
        quantifier = str(node.quantifier)
    elif isinstance(node.quantifier, StringLiteral):
        quantifier = node.quantifier.value
    elif isinstance(node.quantifier, DoubleLiteral):
        # Percentage quantifier: 0.5 → "50%"
        quantifier = f"{int(node.quantifier.value * 100)}%"
    else:
        quantifier = gen.visit(node.quantifier)
    string_set = gen.visit(node.string_set)
    return f"{quantifier} of {string_set}"
