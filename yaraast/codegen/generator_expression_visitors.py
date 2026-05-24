"""Expression rendering helpers for CodeGenerator."""

from __future__ import annotations

from yaraast.codegen.generator_formatting import (
    validate_yara_identifier,
    validate_yara_identifier_path,
)
from yaraast.codegen.generator_helpers import validate_string_identifier_text

_BINARY_PRECEDENCE = {
    "or": 1,
    "and": 2,
    "==": 3,
    "!=": 3,
    "<": 3,
    "<=": 3,
    ">": 3,
    ">=": 3,
    "contains": 3,
    "matches": 3,
    "startswith": 3,
    "endswith": 3,
    "icontains": 3,
    "istartswith": 3,
    "iendswith": 3,
    "iequals": 3,
    "|": 4,
    "^": 5,
    "&": 6,
    "<<": 7,
    ">>": 7,
    "+": 8,
    "-": 8,
    "*": 9,
    "/": 9,
    "\\": 9,
    "%": 9,
}
_UNARY_OPERATORS = frozenset({"not", "-", "~"})


def _precedence(operator: str) -> int:
    return _BINARY_PRECEDENCE.get(operator, 100)


def _render_binary_operator(operator: str) -> str:
    if operator not in _BINARY_PRECEDENCE:
        msg = f"Invalid binary operator '{operator}' for libyara output"
        raise ValueError(msg)
    if operator == "/":
        return "\\"
    return operator


def _render_unary_operator(operator: str) -> str:
    if operator in _UNARY_OPERATORS:
        return operator
    msg = f"Invalid unary operator '{operator}' for libyara output"
    raise ValueError(msg)


def _visit_binary_operand(generator, parent, operand, *, is_right: bool) -> str:
    from yaraast.ast.expressions import BinaryExpression

    rendered = generator.visit(operand)
    if isinstance(operand, BinaryExpression) and (
        _precedence(operand.operator) < _precedence(parent.operator)
        or (is_right and _precedence(operand.operator) == _precedence(parent.operator))
    ):
        return f"({rendered})"
    return rendered


def visit_binary_expression(generator, node) -> str:
    left = _visit_binary_operand(generator, node, node.left, is_right=False)
    right = _visit_binary_operand(generator, node, node.right, is_right=True)
    operator = _render_binary_operator(node.operator)
    return f"{left} {operator} {right}"


def visit_unary_expression(generator, node) -> str:
    operator = _render_unary_operator(node.operator)
    operand = generator.visit(node.operand)
    from yaraast.ast.expressions import BinaryExpression

    if isinstance(node.operand, BinaryExpression):
        operand = f"({operand})"
    if operator == "not":
        return f"not {operand}"
    return f"{operator}{operand}"


def visit_parentheses_expression(generator, node) -> str:
    return f"({generator.visit(node.expression)})"


def visit_set_expression(generator, node) -> str:
    return f"({', '.join(generator.visit(elem) for elem in node.elements)})"


def visit_range_expression(generator, node) -> str:
    return f"{generator.visit(node.low)}..{generator.visit(node.high)}"


def visit_function_call(generator, node) -> str:
    function = validate_yara_identifier_path(node.function, "function")
    return f"{function}({', '.join(generator.visit(arg) for arg in node.arguments)})"


def visit_array_access(generator, node) -> str:
    return f"{generator.visit(node.array)}[{generator.visit(node.index)}]"


def visit_member_access(generator, node) -> str:
    member = validate_yara_identifier(node.member, "member")
    return f"{generator.visit(node.object)}.{member}"


def visit_for_expression(generator, node) -> str:
    iterable = generator.visit(node.iterable)
    body = generator.visit(node.body)
    quantifier = (
        generator.visit(node.quantifier)
        if hasattr(node.quantifier, "accept")
        else str(node.quantifier)
    )
    return f"for {quantifier} {node.variable} in {iterable} : ({body})"


def visit_at_expression(generator, node) -> str:
    string_id = validate_string_identifier_text(node.string_id)
    return f"{string_id} at {generator.visit(node.offset)}"
