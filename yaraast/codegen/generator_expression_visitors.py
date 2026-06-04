"""Expression rendering helpers for CodeGenerator."""

from __future__ import annotations

from typing import Any, cast

from yaraast.codegen.generator_formatting import (
    validate_yara_identifier,
    validate_yara_identifier_path,
)
from yaraast.codegen.generator_helpers import format_string_reference_identifier

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
_NUMERIC_BINARY_OPERATORS = frozenset({"+", "-", "*", "/", "\\"})
_INTEGER_BINARY_OPERATORS = frozenset({"%", "&", "|", "^", "<<", ">>"})


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


def _reject_boolean_expression(value: Any, message: str) -> None:
    from yaraast.ast.expressions import BooleanLiteral, ParenthesesExpression

    if isinstance(value, bool | BooleanLiteral):
        raise ValueError(message)
    if isinstance(value, ParenthesesExpression):
        _reject_boolean_expression(value.expression, message)


def _reject_boolean_binary_numeric_operands(node: Any) -> None:
    if node.operator in _NUMERIC_BINARY_OPERATORS:
        _reject_boolean_expression(
            node.left, f"Left operand of '{node.operator}' must be numeric for libyara output"
        )
        _reject_boolean_expression(
            node.right, f"Right operand of '{node.operator}' must be numeric for libyara output"
        )
    if node.operator in _INTEGER_BINARY_OPERATORS:
        _reject_boolean_expression(
            node.left, f"Left operand of '{node.operator}' must be integer for libyara output"
        )
        _reject_boolean_expression(
            node.right, f"Right operand of '{node.operator}' must be integer for libyara output"
        )


def _visit_binary_operand(generator: Any, parent: Any, operand: Any, *, is_right: bool) -> str:
    from yaraast.ast.expressions import BinaryExpression

    rendered = cast(str, generator.visit(operand))
    if isinstance(operand, BinaryExpression) and (
        _precedence(operand.operator) < _precedence(parent.operator)
        or (is_right and _precedence(operand.operator) == _precedence(parent.operator))
    ):
        return f"({rendered})"
    return rendered


def visit_binary_expression(generator: Any, node: Any) -> str:
    _reject_boolean_binary_numeric_operands(node)
    left = _visit_binary_operand(generator, node, node.left, is_right=False)
    right = _visit_binary_operand(generator, node, node.right, is_right=True)
    operator = _render_binary_operator(node.operator)
    return f"{left} {operator} {right}"


def visit_unary_expression(generator: Any, node: Any) -> str:
    operator = _render_unary_operator(node.operator)
    if operator == "-":
        _reject_boolean_expression(
            node.operand, "Operand of '-' must be numeric for libyara output"
        )
    if operator == "~":
        _reject_boolean_expression(
            node.operand, "Operand of '~' must be integer for libyara output"
        )
    operand = generator.visit(node.operand)
    from yaraast.ast.expressions import BinaryExpression

    if isinstance(node.operand, BinaryExpression):
        operand = f"({operand})"
    if operator == "not":
        return f"not {operand}"
    return f"{operator}{operand}"


def visit_parentheses_expression(generator: Any, node: Any) -> str:
    return f"({generator.visit(node.expression)})"


def visit_set_expression(generator: Any, node: Any) -> str:
    validate_set_expression_elements(node)
    return f"({', '.join(generator.visit(elem) for elem in node.elements)})"


def validate_set_expression_elements(node: Any) -> None:
    validate_expression_collection(node.elements, "SetExpression elements")
    if not node.elements:
        msg = "Set expression must contain at least one element for libyara output"
        raise ValueError(msg)


def validate_function_call_arguments(node: Any) -> None:
    validate_expression_collection(node.arguments, "FunctionCall arguments")


def validate_expression_collection(value: Any, field_name: str) -> None:
    if isinstance(value, list | tuple):
        return
    msg = f"{field_name} must be a list or tuple for libyara output"
    raise TypeError(msg)


def require_present_expression(value: Any, field_name: str) -> Any:
    if value is None:
        msg = f"{field_name} is required for libyara output"
        raise ValueError(msg)
    return value


def _reject_boolean_numeric_expression(value: Any, field_name: str) -> None:
    _reject_boolean_expression(value, f"{field_name} must be integer for libyara output")


def visit_range_expression(generator: Any, node: Any) -> str:
    _reject_boolean_numeric_expression(node.low, "Range low bound")
    _reject_boolean_numeric_expression(node.high, "Range high bound")
    return f"{generator.visit(node.low)}..{generator.visit(node.high)}"


def render_function_call_callee(generator: Any, node: Any) -> str:
    """Render the callee of a function call, including an indexed receiver.

    When ``receiver`` is set the callee is ``<receiver>.<method>`` (e.g.
    ``pe.signatures[0].valid_on``); otherwise it is the dotted function name.
    """
    receiver = getattr(node, "receiver", None)
    if receiver is not None:
        method = validate_yara_identifier(node.function, "function")
        return f"{generator.visit(receiver)}.{method}"
    return validate_yara_identifier_path(node.function, "function")


def visit_function_call(generator: Any, node: Any) -> str:
    callee = render_function_call_callee(generator, node)
    validate_function_call_arguments(node)
    return f"{callee}({', '.join(generator.visit(arg) for arg in node.arguments)})"


def visit_array_access(generator: Any, node: Any) -> str:
    _reject_boolean_numeric_expression(node.index, "Array index")
    return f"{generator.visit(node.array)}[{generator.visit(node.index)}]"


def visit_member_access(generator: Any, node: Any) -> str:
    member = validate_yara_identifier(node.member, "member")
    return f"{generator.visit(node.object)}.{member}"


def visit_for_expression(generator: Any, node: Any) -> str:
    from yaraast.ast.expressions import RangeExpression
    from yaraast.codegen.generator_expressions import _render_quantifier

    iterable = generator.visit(node.iterable)
    if isinstance(node.iterable, RangeExpression):
        iterable = f"({iterable})"
    body = generator.visit(node.body)
    quantifier = _render_quantifier(
        generator, node.quantifier, allow_percentage=False, context="for quantifier"
    )
    variable = _render_for_loop_variable(node.variable)
    return f"for {quantifier} {variable} in {iterable} : ({body})"


def _render_for_loop_variable(variable: Any) -> str:
    if not isinstance(variable, str):
        return validate_yara_identifier(variable, "loop variable")
    names = [part.strip() for part in variable.split(",")]
    if len(names) == 1:
        return validate_yara_identifier(variable, "loop variable")
    return ", ".join(validate_yara_identifier(name, "loop variable") for name in names)


def visit_at_expression(generator: Any, node: Any) -> str:
    if hasattr(node.string_id, "accept"):
        string_id = generator.visit(node.string_id)
    else:
        string_id = format_string_reference_identifier(
            node.string_id,
            allow_placeholder=getattr(generator, "_allow_string_placeholder", False),
        )
    _reject_boolean_numeric_expression(node.offset, "At expression offset")
    return f"{string_id} at {generator.visit(node.offset)}"
