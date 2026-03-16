"""Expression rendering helpers for CodeGenerator."""

from __future__ import annotations


def visit_binary_expression(generator, node) -> str:
    return f"{generator.visit(node.left)} {node.operator} {generator.visit(node.right)}"


def visit_unary_expression(generator, node) -> str:
    operand = generator.visit(node.operand)
    if node.operator == "not":
        return f"not {operand}"
    return f"{node.operator}{operand}"


def visit_parentheses_expression(generator, node) -> str:
    return f"({generator.visit(node.expression)})"


def visit_set_expression(generator, node) -> str:
    return f"({', '.join(generator.visit(elem) for elem in node.elements)})"


def visit_range_expression(generator, node) -> str:
    return f"{generator.visit(node.low)}..{generator.visit(node.high)}"


def visit_function_call(generator, node) -> str:
    return f"{node.function}({', '.join(generator.visit(arg) for arg in node.arguments)})"


def visit_array_access(generator, node) -> str:
    return f"{generator.visit(node.array)}[{generator.visit(node.index)}]"


def visit_member_access(generator, node) -> str:
    return f"{generator.visit(node.object)}.{node.member}"


def visit_for_expression(generator, node) -> str:
    iterable = generator.visit(node.iterable)
    body = generator.visit(node.body)
    return f"for {node.quantifier} {node.variable} in {iterable} : ({body})"


def visit_at_expression(generator, node) -> str:
    return f"{node.string_id} at {generator.visit(node.offset)}"
