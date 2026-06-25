"""Expression optimizer for YARA rules."""

from __future__ import annotations

from collections.abc import Callable
import copy
from typing import Any, cast, overload

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import (
    BinaryExpression,
    BooleanLiteral,
    Expression,
    Identifier,
    IntegerLiteral,
    ParenthesesExpression,
    RangeExpression,
    StringIdentifier,
    StringWildcard,
    UnaryExpression,
)
from yaraast.ast.operators import DefinedExpression
from yaraast.ast.rules import Rule
from yaraast.shared.integer_semantics import (
    INT64_MIN,
    integer_remainder,
    normalize_int64,
    shift_left_int64,
    shift_right_int64,
    truncate_integer_division,
)
from yaraast.visitor.base import ASTTransformer


class _Sentinel:
    pass


_SENTINEL = _Sentinel()


def _fold_boolean(
    left: BooleanLiteral,
    right: BooleanLiteral,
    operator: str,
) -> BooleanLiteral | _Sentinel:
    """Fold constant boolean expressions. Returns result or _SENTINEL."""
    left_value = _boolean_literal_value(left)
    right_value = _boolean_literal_value(right)
    if left_value is None or right_value is None:
        return _SENTINEL
    if operator == "and":
        return BooleanLiteral(value=left_value and right_value)
    if operator == "or":
        return BooleanLiteral(value=left_value or right_value)
    return _SENTINEL


_COMPARISON_OPS: dict[str, Callable[[int, int], bool]] = {
    "==": lambda a, b: a == b,
    "!=": lambda a, b: a != b,
    "<": lambda a, b: a < b,
    ">": lambda a, b: a > b,
    "<=": lambda a, b: a <= b,
    ">=": lambda a, b: a >= b,
}


def _fold_arithmetic(left_val: int, right_val: int, operator: str) -> IntegerLiteral | _Sentinel:
    """Fold constant integer arithmetic. Returns result or _SENTINEL."""
    if operator == "+":
        return IntegerLiteral(value=normalize_int64(left_val + right_val))
    if operator == "-":
        return IntegerLiteral(value=normalize_int64(left_val - right_val))
    if operator == "*":
        return IntegerLiteral(value=normalize_int64(left_val * right_val))
    if operator in ("/", "\\") and right_val != 0:
        if left_val == INT64_MIN and right_val == -1:
            return _SENTINEL
        return IntegerLiteral(value=truncate_integer_division(left_val, right_val))
    if operator == "%" and right_val != 0:
        if left_val == INT64_MIN and right_val == -1:
            return _SENTINEL
        return IntegerLiteral(value=integer_remainder(left_val, right_val))
    if operator == "<<":
        if right_val < 0:
            return _SENTINEL
        return IntegerLiteral(value=shift_left_int64(left_val, right_val))
    if operator == ">>":
        if right_val < 0:
            return _SENTINEL
        return IntegerLiteral(value=shift_right_int64(left_val, right_val))
    if operator == "&":
        return IntegerLiteral(value=normalize_int64(left_val & right_val))
    if operator == "|":
        return IntegerLiteral(value=normalize_int64(left_val | right_val))
    if operator == "^":
        return IntegerLiteral(value=normalize_int64(left_val ^ right_val))
    return _SENTINEL


def _fold_comparison(left_val: int, right_val: int, operator: str) -> BooleanLiteral | _Sentinel:
    """Fold constant integer comparisons. Returns result or _SENTINEL."""
    fn = _COMPARISON_OPS.get(operator)
    if fn is not None:
        return BooleanLiteral(value=fn(left_val, right_val))
    return _SENTINEL


def _is_static_numeric_identity_operand(node: Expression) -> bool:
    return isinstance(node, Identifier) and node.name in {"filesize", "entrypoint"}


def _simplify_identity(node: BinaryExpression) -> tuple[Expression | None, int]:
    """Simplify arithmetic identities only for statically numeric operands."""
    left, right, op = node.left, node.right, node.operator

    right_value = _integer_literal_value(right) if isinstance(right, IntegerLiteral) else None
    left_value = _integer_literal_value(left) if isinstance(left, IntegerLiteral) else None

    if op == "+" and right_value == 0:
        return (left, 1) if _is_static_numeric_identity_operand(left) else (None, 0)
    if op == "+" and left_value == 0:
        return (right, 1) if _is_static_numeric_identity_operand(right) else (None, 0)
    if op == "*" and right_value == 1:
        return (left, 1) if _is_static_numeric_identity_operand(left) else (None, 0)
    if op == "*" and left_value == 1:
        return (right, 1) if _is_static_numeric_identity_operand(right) else (None, 0)

    return None, 0


def _is_static_boolean_identity_operand(node: Expression) -> bool:
    if isinstance(node, BooleanLiteral):
        return _boolean_literal_value(node) is not None
    return isinstance(node, StringIdentifier | StringWildcard | DefinedExpression)


def _simplify_boolean_short_circuit(
    node: BinaryExpression,
    *,
    preserve_undefined: bool = False,
) -> tuple[Expression | None, int]:
    """Simplify boolean short-circuit patterns. Returns (result, opt_count)."""
    if isinstance(node.left, BooleanLiteral):
        left_value = _boolean_literal_value(node.left)
        if left_value is None:
            return None, 0
        if node.operator == "and":
            if not left_value:
                return BooleanLiteral(value=False), 1
            if _is_static_boolean_identity_operand(node.right):
                return node.right, 1
        if node.operator == "or":
            if left_value:
                return BooleanLiteral(value=True), 1
            if _is_static_boolean_identity_operand(node.right):
                return node.right, 1

    if isinstance(node.right, BooleanLiteral):
        right_value = _boolean_literal_value(node.right)
        if right_value is None:
            return None, 0
        if (
            node.operator == "and"
            and not right_value
            and (not preserve_undefined or _is_static_boolean_identity_operand(node.left))
        ):
            return BooleanLiteral(value=False), 1
        if (
            node.operator == "or"
            and right_value
            and (not preserve_undefined or _is_static_boolean_identity_operand(node.left))
        ):
            return BooleanLiteral(value=True), 1
        if node.operator == "and" and _is_static_boolean_identity_operand(node.left):
            return node.left, 1
        if node.operator == "or" and _is_static_boolean_identity_operand(node.left):
            return node.left, 1

    return None, 0


def _is_empty_integer_range(node: Any) -> bool:
    if isinstance(node, ParenthesesExpression):
        node = node.expression
    if not (
        isinstance(node, RangeExpression)
        and isinstance(node.low, IntegerLiteral)
        and isinstance(node.high, IntegerLiteral)
    ):
        return False
    low_value = _integer_literal_value(node.low)
    high_value = _integer_literal_value(node.high)
    if low_value is None or high_value is None:
        return False
    return high_value < low_value


def _integer_literal_value(node: IntegerLiteral) -> int | None:
    if isinstance(node.value, bool) or not isinstance(node.value, int):
        return None
    return node.value


def _boolean_literal_value(node: BooleanLiteral) -> bool | None:
    if not isinstance(node.value, bool):
        return None
    return node.value


class ExpressionOptimizer(ASTTransformer):
    """Optimizes expressions in YARA rules."""

    def __init__(self) -> None:
        super().__init__()
        self.optimization_count = 0
        self._defined_expression_depth = 0

    @overload
    def optimize(self, node: YaraFile) -> tuple[YaraFile, int]: ...

    @overload
    def optimize(self, node: Expression) -> Expression: ...

    def optimize(self, node: Expression | YaraFile) -> Expression | tuple[YaraFile, int]:
        """Optimize an expression or YaraFile.

        Args:
            node: Expression to optimize or YaraFile containing rules to optimize

        Returns:
            If Expression: optimized Expression
            If YaraFile: tuple of (optimized YaraFile, optimization count)
        """
        self.optimization_count = 0
        if isinstance(node, YaraFile):
            node.validate_structure()
            optimized_rules: list[Rule] = []
            for rule in node.rules:
                optimized_rule = self._optimize_rule(rule)
                optimized_rules.append(optimized_rule)

            optimized_file = copy.copy(node)
            optimized_file.rules = optimized_rules
            return optimized_file, self.optimization_count
        # Single expression optimization
        return cast(Expression, self.visit(copy.deepcopy(node)))

    def _optimize_rule(self, rule: Rule) -> Rule:
        """Optimize expressions in a rule."""
        rule = copy.deepcopy(rule)
        if rule.condition is not None:
            # Reset count for this rule to track optimizations
            optimized_condition = cast(Expression, self.visit(rule.condition))
            # Count is incremented by visit methods for each optimization
            rule.condition = optimized_condition
        return rule

    def visit_binary_expression(self, node: BinaryExpression) -> Expression:
        """Visit BinaryExpression and optimize."""
        # Optimize children first
        node.left = cast(Expression, self.visit(node.left))
        node.right = cast(Expression, self.visit(node.right))

        # Constant folding for boolean operations
        if isinstance(node.left, BooleanLiteral) and isinstance(node.right, BooleanLiteral):
            boolean_result = _fold_boolean(node.left, node.right, node.operator)
            if isinstance(boolean_result, BooleanLiteral):
                self.optimization_count += 1
                return boolean_result

        # Constant folding for integer arithmetic and comparisons
        if isinstance(node.left, IntegerLiteral) and isinstance(node.right, IntegerLiteral):
            left_val = _integer_literal_value(node.left)
            right_val = _integer_literal_value(node.right)
            if left_val is None or right_val is None:
                return node

            arithmetic_result = _fold_arithmetic(left_val, right_val, node.operator)
            if isinstance(arithmetic_result, IntegerLiteral):
                self.optimization_count += 1
                return arithmetic_result

            comparison_result = _fold_comparison(left_val, right_val, node.operator)
            if isinstance(comparison_result, BooleanLiteral):
                self.optimization_count += 1
                return comparison_result

        # Identity operations are safe only for operands known to be numeric.
        identity, count = _simplify_identity(node)
        if identity is not None:
            self.optimization_count += count
            return identity

        # Boolean simplifications
        short_circuit, count = _simplify_boolean_short_circuit(
            node,
            preserve_undefined=self._defined_expression_depth > 0,
        )
        if short_circuit is not None:
            self.optimization_count += count
            return short_circuit

        return node

    def visit_unary_expression(self, node: UnaryExpression) -> Expression:
        """Visit UnaryExpression and optimize."""
        # Optimize operand first
        node.operand = cast(Expression, self.visit(node.operand))

        # Constant folding
        if node.operator == "not" and isinstance(node.operand, BooleanLiteral):
            boolean_value = _boolean_literal_value(node.operand)
            if boolean_value is None:
                return node
            self.optimization_count += 1
            return BooleanLiteral(value=not boolean_value)

        if node.operator == "-" and isinstance(node.operand, IntegerLiteral):
            integer_value = _integer_literal_value(node.operand)
            if integer_value is None:
                return node
            self.optimization_count += 1
            return IntegerLiteral(value=normalize_int64(-integer_value))

        if node.operator == "~" and isinstance(node.operand, IntegerLiteral):
            integer_value = _integer_literal_value(node.operand)
            if integer_value is None:
                return node
            self.optimization_count += 1
            return IntegerLiteral(value=normalize_int64(~integer_value))

        # Double negation elimination
        if (
            node.operator == "not"
            and isinstance(node.operand, UnaryExpression)
            and node.operand.operator == "not"
            and _is_static_boolean_identity_operand(node.operand.operand)
        ):
            self.optimization_count += 1
            return node.operand.operand

        return node

    def visit_parentheses_expression(self, node: ParenthesesExpression) -> Expression:
        """Visit ParenthesesExpression and optimize."""
        # Optimize inner expression
        inner = cast(Expression, self.visit(node.expression))

        # Remove unnecessary parentheses around literals and identifiers
        if isinstance(inner, BooleanLiteral | IntegerLiteral | Identifier):
            self.optimization_count += 1
            return inner

        node.expression = inner
        return node

    # Pass-through methods for other expression types
    def visit_boolean_literal(self, node: BooleanLiteral) -> BooleanLiteral:
        return node

    def visit_integer_literal(self, node: IntegerLiteral) -> IntegerLiteral:
        return node

    def visit_identifier(self, node: Identifier) -> Identifier:
        return node

    def visit_string_identifier(self, node: Any) -> Any:
        return node

    def visit_string_count(self, node: Any) -> Any:
        return node

    def visit_string_offset(self, node: Any) -> Any:
        if getattr(node, "index", None) is not None:
            node.index = self.visit(node.index)
        return node

    def visit_string_length(self, node: Any) -> Any:
        if getattr(node, "index", None) is not None:
            node.index = self.visit(node.index)
        return node

    def visit_double_literal(self, node: Any) -> Any:
        return node

    def visit_string_literal(self, node: Any) -> Any:
        return node

    def visit_array_access(self, node: Any) -> Any:
        if hasattr(node, "array"):
            node.array = self.visit(node.array)
        if hasattr(node, "index"):
            node.index = self.visit(node.index)
        return node

    def visit_member_access(self, node: Any) -> Any:
        if hasattr(node, "object"):
            node.object = self.visit(node.object)
        return node

    def visit_function_call(self, node: Any) -> Any:
        if hasattr(node, "arguments"):
            node.arguments = [self.visit(arg) for arg in node.arguments]
        if getattr(node, "receiver", None) is not None:
            node.receiver = self.visit(node.receiver)
        return node

    def visit_range_expression(self, node: Any) -> Any:
        if hasattr(node, "low"):
            node.low = self.visit(node.low)
        if hasattr(node, "high"):
            node.high = self.visit(node.high)
        return node

    def visit_set_expression(self, node: Any) -> Any:
        if hasattr(node, "elements"):
            node.elements = [self.visit(elem) for elem in node.elements]

        return node

    def visit_defined_expression(self, node: DefinedExpression) -> DefinedExpression:
        self._defined_expression_depth += 1
        try:
            node.expression = cast(Expression, self.visit(node.expression))
        finally:
            self._defined_expression_depth -= 1
        return node

    def visit_for_expression(self, node: Any) -> Any:
        node.quantifier = self._optimize_ast_value(node.quantifier)
        node.iterable = self.visit(node.iterable)
        node.body = self.visit(node.body)
        return node

    def visit_for_of_expression(self, node: Any) -> Any:
        node.quantifier = self._optimize_ast_value(node.quantifier)
        node.string_set = self._optimize_ast_value(node.string_set)
        if node.condition is not None:
            node.condition = self.visit(node.condition)
        return node

    def visit_of_expression(self, node: Any) -> Any:
        node.quantifier = self._optimize_ast_value(node.quantifier)
        node.string_set = self._optimize_ast_value(node.string_set)
        return node

    def _optimize_ast_value(self, value: Any) -> Any:
        if hasattr(value, "accept"):
            return self.visit(value)
        if isinstance(value, list):
            return [self._optimize_ast_value(item) for item in value]
        if isinstance(value, tuple):
            return tuple(self._optimize_ast_value(item) for item in value)
        if isinstance(value, set):
            return {self._optimize_ast_value(item) for item in value}
        if isinstance(value, frozenset):
            return frozenset(self._optimize_ast_value(item) for item in value)
        return value

    def visit_at_expression(self, node: Any) -> Any:
        if hasattr(node, "string_id"):
            node.string_id = self._optimize_ast_value(node.string_id)
        if hasattr(node, "offset"):
            node.offset = self.visit(node.offset)
        return node

    def visit_in_expression(self, node: Any) -> Any:
        if hasattr(node, "subject"):
            node.subject = self._optimize_ast_value(node.subject)
        if hasattr(node, "range"):
            node.range = self.visit(node.range)
            if _is_empty_integer_range(node.range):
                self.optimization_count += 1
                return BooleanLiteral(value=False)
        return node

    # Rule-level methods (not used for expression optimization)
    def visit_yara_file(self, node: Any) -> Any:
        return node

    def visit_rule(self, node: Any) -> Any:
        return node

    def visit_import(self, node: Any) -> Any:
        return node

    def visit_include(self, node: Any) -> Any:
        return node

    def visit_tag(self, node: Any) -> Any:
        return node

    def visit_meta(self, node: Any) -> Any:
        return node

    def visit_plain_string(self, node: Any) -> Any:
        return node

    def visit_hex_string(self, node: Any) -> Any:
        return node

    def visit_regex_string(self, node: Any) -> Any:
        return node
