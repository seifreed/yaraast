"""YARA-X specific AST nodes."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from yaraast.ast.base import ASTNode
from yaraast.ast.expressions import Expression

if TYPE_CHECKING:
    from yaraast.ast.conditions import Condition


@dataclass
class WithStatement(ASTNode):
    """YARA-X 'with' statement for declaring local variables.

    Example:
        with $a = "test", $b = 10:
            $a matches /test/ and #b > 5
    """

    declarations: list[WithDeclaration]
    body: Condition

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_with_statement(self)


@dataclass
class WithDeclaration(ASTNode):
    """Single declaration in a with statement."""

    identifier: str  # Variable name (e.g., $a)
    value: Expression  # Initial value

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_with_declaration(self)


@dataclass
class ArrayComprehension(Expression):
    """Array comprehension expression.

    Examples:
        [x * 2 for x in (1, 2, 3)]
        [s for s in strings if s matches /test/]
    """

    expression: Expression | None = None  # Expression to evaluate for each element
    variable: str = ""  # Loop variable name
    iterable: Expression | None = None  # Iterable to loop over
    condition: Expression | None = None  # Optional filter condition

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_array_comprehension(self)


@dataclass
class DictComprehension(Expression):
    """Dictionary comprehension expression.

    Examples:
        {k: v * 2 for k, v in some_dict}
        {s: #s for s in strings if #s > 0}
    """

    key_expression: Expression | None = None  # Expression for dictionary key
    value_expression: Expression | None = None  # Expression for dictionary value
    key_variable: str = ""  # Key variable name (or same as value_variable for single var)
    value_variable: str | None = None  # Value variable name (None if single var)
    iterable: Expression | None = None  # Iterable to loop over
    condition: Expression | None = None  # Optional filter condition

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_dict_comprehension(self)


@dataclass
class TupleExpression(Expression):
    """Tuple expression.

    Examples:
        (1, 2, 3)
        ("a", "b", "c")
    """

    elements: list[Expression]

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_tuple_expression(self)


@dataclass
class TupleIndexing(Expression):
    """Tuple indexing expression.

    Examples:
        my_tuple[0]  # First element
        my_tuple[-1]  # Last element
        result[1]  # Second element of function result
    """

    tuple_expr: Expression  # The tuple to index
    index: Expression  # Index (can be negative)

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_tuple_indexing(self)


@dataclass
class ListExpression(Expression):
    """List/array literal expression.

    Examples:
        [1, 2, 3]
        ["a", "b", "c"]
    """

    elements: list[Expression]

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_list_expression(self)


@dataclass
class DictExpression(Expression):
    """Dictionary literal expression.

    Examples:
        {"key1": "value1", "key2": "value2"}
        {1: "one", 2: "two"}
    """

    items: list[DictItem]

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_dict_expression(self)


@dataclass
class DictItem(ASTNode):
    """Single key-value pair in a dictionary."""

    key: Expression
    value: Expression

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_dict_item(self)


@dataclass
class SliceExpression(Expression):
    """Slice expression for arrays/strings.

    Examples:
        my_array[1:5]
        my_string[:-1]
        data[::2]
    """

    target: Expression
    start: Expression | None = None
    stop: Expression | None = None
    step: Expression | None = None

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_slice_expression(self)


@dataclass
class LambdaExpression(Expression):
    """Lambda/anonymous function expression.

    Examples:
        lambda x: x * 2
        lambda s: s matches /test/
    """

    parameters: list[str]
    body: Expression

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_lambda_expression(self)


@dataclass
class PatternMatch(Expression):
    """Pattern matching expression (YARA-X extended syntax).

    Examples:
        match value {
            1 => "one",
            2 => "two",
            _ => "other"
        }
    """

    value: Expression
    cases: list[MatchCase]
    default: Expression | None = None

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_pattern_match(self)


@dataclass
class MatchCase(ASTNode):
    """Single case in a pattern match."""

    pattern: Expression  # Pattern to match
    result: Expression  # Result if pattern matches

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_match_case(self)


@dataclass
class SpreadOperator(Expression):
    """Spread operator for unpacking iterables.

    Examples:
        [...array1, ...array2]
        {**dict1, **dict2}
    """

    expression: Expression
    is_dict: bool = False  # True for dict spread (**), False for array spread (...)

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_spread_operator(self)
