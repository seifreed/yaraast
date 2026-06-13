"""YARA-X specific AST nodes."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from yaraast.ast.base import (
    ASTNode,
    _require_ast_node,
    _require_ast_node_sequence_type,
    _VisitorType,
    require_string,
)
from yaraast.ast.conditions import Condition
from yaraast.ast.expressions import Expression


def _require_nonempty_local_identifier(
    value: Any,
    empty_context: str,
    *,
    allow_string_identifier: bool = False,
) -> str:
    identifier = require_string(value, "Local variable name")
    if not identifier.strip():
        msg = f"{empty_context} must not be empty"
        raise ValueError(msg)
    from yaraast.shared.local_scope import validate_local_identifier

    validate_local_identifier(identifier, allow_string_identifier=allow_string_identifier)
    return identifier


def _require_optional_nonempty_local_identifier(
    value: Any,
    empty_context: str,
    *,
    allow_string_identifier: bool = False,
) -> str | None:
    if value is None:
        return None
    return _require_nonempty_local_identifier(
        value,
        empty_context,
        allow_string_identifier=allow_string_identifier,
    )


def _validate_child_structure(value: Any) -> None:
    validate_structure = getattr(value, "validate_structure", None)
    if callable(validate_structure):
        validate_structure()


def _validate_child_sequence(values: list[ASTNode]) -> None:
    for value in values:
        _validate_child_structure(value)


@dataclass
class WithStatement(Condition):
    """YARA-X 'with' statement for declaring local variables.

    Example:
        with $a = "test", $b = 10:
            $a matches /test/ and #b > 5
    """

    declarations: list[WithDeclaration]
    body: Expression

    def validate_structure(self) -> None:
        declarations = _require_ast_node_sequence_type(
            self.declarations,
            "WithStatement.declarations",
            WithDeclaration,
            "WithDeclaration",
        )
        _validate_child_sequence(declarations)
        _validate_child_structure(_require_ast_node(self.body, "WithStatement.body"))

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_with_statement(self)


@dataclass
class WithDeclaration(ASTNode):
    """Single declaration in a with statement."""

    identifier: str  # Variable name (e.g., $a)
    value: Expression  # Initial value

    def validate_structure(self) -> None:
        _require_nonempty_local_identifier(
            self.identifier,
            "WithDeclaration identifier",
            allow_string_identifier=True,
        )
        _validate_child_structure(_require_ast_node(self.value, "WithDeclaration.value"))

    def accept(self, visitor: _VisitorType) -> Any:
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

    def validate_structure(self) -> None:
        if self.expression is not None:
            _validate_child_structure(
                _require_ast_node(self.expression, "ArrayComprehension.expression")
            )
        _require_nonempty_local_identifier(self.variable, "ArrayComprehension variable")
        if self.iterable is not None:
            _validate_child_structure(
                _require_ast_node(self.iterable, "ArrayComprehension.iterable")
            )
        if self.condition is not None:
            _validate_child_structure(
                _require_ast_node(self.condition, "ArrayComprehension.condition")
            )

    def accept(self, visitor: _VisitorType) -> Any:
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

    def validate_structure(self) -> None:
        if self.key_expression is not None:
            _validate_child_structure(
                _require_ast_node(self.key_expression, "DictComprehension.key_expression")
            )
        if self.value_expression is not None:
            _validate_child_structure(
                _require_ast_node(self.value_expression, "DictComprehension.value_expression")
            )
        _require_nonempty_local_identifier(self.key_variable, "DictComprehension key_variable")
        _require_optional_nonempty_local_identifier(
            self.value_variable,
            "DictComprehension value_variable",
        )
        if self.iterable is not None:
            _validate_child_structure(
                _require_ast_node(self.iterable, "DictComprehension.iterable")
            )
        if self.condition is not None:
            _validate_child_structure(
                _require_ast_node(self.condition, "DictComprehension.condition")
            )

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_dict_comprehension(self)


@dataclass
class TupleExpression(Expression):
    """Tuple expression.

    Examples:
        (1, 2, 3)
        ("a", "b", "c")
    """

    elements: list[Expression]

    def validate_structure(self) -> None:
        elements = _require_ast_node_sequence_type(
            self.elements,
            "TupleExpression.elements",
            Expression,
            "Expression",
        )
        _validate_child_sequence(elements)

    def accept(self, visitor: _VisitorType) -> Any:
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

    def validate_structure(self) -> None:
        from yaraast.ast.expressions import FunctionCall, Identifier, ParenthesesExpression

        _validate_child_structure(_require_ast_node(self.tuple_expr, "TupleIndexing.tuple_expr"))
        _validate_child_structure(_require_ast_node(self.index, "TupleIndexing.index"))
        if isinstance(self.tuple_expr, FunctionCall | Identifier | TupleExpression):
            return
        if isinstance(self.tuple_expr, ParenthesesExpression) and isinstance(
            self.tuple_expr.expression, FunctionCall | TupleExpression
        ):
            return
        msg = (
            "TupleIndexing.tuple_expr must be a function call or tuple expression "
            "for YARA-X output"
        )
        raise ValueError(msg)

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_tuple_indexing(self)


@dataclass
class ListExpression(Expression):
    """List/array literal expression.

    Examples:
        [1, 2, 3]
        ["a", "b", "c"]
    """

    elements: list[Expression]

    def validate_structure(self) -> None:
        elements = _require_ast_node_sequence_type(
            self.elements,
            "ListExpression.elements",
            Expression,
            "Expression",
        )
        _validate_child_sequence(elements)

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_list_expression(self)


@dataclass
class DictExpression(Expression):
    """Dictionary literal expression.

    Examples:
        {"key1": "value1", "key2": "value2"}
        {1: "one", 2: "two"}
    """

    items: list[DictItem]

    def validate_structure(self) -> None:
        items = _require_ast_node_sequence_type(
            self.items,
            "DictExpression.items",
            DictItem,
            "DictItem",
        )
        _validate_child_sequence(items)

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_dict_expression(self)


@dataclass
class DictItem(ASTNode):
    """Single key-value pair in a dictionary."""

    key: Expression
    value: Expression

    def validate_structure(self) -> None:
        _validate_child_structure(_require_ast_node(self.key, "DictItem.key"))
        _validate_child_structure(_require_ast_node(self.value, "DictItem.value"))

    def accept(self, visitor: _VisitorType) -> Any:
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

    def validate_structure(self) -> None:
        _validate_child_structure(_require_ast_node(self.target, "SliceExpression.target"))
        if self.start is not None:
            _validate_child_structure(_require_ast_node(self.start, "SliceExpression.start"))
        if self.stop is not None:
            _validate_child_structure(_require_ast_node(self.stop, "SliceExpression.stop"))
        if self.step is not None:
            _validate_child_structure(_require_ast_node(self.step, "SliceExpression.step"))

    def accept(self, visitor: _VisitorType) -> Any:
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

    def validate_structure(self) -> None:
        if not isinstance(self.parameters, list | tuple):
            msg = "LambdaExpression parameters must be a list or tuple"
            raise TypeError(msg)
        for parameter in self.parameters:
            _require_nonempty_local_identifier(parameter, "LambdaExpression parameters item")
        _validate_child_structure(_require_ast_node(self.body, "LambdaExpression.body"))

    def accept(self, visitor: _VisitorType) -> Any:
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

    def validate_structure(self) -> None:
        _validate_child_structure(_require_ast_node(self.value, "PatternMatch.value"))
        cases = _require_ast_node_sequence_type(
            self.cases,
            "PatternMatch.cases",
            MatchCase,
            "MatchCase",
        )
        _validate_child_sequence(cases)
        if self.default is not None:
            _validate_child_structure(_require_ast_node(self.default, "PatternMatch.default"))

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_pattern_match(self)


@dataclass
class MatchCase(ASTNode):
    """Single case in a pattern match."""

    pattern: Expression  # Pattern to match
    result: Expression  # Result if pattern matches

    def validate_structure(self) -> None:
        _validate_child_structure(_require_ast_node(self.pattern, "MatchCase.pattern"))
        _validate_child_structure(_require_ast_node(self.result, "MatchCase.result"))

    def accept(self, visitor: _VisitorType) -> Any:
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

    def validate_structure(self) -> None:
        _validate_child_structure(_require_ast_node(self.expression, "SpreadOperator.expression"))
        if not isinstance(self.is_dict, bool):
            msg = "SpreadOperator is_dict must be a boolean"
            raise TypeError(msg)

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_spread_operator(self)
