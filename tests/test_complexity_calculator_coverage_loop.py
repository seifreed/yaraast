"""Regression tests targeting uncovered lines in complexity_calculator.py.

Copyright (c) 2026 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.

Target: yaraast/metrics/complexity_calculator.py
Missing before this file:
  line 41  -- _calculate_string_set_value fallback (non-str, non-accept, non-collection)
  lines 179-184  -- visit_array_comprehension
  lines 187-192  -- visit_dict_comprehension
  line 195   -- visit_tuple_expression
  line 198   -- visit_tuple_indexing
  line 204   -- visit_dict_expression
  line 207   -- visit_dict_item
  lines 210-214  -- visit_slice_expression
  line 217   -- visit_lambda_expression
  line 229   -- visit_spread_operator
"""

from __future__ import annotations

from yaraast.ast.expressions import (
    FunctionCall,
    Identifier,
    IntegerLiteral,
    StringLiteral,
)
from yaraast.metrics.complexity_calculator import ComplexityCalculator
from yaraast.yarax.ast_nodes import (
    ArrayComprehension,
    DictComprehension,
    DictExpression,
    DictItem,
    LambdaExpression,
    SliceExpression,
    SpreadOperator,
    TupleExpression,
    TupleIndexing,
)

# ---------------------------------------------------------------------------
# Helper: fresh calculator instance used by every test below
# ---------------------------------------------------------------------------


def _calc() -> ComplexityCalculator:
    return ComplexityCalculator()


# ---------------------------------------------------------------------------
# line 41 — _calculate_string_set_value fallback branch
# ---------------------------------------------------------------------------


def test_string_set_value_fallback_for_non_collection_scalar() -> None:
    """_calculate_string_set_value returns 1 for any value that is not a str,
    not an ASTNode, and not a list/tuple/set/frozenset (line 41).

    Integers and floats are the simplest real scalars that reach the
    else-branch and return the literal 1.
    """
    calc = _calc()

    # Integer: not str, not accept-able, not a collection
    assert calc._calculate_string_set_value(99) == 1

    # Float: same path
    assert calc._calculate_string_set_value(2.71) == 1


# ---------------------------------------------------------------------------
# lines 179-184 — visit_array_comprehension
# ---------------------------------------------------------------------------


def test_array_comprehension_no_optional_children() -> None:
    """visit_array_comprehension base complexity is 5 when expression,
    iterable, and condition are all None.
    """
    calc = _calc()
    node = ArrayComprehension(variable="x")
    # Base complexity = 5; no optional children contribute anything
    assert calc.calculate(node) == 5


def test_array_comprehension_with_all_children() -> None:
    """visit_array_comprehension accumulates child complexities when all
    optional children are present.

    Base 5
    + expression=IntegerLiteral(1) via _calculate_ast_value -> 1
    + iterable=Identifier('arr')  via _calculate_ast_value -> 1
    + condition=IntegerLiteral(1) via _calculate_ast_value -> 1
    = 8
    """
    calc = _calc()
    node = ArrayComprehension(
        expression=IntegerLiteral(value=1),
        variable="x",
        iterable=Identifier(name="arr"),
        condition=IntegerLiteral(value=1),
    )
    assert calc.calculate(node) == 8


# ---------------------------------------------------------------------------
# lines 187-192 — visit_dict_comprehension
# ---------------------------------------------------------------------------


def test_dict_comprehension_minimal() -> None:
    """visit_dict_comprehension base complexity is 6 with all optional
    children absent.
    """
    calc = _calc()
    node = DictComprehension(key_variable="k")
    assert calc.calculate(node) == 6


def test_dict_comprehension_with_all_children() -> None:
    """visit_dict_comprehension accumulates key_expression, value_expression,
    iterable, and condition contributions.

    Base 6
    + key_expression=StringLiteral   -> 1
    + value_expression=IntegerLiteral -> 1
    + iterable=Identifier            -> 1
    + condition=IntegerLiteral        -> 1
    = 10
    """
    calc = _calc()
    node = DictComprehension(
        key_expression=StringLiteral(value="k"),
        value_expression=IntegerLiteral(value=1),
        key_variable="k",
        iterable=Identifier(name="mapping"),
        condition=IntegerLiteral(value=1),
    )
    assert calc.calculate(node) == 10


# ---------------------------------------------------------------------------
# line 195 — visit_tuple_expression
# ---------------------------------------------------------------------------


def test_tuple_expression_sums_element_complexities() -> None:
    """visit_tuple_expression returns 1 (base) plus the sum of element
    complexities via _calculate_ast_value.

    Two IntegerLiterals each contribute 1 -> total = 1 + 1 + 1 = 3.
    """
    calc = _calc()
    node = TupleExpression(elements=[IntegerLiteral(value=7), IntegerLiteral(value=42)])
    assert calc.calculate(node) == 3


def test_tuple_expression_single_element() -> None:
    """visit_tuple_expression with one element: 1 (base) + 1 (element) = 2."""
    calc = _calc()
    node = TupleExpression(elements=[StringLiteral(value="hello")])
    assert calc.calculate(node) == 2


# ---------------------------------------------------------------------------
# line 198 — visit_tuple_indexing
# ---------------------------------------------------------------------------


def test_tuple_indexing_complexity() -> None:
    """visit_tuple_indexing returns 1 + tuple_expr + index complexities.

    FunctionCall(no receiver, no args) = 2
    IntegerLiteral = 1
    Total = 1 + 2 + 1 = 4
    """
    calc = _calc()
    tuple_expr = FunctionCall(function="get_tuple", arguments=[])
    index = IntegerLiteral(value=0)
    node = TupleIndexing(tuple_expr=tuple_expr, index=index)
    assert calc.calculate(node) == 4


# ---------------------------------------------------------------------------
# line 204 — visit_dict_expression
# ---------------------------------------------------------------------------


def test_dict_expression_with_items() -> None:
    """visit_dict_expression returns 1 + sum of DictItem complexities via
    _calculate_ast_value.

    DictItem(key=StringLiteral, value=IntegerLiteral):
      visit_dict_item = 1 + 1 + 1 = 3
    DictExpression with one item = 1 + 3 = 4
    """
    calc = _calc()
    item = DictItem(key=StringLiteral(value="key"), value=IntegerLiteral(value=1))
    node = DictExpression(items=[item])
    assert calc.calculate(node) == 4


def test_dict_expression_empty() -> None:
    """visit_dict_expression with empty items list returns 1 (base only)."""
    calc = _calc()
    node = DictExpression(items=[])
    assert calc.calculate(node) == 1


# ---------------------------------------------------------------------------
# line 207 — visit_dict_item
# ---------------------------------------------------------------------------


def test_dict_item_complexity() -> None:
    """visit_dict_item returns 1 + key complexity + value complexity.

    key=StringLiteral -> 1, value=IntegerLiteral -> 1
    Total = 1 + 1 + 1 = 3
    """
    calc = _calc()
    node = DictItem(key=StringLiteral(value="name"), value=IntegerLiteral(value=99))
    assert calc.calculate(node) == 3


# ---------------------------------------------------------------------------
# lines 210-214 — visit_slice_expression
# ---------------------------------------------------------------------------


def test_slice_expression_target_only() -> None:
    """visit_slice_expression with None start/stop/step contributes only
    1 (base) + target complexity.

    _calculate_ast_value(None) returns 0 for each None optional.
    Identifier target = 1, so total = 1 + 1 = 2.
    """
    calc = _calc()
    node = SliceExpression(target=Identifier(name="data"))
    assert calc.calculate(node) == 2


def test_slice_expression_full() -> None:
    """visit_slice_expression with all children present.

    Base 1
    + target=Identifier -> 1
    + start=IntegerLiteral(0) -> 1
    + stop=IntegerLiteral(5) -> 1
    + step=IntegerLiteral(1) -> 1
    = 5
    """
    calc = _calc()
    node = SliceExpression(
        target=Identifier(name="data"),
        start=IntegerLiteral(value=0),
        stop=IntegerLiteral(value=5),
        step=IntegerLiteral(value=1),
    )
    assert calc.calculate(node) == 5


def test_slice_expression_partial_children() -> None:
    """visit_slice_expression with only start set (stop and step None).

    Base 1
    + target=Identifier -> 1
    + start=IntegerLiteral(2) -> 1
    + stop=None -> 0
    + step=None -> 0
    = 3
    """
    calc = _calc()
    node = SliceExpression(
        target=Identifier(name="buf"),
        start=IntegerLiteral(value=2),
    )
    assert calc.calculate(node) == 3


# ---------------------------------------------------------------------------
# line 217 — visit_lambda_expression
# ---------------------------------------------------------------------------


def test_lambda_expression_complexity() -> None:
    """visit_lambda_expression returns 2 + body complexity.

    body=IntegerLiteral -> 1, so total = 2 + 1 = 3.
    """
    calc = _calc()
    node = LambdaExpression(parameters=["x"], body=IntegerLiteral(value=0))
    assert calc.calculate(node) == 3


def test_lambda_expression_complex_body() -> None:
    """visit_lambda_expression propagates nested body complexity.

    body=SliceExpression(target=Identifier) -> 2 (from test above),
    so total = 2 + 2 = 4.
    """
    calc = _calc()
    body = SliceExpression(target=Identifier(name="arr"))
    node = LambdaExpression(parameters=["s"], body=body)
    assert calc.calculate(node) == 4


# ---------------------------------------------------------------------------
# line 229 — visit_spread_operator
# ---------------------------------------------------------------------------


def test_spread_operator_complexity() -> None:
    """visit_spread_operator returns 1 + inner expression complexity.

    expression=Identifier -> 1, so total = 1 + 1 = 2.
    """
    calc = _calc()
    node = SpreadOperator(expression=Identifier(name="items"))
    assert calc.calculate(node) == 2


def test_spread_operator_dict_flag() -> None:
    """visit_spread_operator complexity is identical regardless of is_dict.

    The is_dict flag affects code generation, not complexity score.
    expression=Identifier -> 1, so total = 1 + 1 = 2 in both cases.
    """
    calc = _calc()
    array_spread = SpreadOperator(expression=Identifier(name="arr"), is_dict=False)
    dict_spread = SpreadOperator(expression=Identifier(name="d"), is_dict=True)
    assert calc.calculate(array_spread) == 2
    assert calc.calculate(dict_spread) == 2
