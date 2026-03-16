"""Additional branch coverage for complexity calculator (no mocks)."""

from __future__ import annotations

from yaraast.ast.conditions import (
    AtExpression,
    ForExpression,
    ForOfExpression,
    InExpression,
    OfExpression,
)
from yaraast.ast.expressions import (
    ArrayAccess,
    BinaryExpression,
    BooleanLiteral,
    DoubleLiteral,
    FunctionCall,
    Identifier,
    IntegerLiteral,
    MemberAccess,
    ParenthesesExpression,
    RangeExpression,
    RegexLiteral,
    SetExpression,
    StringCount,
    StringIdentifier,
    StringLength,
    StringLiteral,
    StringOffset,
    UnaryExpression,
)
from yaraast.ast.modules import DictionaryAccess
from yaraast.ast.operators import DefinedExpression, StringOperatorExpression
from yaraast.metrics.complexity_calculator import ComplexityCalculator


def test_complexity_calculator_core_and_branches() -> None:
    calc = ComplexityCalculator()

    assert calc.calculate(None) == 0
    assert calc.calculate(BooleanLiteral(value=True)) == 1
    assert calc.calculate(IntegerLiteral(value=1)) == 1
    assert calc.calculate(DoubleLiteral(value=1.25)) == 1
    assert calc.calculate(StringLiteral(value="x")) == 1
    assert calc.calculate(RegexLiteral(pattern="ab+", modifiers="i")) == 2
    assert calc.calculate(Identifier(name="x")) == 1
    assert calc.calculate(StringIdentifier(name="$a")) == 1

    and_expr = BinaryExpression(
        left=BooleanLiteral(value=True),
        operator="and",
        right=BooleanLiteral(value=False),
    )
    non_logical = BinaryExpression(
        left=IntegerLiteral(value=1),
        operator="+",
        right=IntegerLiteral(value=2),
    )
    assert calc.calculate(and_expr) >= 5
    assert calc.calculate(non_logical) >= 4

    unary = UnaryExpression(operator="not", operand=BooleanLiteral(value=True))
    assert calc.calculate(unary) >= 3

    fcall = FunctionCall(
        function="f",
        arguments=[IntegerLiteral(value=1), IntegerLiteral(value=2)],
    )
    assert calc.calculate(fcall) == 4

    assert calc.calculate(StringCount(string_id="a")) == 2
    assert calc.calculate(StringOffset(string_id="a")) == 2
    assert calc.calculate(StringOffset(string_id="a", index=IntegerLiteral(value=0))) == 3
    assert calc.calculate(StringLength(string_id="a")) == 2
    assert calc.calculate(StringLength(string_id="a", index=IntegerLiteral(value=0))) == 3

    for_expr = ForExpression(
        quantifier="any",
        variable="i",
        iterable=Identifier(name="arr"),
        body=BooleanLiteral(value=True),
    )
    assert calc.calculate(for_expr) >= 7

    for_of_node = ForOfExpression(
        quantifier="any",
        string_set=SetExpression(elements=[StringIdentifier(name="$a")]),
        condition=BooleanLiteral(value=True),
    )
    assert calc.calculate(for_of_node) >= 7

    for_of_list = ForOfExpression(
        quantifier="all",
        string_set=["$a", "$b"],
        condition=None,
    )
    assert calc.calculate(for_of_list) == 7

    for_of_raw = ForOfExpression(quantifier="all", string_set="them", condition=None)
    assert calc.calculate(for_of_raw) == 6

    of_expr_node = OfExpression(
        quantifier=StringLiteral(value="any"),
        string_set=SetExpression(elements=[StringIdentifier(name="$a")]),
    )
    assert calc.calculate(of_expr_node) >= 5

    of_expr_list = OfExpression(quantifier=StringLiteral(value="2"), string_set=["$a", "$b", "$c"])
    assert calc.calculate(of_expr_list) == 7

    set_expr = SetExpression(elements=[IntegerLiteral(value=1), IntegerLiteral(value=2)])
    assert calc.calculate(set_expr) == 3

    range_expr = RangeExpression(low=IntegerLiteral(value=1), high=IntegerLiteral(value=3))
    assert calc.calculate(range_expr) == 3

    arr = ArrayAccess(array=Identifier(name="arr"), index=IntegerLiteral(value=0))
    assert calc.calculate(arr) == 3

    member = MemberAccess(object=Identifier(name="obj"), member="x")
    assert calc.calculate(member) == 2

    par = ParenthesesExpression(expression=IntegerLiteral(value=9))
    assert calc.calculate(par) == 1


def test_complexity_calculator_misc_nodes() -> None:
    calc = ComplexityCalculator()

    assert calc.calculate(DefinedExpression(expression=Identifier(name="x"))) == 2
    assert (
        calc.calculate(
            StringOperatorExpression(
                left=Identifier(name="a"), operator="contains", right=StringLiteral(value="b")
            )
        )
        == 4
    )

    assert calc.calculate(AtExpression(string_id="$a", offset=IntegerLiteral(value=10))) == 3

    assert calc.calculate(InExpression(subject="$a", range=IntegerLiteral(value=5))) == 3

    d1 = DictionaryAccess(object=Identifier(name="obj"), key=StringLiteral(value="k"))
    assert calc.calculate(d1) == 3

    d2 = DictionaryAccess(object=Identifier(name="obj"), key="k")
    assert calc.calculate(d2) == 2
