"""Additional YARA-X generator coverage (no mocks)."""

from __future__ import annotations

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import BooleanLiteral, Identifier, IntegerLiteral, StringLiteral
from yaraast.ast.rules import Rule
from yaraast.yarax.ast_nodes import (
    ArrayComprehension,
    DictComprehension,
    DictExpression,
    DictItem,
    LambdaExpression,
    ListExpression,
    MatchCase,
    PatternMatch,
    SliceExpression,
    SpreadOperator,
    TupleExpression,
    TupleIndexing,
    WithDeclaration,
    WithStatement,
)
from yaraast.yarax.generator import YaraXGenerator


def test_yarax_generator_various_nodes() -> None:
    with_stmt = WithStatement(
        declarations=[
            WithDeclaration(identifier="$a", value=StringLiteral("x")),
        ],
        body=BooleanLiteral(True),
    )
    list_expr = ListExpression(
        elements=[IntegerLiteral(1), SpreadOperator(expression=Identifier("arr"))],
    )
    dict_expr = DictExpression(
        items=[
            DictItem(key=StringLiteral("k"), value=IntegerLiteral(1)),
            DictItem(
                key=StringLiteral("__spread__"),
                value=SpreadOperator(expression=Identifier("d"), is_dict=True),
            ),
        ],
    )
    array_comp = ArrayComprehension(
        expression=Identifier("x"),
        variable="x",
        iterable=Identifier("items"),
        condition=Identifier("x"),
    )
    dict_comp = DictComprehension(
        key_expression=Identifier("k"),
        value_expression=Identifier("v"),
        key_variable="k",
        value_variable="v",
        iterable=Identifier("data"),
    )
    lam = LambdaExpression(parameters=["x"], body=Identifier("x"))
    match_expr = PatternMatch(
        value=IntegerLiteral(1),
        cases=[MatchCase(pattern=IntegerLiteral(1), result=IntegerLiteral(2))],
        default=IntegerLiteral(0),
    )
    slice_expr = SliceExpression(target=Identifier("arr"), start=None, stop=IntegerLiteral(2))
    tuple_expr = TupleExpression(elements=[IntegerLiteral(1), IntegerLiteral(2)])
    tuple_index = TupleIndexing(tuple_expr=tuple_expr, index=IntegerLiteral(0))

    rule = Rule(
        name="yarax_rule",
        condition=with_stmt,
        strings=[],
    )
    file = YaraFile(rules=[rule])
    gen = YaraXGenerator()

    code = gen.generate(file)
    assert 'with $a = "x": true' in code

    assert gen.visit(list_expr)
    assert gen.visit(dict_expr)
    assert gen.visit(array_comp)
    assert gen.visit(dict_comp)
    assert gen.visit(lam).startswith("lambda")
    assert "match" in gen.visit(match_expr)
    assert "[" in gen.visit(slice_expr)
    assert "(" in gen.visit(tuple_expr)
    assert "[" in gen.visit(tuple_index)
