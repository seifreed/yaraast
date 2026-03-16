from __future__ import annotations

from yaraast.ast.expressions import (
    BooleanLiteral,
    Identifier,
    IntegerLiteral,
    MemberAccess,
    StringLiteral,
)
from yaraast.yarax.ast_nodes import (
    ArrayComprehension,
    DictComprehension,
    LambdaExpression,
    MatchCase,
    PatternMatch,
    SliceExpression,
    TupleExpression,
    TupleIndexing,
)
from yaraast.yarax.generator import YaraXGenerator


def test_yarax_generator_covers_empty_single_and_optional_sections() -> None:
    gen = YaraXGenerator()

    assert gen.visit(TupleExpression(elements=[])) == "()"
    assert gen.visit(TupleExpression(elements=[IntegerLiteral(1)])) == "(1,)"

    one_var_dict_comp = DictComprehension(
        key_expression=Identifier(name="k"),
        value_expression=Identifier(name="k"),
        key_variable="k",
        iterable=Identifier(name="items"),
    )
    assert gen.visit(one_var_dict_comp) == "{k: k for k in items}"

    conditional_dict_comp = DictComprehension(
        key_expression=Identifier(name="k"),
        value_expression=Identifier(name="v"),
        key_variable="k",
        value_variable="v",
        iterable=Identifier(name="items"),
        condition=Identifier(name="keep"),
    )
    assert gen.visit(conditional_dict_comp) == "{k: v for k, v in items if keep}"

    no_if_array_comp = ArrayComprehension(
        expression=Identifier(name="x"),
        variable="x",
        iterable=Identifier(name="items"),
    )
    assert gen.visit(no_if_array_comp) == "[x for x in items]"

    no_default_match = PatternMatch(
        value=Identifier(name="x"),
        cases=[MatchCase(pattern=IntegerLiteral(1), result=BooleanLiteral(True))],
        default=None,
    )
    assert "_ =>" not in gen.visit(no_default_match)

    assert gen.visit(LambdaExpression(parameters=[], body=IntegerLiteral(1))) == "lambda: 1"


def test_yarax_generator_covers_tuple_indexing_slice_and_parenthesized_target() -> None:
    gen = YaraXGenerator()

    wrapped = TupleIndexing(
        tuple_expr=MemberAccess(object=Identifier(name="obj"), member="tuple"),
        index=IntegerLiteral(0),
    )
    assert gen.visit(wrapped) == "(obj.tuple)[0]"

    no_stop = SliceExpression(
        target=Identifier(name="arr"), start=IntegerLiteral(1), stop=None, step=None
    )
    assert gen.visit(no_stop) == "arr[1]"

    with_step = SliceExpression(
        target=Identifier(name="arr"),
        start=IntegerLiteral(1),
        stop=IntegerLiteral(4),
        step=IntegerLiteral(2),
    )
    assert gen.visit(with_step) == "arr[1:4:2]"

    no_start_but_step = SliceExpression(
        target=Identifier(name="arr"),
        start=None,
        stop=IntegerLiteral(4),
        step=IntegerLiteral(2),
    )
    assert gen.visit(no_start_but_step) == "arr[:4:2]"

    case = MatchCase(pattern=StringLiteral("a"), result=StringLiteral("b"))
    assert gen.visit(case) == '"a" => "b"'
