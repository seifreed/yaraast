from __future__ import annotations

import pytest

from yaraast.ast.base import ASTNode
from yaraast.ast.expressions import (
    ArrayAccess,
    BinaryExpression,
    BooleanLiteral,
    FunctionCall,
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
    WithDeclaration,
    WithStatement,
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


def test_yarax_generator_allows_contextual_local_identifiers() -> None:
    gen = YaraXGenerator()

    with_stmt = WithStatement(
        declarations=[WithDeclaration(identifier="as", value=IntegerLiteral(1))],
        body=Identifier("as"),
    )
    assert gen.visit(with_stmt) == "with as = 1: as"

    array_comp = ArrayComprehension(
        expression=Identifier("as"),
        variable="as",
        iterable=Identifier("items"),
        condition=Identifier("as"),
    )
    assert gen.visit(array_comp) == "[as for as in items if as]"

    dict_comp = DictComprehension(
        key_expression=Identifier("as"),
        value_expression=Identifier("include"),
        key_variable="as",
        value_variable="include",
        iterable=Identifier("items"),
        condition=Identifier("include"),
    )
    assert gen.visit(dict_comp) == "{as: include for as, include in items if include}"

    lambda_expr = LambdaExpression(
        parameters=["as", "include"],
        body=BinaryExpression(Identifier("as"), "+", Identifier("include")),
    )
    assert gen.visit(lambda_expr) == "lambda as, include: as + include"


def test_yarax_generator_parenthesizes_compound_function_call_receivers() -> None:
    compound_receiver = BinaryExpression(
        left=Identifier(name="a"),
        operator="+",
        right=Identifier(name="b"),
    )
    call = FunctionCall(
        function="map",
        arguments=[],
        receiver=compound_receiver,
    )

    assert YaraXGenerator().visit(call) == "(a + b).map()"
    assert YaraXGenerator().visit(ArrayAccess(compound_receiver, IntegerLiteral(0))) == (
        "(a + b)[0]"
    )
    assert YaraXGenerator().visit(MemberAccess(compound_receiver, "field")) == "(a + b).field"


@pytest.mark.parametrize(
    "node",
    [
        WithDeclaration(identifier="bad-name", value=IntegerLiteral(1)),
        WithStatement(
            declarations=[WithDeclaration(identifier="bad-name", value=IntegerLiteral(1))],
            body=BooleanLiteral(True),
        ),
        LambdaExpression(parameters=["bad-name"], body=IntegerLiteral(1)),
        ArrayComprehension(
            expression=Identifier("x"),
            variable="bad-name",
            iterable=Identifier("items"),
        ),
        DictComprehension(
            key_expression=Identifier("k"),
            value_expression=Identifier("v"),
            key_variable="bad-key",
            iterable=Identifier("items"),
        ),
        DictComprehension(
            key_expression=Identifier("k"),
            value_expression=Identifier("v"),
            key_variable="k",
            value_variable="bad-value",
            iterable=Identifier("items"),
        ),
    ],
)
def test_yarax_generator_rejects_invalid_local_identifiers(node: ASTNode) -> None:
    with pytest.raises(ValueError, match=r"Invalid .* identifier"):
        YaraXGenerator().visit(node)


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
    assert gen.visit(no_stop) == "arr[1:]"

    full_slice = SliceExpression(target=Identifier(name="arr"), start=None, stop=None, step=None)
    assert gen.visit(full_slice) == "arr[:]"

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

    compound_target = SliceExpression(
        target=BinaryExpression(
            left=Identifier(name="a"),
            operator="+",
            right=Identifier(name="b"),
        ),
        start=IntegerLiteral(0),
        stop=IntegerLiteral(1),
    )
    assert gen.visit(compound_target) == "(a + b)[0:1]"

    case = MatchCase(pattern=StringLiteral("a"), result=StringLiteral("b"))
    assert gen.visit(case) == '"a" => "b"'
