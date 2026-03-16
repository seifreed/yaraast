"""Real tests for YARA-X parser/generator (no mocks)."""

from __future__ import annotations

from textwrap import dedent

from yaraast.ast.expressions import Identifier, IntegerLiteral, StringLiteral
from yaraast.yarax.ast_nodes import (
    ArrayComprehension,
    DictComprehension,
    DictExpression,
    DictItem,
    LambdaExpression,
    ListExpression,
    MatchCase,
    PatternMatch,
    SpreadOperator,
    TupleExpression,
    WithDeclaration,
    WithStatement,
)
from yaraast.yarax.generator import YaraXGenerator
from yaraast.yarax.parser import YaraXParser


def test_yarax_with_statement_parse() -> None:
    code = dedent(
        """
        rule r {
            strings:
                $a = "abc"
            condition:
                with $x = #a:
                    $x > 0 and $a
        }
        """,
    )

    ast = YaraXParser(code).parse()
    generated = YaraXGenerator().generate(ast)

    assert "with $x" in generated
    assert "$x > 0" in generated


def test_yarax_with_statement_accepts_identifier_variable() -> None:
    code = dedent(
        """
        rule r {
            condition:
                with pdfpos = 0x9f000:
                    pdfpos > 0
        }
        """,
    )

    ast = YaraXParser(code).parse()
    generated = YaraXGenerator().generate(ast)

    assert "with pdfpos = 0x9f000" in generated
    assert "pdfpos > 0" in generated


def test_yarax_generator_features() -> None:
    gen = YaraXGenerator()

    array_comp = ArrayComprehension(
        expression=Identifier(name="x"),
        variable="x",
        iterable=TupleExpression(elements=[IntegerLiteral(1), IntegerLiteral(2)]),
    )
    dict_comp = DictComprehension(
        key_expression=Identifier(name="k"),
        value_expression=Identifier(name="v"),
        key_variable="k",
        value_variable="v",
        iterable=Identifier(name="items"),
    )
    list_expr = ListExpression(elements=[IntegerLiteral(1), SpreadOperator(Identifier(name="arr"))])
    dict_expr = DictExpression(items=[DictItem(key=StringLiteral("k"), value=StringLiteral("v"))])
    lambda_expr = LambdaExpression(parameters=["x"], body=Identifier(name="x"))
    match_expr = PatternMatch(
        value=Identifier(name="val"),
        cases=[MatchCase(pattern=IntegerLiteral(1), result=StringLiteral("one"))],
        default=StringLiteral("other"),
    )
    with_stmt = WithStatement(
        declarations=[WithDeclaration(identifier="$x", value=IntegerLiteral(1))],
        body=Identifier(name="x"),
    )

    assert "for x in" in gen.visit(array_comp)
    assert "for k, v in items" in gen.visit(dict_comp)
    assert "...arr" in gen.visit(list_expr)
    assert '{"k": "v"}' in gen.visit(dict_expr)
    assert "lambda x:" in gen.visit(lambda_expr)
    assert "match val" in gen.visit(match_expr)
    assert "with $x = 1" in gen.visit(with_stmt)
