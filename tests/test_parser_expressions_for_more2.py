"""Additional branch coverage for parser for/of helpers (no mocks)."""

from __future__ import annotations

import pytest

from yaraast.ast.conditions import ForExpression, ForOfExpression
from yaraast.ast.expressions import (
    BinaryExpression,
    BooleanLiteral,
    IntegerLiteral,
    MemberAccess,
    StringLiteral,
)
from yaraast.ast.modules import ModuleReference
from yaraast.lexer import Lexer
from yaraast.parser._shared import ParserError
from yaraast.parser.parser import Parser


def _expr_parser(text: str) -> Parser:
    parser = Parser("rule seed { condition: true }")
    parser.tokens = Lexer(text).tokenize()
    parser.current = 0
    return parser


def test_parse_for_expression_success_and_error_paths() -> None:
    node_any = _expr_parser("any i in (1) : ( true )")._parse_for_expression()
    assert isinstance(node_any, ForExpression)
    assert node_any.quantifier == "any"
    assert node_any.variable == "i"

    node_all = _expr_parser("all j in (2) : ( j > 0 )")._parse_for_expression()
    assert isinstance(node_all, ForExpression)
    assert node_all.quantifier == "all"
    assert node_all.variable == "j"

    node_n = _expr_parser("3 of them : ( true )")._parse_for_expression()
    assert isinstance(node_n, ForOfExpression)
    assert isinstance(node_n.quantifier, IntegerLiteral)
    assert node_n.quantifier.value == 3
    assert node_n.condition is not None

    node_for_of = _expr_parser("any of them : ( true )")._parse_for_expression()
    assert isinstance(node_for_of, ForOfExpression)
    assert node_for_of.quantifier == "any"
    assert node_for_of.condition is not None

    with pytest.raises(ParserError, match="Expected quantifier"):
        _expr_parser(":")._parse_for_expression()
    with pytest.raises(ParserError, match="Expected variable name"):
        _expr_parser("them")._parse_for_expression()
    with pytest.raises(ParserError, match="Expected variable name"):
        _expr_parser("any in 1 : ( true )")._parse_for_expression()
    with pytest.raises(ParserError, match="Expected ':' after string set"):
        _expr_parser("any of them")._parse_for_expression()
    with pytest.raises(ParserError, match="Expected ':' after string set"):
        _expr_parser("2 of ($a*)")._parse_for_expression()
    with pytest.raises(ParserError, match="Expected variable after ','"):
        _expr_parser("any i, in 1 : ( true )")._parse_for_expression()
    with pytest.raises(ParserError, match="Expected 'in' after variable"):
        _expr_parser("any i 1 : ( true )")._parse_for_expression()
    with pytest.raises(ParserError, match="Expected ':' after iterable"):
        _expr_parser("any i in values true")._parse_for_expression()
    with pytest.raises(ParserError, match="Expected '\\(' after ':'"):
        _expr_parser("any i in values : true )")._parse_for_expression()
    with pytest.raises(ParserError, match="Expected '\\)' after for body"):
        _expr_parser("any i in values : ( true")._parse_for_expression()
    with pytest.raises(ParserError, match="Expected '\\)' after condition"):
        _expr_parser("any of them : ( true")._parse_for_expression()
    with pytest.raises(ParserError, match="Expected '\\(' after ':'"):
        _expr_parser("any of them : true")._parse_for_expression()
    with pytest.raises(ParserError, match="Expected '\\(' after ':'"):
        _expr_parser("any of them :")._parse_for_expression()


def test_multi_variable_for_loop_round_trips() -> None:
    from yaraast.codegen.generator import CodeGenerator

    source = 'import "pe" rule r { condition: for any k,v in pe.version_info : ( k == "x" ) }'
    ast = Parser().parse(source)
    assert isinstance(ast.rules[0].condition, ForExpression)
    assert ast.rules[0].condition.variable == "k,v"

    generated = CodeGenerator().generate(ast)
    assert "for any k, v in pe.version_info" in generated

    reparsed = Parser().parse(generated)
    assert isinstance(reparsed.rules[0].condition, ForExpression)
    assert reparsed.rules[0].condition.variable == "k,v"


def test_yarax_for_loop_accepts_more_than_two_variables() -> None:
    from yaraast.codegen.generator import CodeGenerator

    source = """
rule r {
    condition:
        for any k, v, offset in rows : (offset > 0 and k == v)
}
"""

    ast = Parser().parse(source)
    condition = ast.rules[0].condition
    assert isinstance(condition, ForExpression)
    assert condition.variable == "k,v,offset"

    generated = CodeGenerator().generate(ast)
    assert "for any k, v, offset in rows" in generated

    reparsed = Parser().parse(generated)
    reparsed_condition = reparsed.rules[0].condition
    assert isinstance(reparsed_condition, ForExpression)
    assert reparsed_condition.variable == "k,v,offset"


def test_yarax_for_of_accepts_percentage_quantifier() -> None:
    from yaraast.codegen.generator import CodeGenerator

    source = """
rule r {
    strings:
        $a = "a"
    condition:
        for 10% of ($a*) : ($)
}
"""

    ast = Parser().parse(source)
    condition = ast.rules[0].condition
    assert isinstance(condition, ForOfExpression)
    assert condition.quantifier == "10%"

    generated = CodeGenerator().generate(ast)
    assert "for 10% of ($a*) : ($)" in generated

    reparsed = Parser().parse(generated)
    reparsed_condition = reparsed.rules[0].condition
    assert isinstance(reparsed_condition, ForOfExpression)
    assert reparsed_condition.quantifier == "10%"


@pytest.mark.parametrize("keyword", ["as", "include"])
def test_contextual_keyword_for_loop_variable_round_trips(keyword: str) -> None:
    from yaraast.codegen.generator import CodeGenerator

    yara = pytest.importorskip("yara")
    source = f"rule r {{ condition: for any {keyword} in (1, 2) : ({keyword} > 0) }}"
    yara.compile(source=source)

    ast = Parser().parse(source)
    condition = ast.rules[0].condition
    assert isinstance(condition, ForExpression)
    assert condition.variable == keyword

    generated = CodeGenerator().generate(ast)
    assert f"for any {keyword} in" in generated
    yara.compile(source=generated)


def test_parse_for_of_does_not_consume_outer_boolean_expression() -> None:
    ast = Parser().parse('rule r { strings: $a = "a" condition: for any of them : ($) and true }')
    condition = ast.rules[0].condition

    assert isinstance(condition, BinaryExpression)
    assert condition.operator == "and"
    assert isinstance(condition.left, ForOfExpression)
    assert isinstance(condition.right, BooleanLiteral)
    assert condition.right.value is True


@pytest.mark.parametrize(
    "quantifier",
    [
        "#a",
        "@a",
        "@a[1]",
        "!a",
        "uint8(0)",
        "filesize",
        "entrypoint",
        "#a + 1",
        "(1 + 1)",
        "1 & 2",
    ],
)
def test_for_loop_accepts_primary_expression_quantifier(quantifier: str) -> None:
    """libyara allows any primary expression as the loop quantifier."""
    source = f'rule r {{ strings: $a = "x" condition: for {quantifier} i in (1..2) : (@a[i] > 0) }}'
    ast = Parser().parse(source)
    condition = ast.rules[0].condition
    assert isinstance(condition, ForExpression)
    assert not isinstance(condition.quantifier, str)


def test_for_of_accepts_expression_quantifier() -> None:
    source = 'rule r { strings: $a = "x" $b = "y" condition: for #a of them : ($) }'
    ast = Parser().parse(source)
    condition = ast.rules[0].condition
    assert isinstance(condition, ForOfExpression)
    assert not isinstance(condition.quantifier, str)


@pytest.mark.parametrize("quantifier", ["-1", "~1"])
def test_for_of_rejects_negative_static_expression_quantifier(quantifier: str) -> None:
    source = f'rule r {{ strings: $a = "x" condition: for {quantifier} of them : ($) }}'
    with pytest.raises(ParserError, match="quantifier can not be negative"):
        Parser().parse(source)


def test_for_of_accepts_dynamic_negative_expression_quantifier() -> None:
    source = 'rule r { strings: $a = "x" condition: for -#a of them : ($) }'
    ast = Parser().parse(source)
    condition = ast.rules[0].condition
    assert isinstance(condition, ForOfExpression)
    assert not isinstance(condition.quantifier, str)


@pytest.mark.parametrize(
    "quantifier",
    [
        "true",
        "false",
        "$a",
        "/re/",
        "1 == 2",
        "1 < 2",
        "not 1",
    ],
)
def test_for_loop_rejects_non_primary_quantifier(quantifier: str) -> None:
    """Boolean, relational and string-reference quantifiers are syntax errors."""
    source = f'rule r {{ strings: $a = "x" condition: for {quantifier} i in (1..2) : (@a[i] > 0) }}'
    with pytest.raises(ParserError):
        Parser().parse(source)


@pytest.mark.parametrize(
    "source",
    [
        'rule r { strings: $a = "a" condition: for any of them }',
        'rule r { strings: $a = "a" condition: for 2 of them }',
        'rule r { strings: $a1 = "a" condition: for 2 of ($a*) }',
    ],
)
def test_parser_rejects_for_of_without_body(source: str) -> None:
    with pytest.raises(ParserError, match="Expected ':' after string set"):
        Parser().parse(source)


def test_parse_of_string_set_and_function_name_resolution_paths() -> None:
    parser = _expr_parser("(abc)")
    of_expr = parser._parse_of_expression("any")
    assert isinstance(of_expr.quantifier, StringLiteral)
    assert of_expr.quantifier.value == "any"

    for invalid_set in ("foo.bar", 'foo["k"]', "foo[1]", "foo(1,2)", "pe.section(1)"):
        with pytest.raises(ParserError, match="Expected string or rule identifier"):
            _expr_parser(invalid_set)._parse_of_string_set()

    with pytest.raises(ParserError, match="Expected member name after"):
        _expr_parser("foo.")._parse_of_string_set()
    with pytest.raises(ParserError, match="Expected '\\]'"):
        _expr_parser("foo[1")._parse_of_string_set()
    with pytest.raises(ParserError, match="Expected '\\)' after arguments"):
        _expr_parser("foo(1,2")._parse_of_string_set()
    with pytest.raises(ParserError, match="Invalid function call"):
        _expr_parser("1(2)")._parse_of_string_set()

    # Exercise non-dotted object branches.
    unknown_member = MemberAccess(object=StringLiteral(value="x"), member="tail")
    call = parser._build_member_function_call(unknown_member, [])
    assert call.function == "tail"
    assert call.receiver == unknown_member.object

    mod_member = MemberAccess(object=ModuleReference(module="pe"), member="section")
    call = parser._build_member_function_call(mod_member, [])
    assert call.function == "pe.section"
    assert call.receiver is None
