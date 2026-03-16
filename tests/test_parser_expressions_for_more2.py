"""Additional branch coverage for parser for/of helpers (no mocks)."""

from __future__ import annotations

import pytest

from yaraast.ast.expressions import ArrayAccess, FunctionCall, MemberAccess, StringLiteral
from yaraast.ast.modules import DictionaryAccess, ModuleReference
from yaraast.lexer import Lexer
from yaraast.parser._shared import ParserError
from yaraast.parser.parser import Parser


def _expr_parser(text: str) -> Parser:
    parser = Parser("rule seed { condition: true }")
    parser.tokens = Lexer(text).tokenize()
    parser.current = 0
    return parser


def test_parse_for_expression_success_and_error_paths() -> None:
    node_any = _expr_parser("any i in 1 : ( true )")._parse_for_expression()
    assert node_any.quantifier == "any"
    assert node_any.variable == "i"

    node_all = _expr_parser("all j in 2 : ( j > 0 )")._parse_for_expression()
    assert node_all.quantifier == "all"
    assert node_all.variable == "j"

    node_n = _expr_parser("3 of them")._parse_for_expression()
    assert node_n.quantifier == "3"
    assert node_n.condition is None

    node_for_of = _expr_parser("any of them : ( true )")._parse_for_expression()
    assert node_for_of.quantifier == "any"
    assert node_for_of.condition is not None

    with pytest.raises(ParserError, match="Expected quantifier"):
        _expr_parser("them")._parse_for_expression()
    with pytest.raises(ParserError, match="Expected variable name"):
        _expr_parser("any in 1 : ( true )")._parse_for_expression()
    with pytest.raises(ParserError, match="Expected 'in' after variable"):
        _expr_parser("any i 1 : ( true )")._parse_for_expression()
    with pytest.raises(ParserError, match="Expected ':' after iterable"):
        _expr_parser("any i in 1 true")._parse_for_expression()
    with pytest.raises(ParserError, match="Expected '\\(' after ':'"):
        _expr_parser("any i in 1 : true )")._parse_for_expression()
    with pytest.raises(ParserError, match="Expected '\\)' after for body"):
        _expr_parser("any i in 1 : ( true")._parse_for_expression()
    with pytest.raises(ParserError, match="Expected '\\)' after condition"):
        _expr_parser("any of them : ( true")._parse_for_expression()


def test_parse_of_string_set_and_function_name_resolution_paths() -> None:
    parser = _expr_parser("abc")
    of_expr = parser._parse_of_expression("any")
    assert isinstance(of_expr.quantifier, StringLiteral)
    assert of_expr.quantifier.value == "any"

    member = _expr_parser("foo.bar")._parse_of_string_set()
    assert isinstance(member, MemberAccess)
    assert member.member == "bar"

    dict_access = _expr_parser('foo["k"]')._parse_of_string_set()
    assert isinstance(dict_access, DictionaryAccess)
    assert dict_access.key == "k"

    arr_access = _expr_parser("foo[1]")._parse_of_string_set()
    assert isinstance(arr_access, ArrayAccess)

    fn_simple = _expr_parser("foo(1,2)")._parse_of_string_set()
    assert isinstance(fn_simple, FunctionCall)
    assert fn_simple.function == "foo"

    fn_module = _expr_parser("pe.section(1)")._parse_of_string_set()
    assert isinstance(fn_module, FunctionCall)
    assert fn_module.function == "pe.section"

    fn_nested = _expr_parser("a.b.c(1)")._parse_of_string_set()
    assert isinstance(fn_nested, FunctionCall)
    assert fn_nested.function == "a.b.c"

    with pytest.raises(ParserError, match="Expected member name after"):
        _expr_parser("foo.")._parse_of_string_set()
    with pytest.raises(ParserError, match="Expected '\\]'"):
        _expr_parser("foo[1")._parse_of_string_set()
    with pytest.raises(ParserError, match="Expected '\\)' after arguments"):
        _expr_parser("foo(1,2")._parse_of_string_set()
    with pytest.raises(ParserError, match="Invalid function call"):
        _expr_parser("1(2)")._parse_of_string_set()

    # Exercise fallback branches for unknown object types.
    unknown_member = MemberAccess(object=StringLiteral(value="x"), member="tail")
    assert parser._resolve_function_name(unknown_member) == "unknown.tail"
    assert parser._member_access_to_string(unknown_member) == "unknown.tail"

    mod_member = MemberAccess(object=ModuleReference(module="pe"), member="section")
    assert parser._resolve_function_name(mod_member) == "pe.section"
