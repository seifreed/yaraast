"""Additional coverage for parser for/of helper stringification paths."""

from __future__ import annotations

from yaraast.ast.expressions import Identifier, MemberAccess, StringLiteral
from yaraast.ast.modules import ModuleReference
from yaraast.lexer import Lexer
from yaraast.parser.parser import Parser


def _expr_parser(text: str) -> Parser:
    parser = Parser("rule seed { condition: true }")
    parser.tokens = Lexer(text).tokenize()
    parser.current = 0
    return parser


def test_member_function_call_keeps_only_non_dotted_receivers() -> None:
    parser = _expr_parser("x")

    direct = MemberAccess(object=Identifier(name="foo"), member="bar")
    call = parser._build_member_function_call(direct, [])
    assert call.function == "foo.bar"
    assert call.receiver is None

    mod_member = MemberAccess(object=ModuleReference(module="pe"), member="section")
    call = parser._build_member_function_call(mod_member, [])
    assert call.function == "pe.section"
    assert call.receiver is None

    nested = MemberAccess(
        object=MemberAccess(object=Identifier(name="a"), member="b"),
        member="c",
    )
    call = parser._build_member_function_call(nested, [])
    assert call.function == "a.b.c"
    assert call.receiver is None

    unknown = MemberAccess(object=StringLiteral(value="x"), member="tail")
    call = parser._build_member_function_call(unknown, [])
    assert call.function == "tail"
    assert call.receiver == unknown.object
