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


def test_member_access_to_string_module_and_nested_paths() -> None:
    parser = _expr_parser("x")

    direct = MemberAccess(object=Identifier(name="foo"), member="bar")
    assert parser._resolve_function_name(direct) == "foo.bar"

    mod_member = MemberAccess(object=ModuleReference(module="pe"), member="section")
    assert parser._member_access_to_string(mod_member) == "pe.section"

    nested = MemberAccess(
        object=MemberAccess(object=Identifier(name="a"), member="b"),
        member="c",
    )
    assert parser._member_access_to_string(nested) == "a.b.c"

    unknown = MemberAccess(object=StringLiteral(value="x"), member="tail")
    assert parser._member_access_to_string(unknown) == "unknown.tail"
