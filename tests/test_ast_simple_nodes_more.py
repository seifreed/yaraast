"""Additional tests for simple AST nodes (no mocks)."""

from __future__ import annotations

from yaraast.ast.base import Location
from yaraast.ast.expressions import (
    BinaryExpression,
    BooleanLiteral,
    Expression,
    Identifier,
    IntegerLiteral,
    StringIdentifier,
)
from yaraast.ast.modifiers import StringModifier
from yaraast.ast.rules import Rule, Tag
from yaraast.ast.strings import (
    HexAlternative,
    HexByte,
    HexJump,
    HexNibble,
    HexString,
    HexToken,
    HexWildcard,
    PlainString,
    RegexString,
    StringDefinition,
)


class _Visitor:
    def visit_expression(self, node: Expression) -> str:
        return f"expr:{node.__class__.__name__}"

    def visit_string_identifier(self, node: StringIdentifier) -> str:
        return f"string:{node.name}"

    def visit_boolean_literal(self, node: BooleanLiteral) -> str:
        return f"bool:{node.value}"

    def visit_integer_literal(self, node: IntegerLiteral) -> str:
        return f"int:{node.value}"

    def visit_identifier(self, node: Identifier) -> str:
        return f"id:{node.name}"

    def visit_binary_expression(self, node: BinaryExpression) -> str:
        return f"bin:{node.operator}"

    def visit_tag(self, node: Tag) -> str:
        return f"tag:{node.name}"

    def visit_string_modifier(self, node: StringModifier) -> str:
        return f"mod:{node.name}"

    def visit_string_definition(self, node: StringDefinition) -> str:
        return f"strdef:{node.identifier}"

    def visit_plain_string(self, node: PlainString) -> str:
        return f"plain:{node.value}"

    def visit_regex_string(self, node: RegexString) -> str:
        return f"regex:{node.regex}"

    def visit_hex_byte(self, node: HexByte) -> str:
        return f"hex:{node.value}"

    def visit_hex_string(self, node: HexString) -> str:
        return f"hexstr:{node.identifier}"

    def visit_hex_token(self, node: HexToken) -> str:
        return f"hextoken:{node.__class__.__name__}"

    def visit_hex_wildcard(self, node: HexWildcard) -> str:
        return "wildcard"

    def visit_hex_jump(self, node: HexJump) -> str:
        return f"jump:{node.min_jump}-{node.max_jump}"

    def visit_hex_alternative(self, node: HexAlternative) -> str:
        return f"alt:{len(node.alternatives)}"

    def visit_hex_nibble(self, node: HexNibble) -> str:
        return f"nibble:{node.high}:{node.value}"

    def visit_rule(self, node: Rule) -> str:
        return f"rule:{node.name}"


def test_simple_nodes_accept_and_location() -> None:
    visitor = _Visitor()

    expr = Expression()
    expr.location = Location(line=1, column=1)
    assert expr.accept(visitor) == "expr:Expression"
    assert expr.location == Location(line=1, column=1)

    string_id = StringIdentifier(name="$a")
    assert string_id.accept(visitor) == "string:$a"

    bool_lit = BooleanLiteral(value=True)
    assert bool_lit.accept(visitor) == "bool:True"

    int_lit = IntegerLiteral(value=12)
    assert int_lit.accept(visitor) == "int:12"

    ident = Identifier(name="alpha")
    assert ident.accept(visitor) == "id:alpha"


def test_simple_nodes_strings_and_rule() -> None:
    visitor = _Visitor()

    tag = Tag(name="t1")
    assert tag.accept(visitor) == "tag:t1"

    mod = StringModifier.from_name_value("ascii")
    assert mod.accept(visitor) == "mod:ascii"

    plain = PlainString(identifier="$a", value="hello", modifiers=[mod])
    assert plain.accept(visitor) == "plain:hello"

    regex = RegexString(identifier="$r", regex="ab.*")
    assert regex.accept(visitor) == "regex:ab.*"

    hex_byte = HexByte(value=0x90)
    assert hex_byte.accept(visitor) == "hex:144"

    wildcard = HexWildcard()
    assert wildcard.accept(visitor) == "wildcard"

    ident = Identifier(name="alpha")
    bool_lit = BooleanLiteral(value=False)
    rule = Rule(
        name="r1",
        modifiers=["private"],
        tags=[tag],
        meta={"author": "me"},
        strings=[plain, regex],
        condition=BinaryExpression(left=ident, operator="and", right=bool_lit),
    )
    assert rule.accept(visitor) == "rule:r1"


def test_simple_hex_nodes_accept() -> None:
    visitor = _Visitor()

    string_def = StringDefinition(identifier="$base")
    assert string_def.accept(visitor) == "strdef:$base"

    base = HexToken()
    assert base.accept(visitor) == "hextoken:HexToken"

    jump = HexJump(min_jump=1, max_jump=3)
    assert jump.accept(visitor) == "jump:1-3"

    alt = HexAlternative(alternatives=[[HexByte(value=0x41)], [HexWildcard()]])
    assert alt.accept(visitor) == "alt:2"

    nibble = HexNibble(high=True, value=0xA)
    assert nibble.accept(visitor) == "nibble:True:10"

    hex_string = HexString(identifier="$h", tokens=[HexByte(value=0x90), jump])
    assert hex_string.accept(visitor) == "hexstr:$h"
