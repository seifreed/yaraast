"""Extra real coverage for html_tree and CLI AST dumper."""

from __future__ import annotations

from types import SimpleNamespace

from yaraast.ast.conditions import Condition
from yaraast.ast.expressions import (
    ArrayAccess,
    BooleanLiteral,
    FunctionCall,
    Identifier,
    IntegerLiteral,
    ParenthesesExpression,
    RangeExpression,
    StringWildcard,
    UnaryExpression,
)
from yaraast.ast.operators import DefinedExpression
from yaraast.ast.rules import Import, Include
from yaraast.ast.strings import HexByte, HexJump, HexNibble, HexString, PlainString, RegexString
from yaraast.cli.visitors import ASTDumper
from yaraast.metrics.html_tree import HtmlTreeGenerator


def test_html_tree_import_alias_and_include_nodes() -> None:
    gen = HtmlTreeGenerator()

    import_node = gen.visit_import(Import(module="pe", alias="pe_mod"))
    include_node = gen.visit_include(Include(path="common.yar"))

    assert import_node["label"] == 'Import: "pe" as pe_mod'
    assert include_node["label"] == 'Include: "common.yar"'


def test_ast_dumper_direct_visitors_for_remaining_nodes() -> None:
    dumper = ASTDumper()

    rule_with_accept_modifier = SimpleNamespace(
        modifiers=[
            SimpleNamespace(
                accept=lambda visitor: visitor.visit_string_modifier(
                    SimpleNamespace(name="global", value=None)
                )
            )
        ]
    )
    assert dumper._process_modifiers(rule_with_accept_modifier) == [
        {"type": "StringModifier", "name": "global", "value": None},
    ]
    assert dumper._process_meta(None) == {}

    hex_dump = dumper.visit_hex_string(HexString(identifier="$h", tokens=[HexByte(value=0x41)]))
    regex_dump = dumper.visit_regex_string(RegexString(identifier="$r", regex="abc"))
    assert hex_dump["tokens"][0]["value"] == 0x41
    assert regex_dump["regex"] == "abc"

    assert dumper.visit_hex_jump(HexJump(min_jump=1, max_jump=3)) == {
        "type": "HexJump",
        "min_jump": 1,
        "max_jump": 3,
    }
    assert dumper.visit_string_wildcard(StringWildcard(pattern="$a*"))["pattern"] == "$a*"
    assert dumper.visit_boolean_literal(BooleanLiteral(value=True))["value"] is True
    assert (
        dumper.visit_unary_expression(
            UnaryExpression(operator="not", operand=IntegerLiteral(value=1))
        )["operator"]
        == "not"
    )
    assert (
        dumper.visit_parentheses_expression(
            ParenthesesExpression(expression=IntegerLiteral(value=7))
        )["expression"]["value"]
        == 7
    )
    assert (
        dumper.visit_range_expression(
            RangeExpression(low=IntegerLiteral(value=1), high=IntegerLiteral(value=9))
        )["high"]["value"]
        == 9
    )
    assert (
        dumper.visit_function_call(
            FunctionCall(function="uint16", arguments=[IntegerLiteral(value=0)])
        )["arguments"][0]["value"]
        == 0
    )
    assert (
        dumper.visit_array_access(
            ArrayAccess(array=Identifier(name="arr"), index=IntegerLiteral(value=2))
        )["index"]["value"]
        == 2
    )
    assert dumper.visit_condition(Condition())["type"] == "Condition"
    assert (
        dumper.visit_defined_expression(DefinedExpression(expression=IntegerLiteral(value=5)))[
            "expression"
        ]["value"]
        == 5
    )
    assert dumper.visit_hex_nibble(HexNibble(high=True, value=0xA)) == {
        "type": "HexNibble",
        "high": True,
        "value": 0xA,
    }

    extern_import = SimpleNamespace(module="math")
    extern_ref = SimpleNamespace(name="extern_rule")
    assert dumper.visit_extern_import(extern_import)["module"] == "math"
    assert dumper.visit_extern_rule_reference(extern_ref)["name"] == "extern_rule"


def test_ast_dumper_plain_and_regex_string_accept_modifiers() -> None:
    dumper = ASTDumper()
    modifier = SimpleNamespace(
        accept=lambda visitor: visitor.visit_string_modifier(
            SimpleNamespace(name="ascii", value=None)
        )
    )

    plain = PlainString(identifier="$a", value="abc")
    plain.modifiers = [modifier]
    regex = RegexString(identifier="$b", regex="abc")
    regex.modifiers = [modifier]

    assert dumper.visit_plain_string(plain)["modifiers"][0]["name"] == "ascii"
    assert dumper.visit_regex_string(regex)["modifiers"][0]["name"] == "ascii"
