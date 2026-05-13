"""Extra coverage for cli.visitors.dumper without mocks."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

from yaraast.ast.base import YaraFile
from yaraast.ast.conditions import InExpression
from yaraast.ast.expressions import (
    DoubleLiteral,
    Identifier,
    IntegerLiteral,
    SetExpression,
    StringCount,
    StringLength,
    StringOffset,
)
from yaraast.ast.extern import ExternImport, ExternNamespace, ExternRule
from yaraast.ast.meta import Meta
from yaraast.ast.modifiers import RuleModifier
from yaraast.ast.pragmas import CustomPragma, InRulePragma, Pragma, PragmaType
from yaraast.ast.rules import Rule
from yaraast.ast.strings import (
    HexAlternative,
    HexByte,
    HexNegatedByte,
    HexToken,
    HexWildcard,
    PlainString,
)
from yaraast.cli.visitors import ASTDumper


class _AcceptOnly:
    def accept(self, _visitor: object) -> dict[str, str]:
        return {"type": "AcceptOnly"}


class _AcceptOnlyModifier:
    def __init__(self, name: str = "x") -> None:
        self.name = name
        self.value = None

    def accept(self, visitor: Any) -> Any:
        return visitor.visit_string_modifier(self)


def test_dumper_branches_for_modifiers_meta_and_generic_nodes() -> None:
    d = ASTDumper()

    # _process_modifiers branches
    rule_list = Rule(name="r", modifiers=["private", RuleModifier.from_string("global"), 123])
    mods_list = d._process_modifiers(rule_list)
    assert "private" in mods_list and "global" in mods_list and "123" in mods_list

    rule_str = Rule(name="r", modifiers="global")
    assert d._process_modifiers(rule_str) == ["global"]

    rule_empty = Rule(name="r", modifiers=[])
    assert d._process_modifiers(rule_empty) == []

    rule_str = Rule(name="r", modifiers=["private"])
    assert d._process_modifiers(rule_str) == ["private"]

    # _process_meta list branch + ignored entries
    meta = d._process_meta([Meta(key="a", value=1), SimpleNamespace(foo=1)])
    assert meta == {"a": 1}

    # visit_string_definition
    base_sd = d.visit_string_definition(PlainString(identifier="$x", value="abc"))
    assert base_sd["type"] == "StringDefinition"

    # _extract_modifiers branches
    s_obj = PlainString(identifier="$a", value="x")
    s_obj.modifiers = ["ascii", _AcceptOnlyModifier(), 3]
    ext = d._extract_modifiers(s_obj)
    assert "ascii" in ext and "3" in ext
    assert any(isinstance(v, dict) and v.get("type") == "StringModifier" for v in ext)

    s_empty = PlainString(identifier="$b", value="x", modifiers=[])
    assert d._extract_modifiers(s_empty) == []

    # hex token and expression/condition node dumpers
    assert d.visit_hex_token(HexToken())["type"] == "HexToken"
    assert d.visit(HexNegatedByte(value=0x4D)) == {"type": "HexNegatedByte", "value": 0x4D}
    assert d.visit_hex_wildcard(HexWildcard())["type"] == "HexWildcard"
    alt = HexAlternative(alternatives=[[HexByte(value=0x41)], [HexByte(value=0x42)]])
    assert d.visit_hex_alternative(alt)["alternatives"]
    assert d.visit_expression(IntegerLiteral(value=1))["type"] == "Expression"
    assert d.visit_string_count(StringCount(string_id="$a"))["string_id"] == "$a"
    assert d.visit_string_offset(StringOffset(string_id="$a"))["index"] is None
    assert d.visit_string_length(StringLength(string_id="$a"))["index"] is None
    assert d.visit_double_literal(DoubleLiteral(value=1.2))["value"] == 1.2
    assert d.visit_set_expression(SetExpression(elements=[Identifier(name="x")]))["elements"]


def test_dumper_extra_node_types_and_fallback_fields() -> None:
    d = ASTDumper()

    # extern import fallback module_path
    ext_imp = SimpleNamespace(module_path="mod.path")
    assert d.visit_extern_import(ext_imp)["module"] == "mod.path"

    # extern rule reference fallback rule_name
    ext_ref = SimpleNamespace(rule_name="r1")
    assert d.visit_extern_rule_reference(ext_ref)["name"] == "r1"

    assert d.visit_comment(SimpleNamespace(text="hello"))["text"] == "hello"
    assert d.visit_comment_group(SimpleNamespace(lines=["a", "b"]))["lines"] == ["a", "b"]
    assert (
        d.visit_for_expression(
            cast(
                Any,
                SimpleNamespace(
                    quantifier="any",
                    variable="i",
                    iterable=IntegerLiteral(value=1),
                    body=IntegerLiteral(value=1),
                ),
            )
        )["type"]
        == "ForExpression"
    )
    dumped_for = d.visit_for_expression(
        cast(
            Any,
            SimpleNamespace(
                quantifier=IntegerLiteral(value=2),
                variable="i",
                iterable=IntegerLiteral(value=1),
                body=IntegerLiteral(value=1),
            ),
        )
    )
    assert dumped_for["quantifier"] == {"type": "IntegerLiteral", "value": 2}
    assert (
        d.visit_for_of_expression(
            cast(
                Any,
                SimpleNamespace(quantifier=1, string_set=IntegerLiteral(value=1), condition=None),
            )
        )["quantifier"]
        == 1
    )
    assert (
        d.visit_at_expression(
            cast(Any, SimpleNamespace(string_id="$a", offset=IntegerLiteral(value=1)))
        )["type"]
        == "AtExpression"
    )
    assert (
        d.visit_in_expression(
            cast(Any, SimpleNamespace(string_id="$a", range=IntegerLiteral(value=1)))
        )["type"]
        == "InExpression"
    )
    assert (
        d.visit_of_expression(
            cast(Any, SimpleNamespace(quantifier=1, string_set=IntegerLiteral(value=1)))
        )["quantifier"]
        == 1
    )
    assert d.visit_meta(Meta(key="k", value="v"))["key"] == "k"
    assert d.visit_extern_namespace(SimpleNamespace(name="ns"))["name"] == "ns"
    assert d.visit_extern_rule(SimpleNamespace(name="r"))["name"] == "r"
    assert d.visit_in_rule_pragma(SimpleNamespace(directive="x"))["directive"] == "x"
    assert d.visit_pragma(SimpleNamespace(directive="p"))["directive"] == "p"
    assert d.visit_pragma_block(SimpleNamespace(pragmas=[]))["pragmas"] == []


def test_dumper_preserves_real_extended_ast_nodes() -> None:
    d = ASTDumper()
    ast = YaraFile(
        extern_imports=[ExternImport(module_path="external.yar", alias="ext", rules=["R1"])],
        extern_rules=[ExternRule(name="R1", modifiers=[RuleModifier.from_string("private")])],
        pragmas=[CustomPragma(name="vendor", arguments=["on"], parameters={"level": "strict"})],
        namespaces=[ExternNamespace(name="ns", extern_rules=[ExternRule(name="Nested")])],
        rules=[
            Rule(
                name="r1",
                condition=InExpression(subject=Identifier("offset"), range=IntegerLiteral(10)),
                pragmas=[
                    InRulePragma(
                        pragma=Pragma(PragmaType.PRAGMA, "optimize", ["fast"]),
                        position="before_condition",
                    )
                ],
            )
        ],
    )

    dumped = d.visit(ast)

    assert dumped["extern_imports"][0]["module_path"] == "external.yar"
    assert dumped["extern_imports"][0]["alias"] == "ext"
    assert dumped["extern_rules"][0]["modifiers"] == ["private"]
    assert dumped["pragmas"][0]["parameters"] == {"level": "strict"}
    assert dumped["namespaces"][0]["extern_rules"][0]["name"] == "Nested"
    assert dumped["rules"][0]["pragmas"][0]["directive"] == "optimize"
    assert dumped["rules"][0]["pragmas"][0]["position"] == "before_condition"
    assert dumped["rules"][0]["condition"]["string_id"] is None
    assert dumped["rules"][0]["condition"]["subject"] == {"type": "Identifier", "name": "offset"}
