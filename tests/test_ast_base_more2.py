"""Additional tests for base AST nodes (no mocks)."""

from __future__ import annotations

from yaraast.ast.base import Location, YaraFile
from yaraast.ast.expressions import BooleanLiteral
from yaraast.ast.extern import ExternRule
from yaraast.ast.pragmas import IncludeOncePragma
from yaraast.ast.rules import Import, Include, Rule, Tag
from yaraast.ast.strings import PlainString
from yaraast.parser import Parser


def test_ast_node_children_and_location() -> None:
    condition = BooleanLiteral(value=True)
    rule = Rule(
        name="r1",
        tags=[Tag(name="t1")],
        strings=[PlainString(identifier="$a", value="x")],
        condition=condition,
    )
    file_node = YaraFile(rules=[rule])

    children = file_node.children()
    assert rule in children
    assert condition in rule.children()

    loc = Location(line=10, column=5, file="test.yar")
    rule.location = loc
    assert rule.location.file == "test.yar"


def test_yarafile_helpers() -> None:
    file_node = YaraFile(
        imports=[Import(module="pe")],
        includes=[Include(path="inc.yar")],
        rules=[Rule(name="r1")],
    )
    assert file_node.get_all_rules()[0].name == "r1"

    pragma = IncludeOncePragma()
    file_node.add_pragma(pragma)
    assert file_node.has_include_once() is True

    extern_rule = ExternRule(name="ext1", namespace="ext")
    file_node.add_extern_rule(extern_rule)
    assert file_node.get_extern_rule_by_name("ext1", "ext") == extern_rule


def test_parser_populates_location_spans_for_core_nodes() -> None:
    ast = Parser().parse(
        """
rule sample {
    strings:
        $a = "abc"
    condition:
        $a or true
}
""".lstrip()
    )

    rule = ast.rules[0]
    string_def = rule.strings[0]

    assert rule.location is not None
    assert rule.location.end_line is not None
    assert rule.location.end_column is not None
    assert string_def.location is not None
    assert string_def.location.end_line is not None
    assert string_def.location.end_column is not None
    assert rule.condition is not None
    assert rule.condition.location is not None
    assert rule.condition.location.end_line is not None
