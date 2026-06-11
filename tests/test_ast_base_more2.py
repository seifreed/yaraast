"""Additional tests for base AST nodes (no mocks)."""

from __future__ import annotations

from typing import Any, cast

import pytest

from yaraast.ast.base import Location, YaraFile
from yaraast.ast.comments import Comment, CommentGroup
from yaraast.ast.expressions import BooleanLiteral
from yaraast.ast.extern import ExternRule
from yaraast.ast.pragmas import IncludeOncePragma
from yaraast.ast.rules import Import, Include, Rule, Tag
from yaraast.ast.strings import HexAlternative, HexByte, HexString, HexWildcard, PlainString
from yaraast.optimization.expression_optimizer import ExpressionOptimizer
from yaraast.parser import Parser
from yaraast.yarax.ast_nodes import (
    DictExpression,
    LambdaExpression,
    PatternMatch,
    WithStatement,
)


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


def test_comment_group_exposes_aggregate_text() -> None:
    group = CommentGroup([Comment("one"), Comment("two")])

    assert group.text == "one\ntwo"
    group.text = "three\nfour"
    assert [comment.text for comment in group.comments] == ["three", "four"]


def test_ast_node_children_flattens_nested_ast_lists() -> None:
    byte = HexByte(value=0x11)
    wildcard = HexWildcard()
    alternative = HexAlternative(alternatives=[[byte], [wildcard]])

    assert alternative.children() == [byte, wildcard]


def test_yarafile_accept_rejects_non_ast_children() -> None:
    file_node = YaraFile(rules=[cast(Any, object())])

    with pytest.raises(TypeError, match="YaraFile rules must contain Rule nodes"):
        file_node.accept(cast(Any, object()))


def test_rule_validate_structure_rejects_non_ast_children() -> None:
    invalid_strings = Rule(name="bad", strings=[cast(Any, object())])
    with pytest.raises(TypeError, match="Rule strings must contain StringDefinition nodes"):
        invalid_strings.validate_structure()

    invalid_condition = Rule(name="bad", condition=cast(Any, object()))
    with pytest.raises(TypeError, match=r"Rule\.condition must be an AST node"):
        invalid_condition.validate_structure()


@pytest.mark.parametrize(
    ("node", "message"),
    [
        (Import(""), "Import module cannot be empty"),
        (Import("   "), "Import module cannot be empty"),
        (Import("pe", alias=""), "Import alias cannot be empty"),
        (Include(""), "Include path cannot be empty"),
        (Include("\t"), "Include path cannot be empty"),
        (Tag(""), "Tag name cannot be empty"),
        (Tag("   "), "Tag name cannot be empty"),
        (Rule(""), "Rule name cannot be empty"),
        (Rule("   "), "Rule name cannot be empty"),
    ],
)
def test_validate_structure_rejects_empty_scalar_fields(
    node: Import | Include | Tag | Rule,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        node.validate_structure()


def test_direct_yarafile_optimizers_validate_structure() -> None:
    malformed_file = YaraFile(rules=[cast(Any, object())])

    with pytest.raises(TypeError, match="YaraFile rules must contain Rule nodes"):
        ExpressionOptimizer().optimize(malformed_file)


def test_direct_yarafile_optimizers_validate_nested_hex_tokens() -> None:
    malformed_file = YaraFile(
        rules=[
            Rule(
                name="bad_hex",
                strings=[HexString("$h", tokens=[cast(Any, object())])],
                condition=BooleanLiteral(True),
            )
        ]
    )

    with pytest.raises(TypeError, match=r"HexString\.tokens must contain AST nodes"):
        ExpressionOptimizer().optimize(malformed_file)


@pytest.mark.parametrize(
    ("field_name", "value", "message"),
    [
        ("imports", [Import(cast(Any, object()))], "Import module must be a string"),
        ("includes", [Include(cast(Any, object()))], "Include path must be a string"),
        ("rules", [Rule(cast(Any, object()))], "Rule name must be a string"),
        ("rules", [Rule("bad_tag", tags=[Tag(cast(Any, object()))])], "Tag name must be a string"),
        (
            "rules",
            [Rule("bad_string", strings=[PlainString(cast(Any, object()), "x")])],
            "String identifier must be a string",
        ),
        (
            "rules",
            [Rule("bad_value", strings=[PlainString("$a", value=cast(Any, object()))])],
            "Plain string value must be a string or bytes",
        ),
    ],
)
def test_direct_yarafile_optimizers_validate_scalar_fields(
    field_name: str,
    value: Any,
    message: str,
) -> None:
    malformed_file = YaraFile()
    setattr(malformed_file, field_name, value)

    with pytest.raises(TypeError, match=message):
        ExpressionOptimizer().optimize(malformed_file)


@pytest.mark.parametrize(
    ("condition", "message"),
    [
        (
            WithStatement(cast(Any, object()), BooleanLiteral(True)),
            "WithStatement declarations must be a list or tuple",
        ),
        (
            WithStatement([cast(Any, object())], BooleanLiteral(True)),
            "WithStatement declarations must contain WithDeclaration nodes",
        ),
        (
            DictExpression([cast(Any, object())]),
            "DictExpression items must contain DictItem nodes",
        ),
        (
            PatternMatch(BooleanLiteral(True), [cast(Any, object())]),
            "PatternMatch cases must contain MatchCase nodes",
        ),
        (
            LambdaExpression([cast(Any, object())], BooleanLiteral(True)),
            "Local variable name must be a string",
        ),
    ],
)
def test_direct_yarafile_analysis_validates_yarax_condition_structure(
    condition: Any,
    message: str,
) -> None:
    malformed_file = YaraFile(rules=[Rule("bad_yarax", condition=condition)])

    with pytest.raises(TypeError, match=message):
        ExpressionOptimizer().optimize(malformed_file)


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
    ast = Parser().parse("""
rule sample {
    strings:
        $a = "abc"
    condition:
        $a or true
}
""".lstrip())

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
