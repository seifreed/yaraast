"""Additional real coverage for simple_roundtrip_helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest

from yaraast.ast.base import Location, YaraFile
from yaraast.ast.comments import Comment, CommentGroup
from yaraast.ast.conditions import (
    AtExpression,
    ForExpression,
    ForOfExpression,
    InExpression,
    OfExpression,
)
from yaraast.ast.expressions import (
    ArrayAccess,
    BinaryExpression,
    BooleanLiteral,
    FunctionCall,
    Identifier,
    IntegerLiteral,
    MemberAccess,
    ParenthesesExpression,
    RangeExpression,
    RegexLiteral,
    SetExpression,
    StringIdentifier,
    StringLength,
    StringLiteral,
    StringOffset,
    StringWildcard,
)
from yaraast.ast.extern import ExternImport, ExternNamespace, ExternRule, ExternRuleReference
from yaraast.ast.meta import Meta
from yaraast.ast.modifiers import MetaEntry, MetaScope, RuleModifier, StringModifier
from yaraast.ast.modules import DictionaryAccess, ModuleReference
from yaraast.ast.operators import DefinedExpression, StringOperatorExpression
from yaraast.ast.pragmas import CustomPragma, InRulePragma, PragmaBlock, PragmaScope
from yaraast.ast.rules import Import, Include, Rule, Tag
from yaraast.ast.strings import (
    HexAlternative,
    HexByte,
    HexJump,
    HexNegatedByte,
    HexNibble,
    HexString,
    HexWildcard,
    PlainString,
    RegexString,
    StringDefinition,
)
from yaraast.errors import SerializationError
from yaraast.serialization.simple_roundtrip_helpers import (
    _compare_normalized,
    deserialize_from_file,
    deserialize_meta,
    deserialize_node,
    deserialize_rule,
    deserialize_string,
    serialize_meta,
    serialize_node,
    serialize_rule,
    serialize_string,
    serialize_to_file,
    validate_roundtrip,
)
from yaraast.yarax.ast_nodes import (
    ArrayComprehension,
    DictComprehension,
    DictExpression,
    DictItem,
    LambdaExpression,
    ListExpression,
    MatchCase,
    PatternMatch,
    SliceExpression,
    SpreadOperator,
    TupleExpression,
    TupleIndexing,
    WithDeclaration,
    WithStatement,
)


def test_simple_roundtrip_helpers_serialize_meta_and_string_fallbacks(tmp_path: Path) -> None:
    rule = Rule(
        name="helper_rule",
        condition=BooleanLiteral(value=True),
        tags=cast(Any, [Tag(name="one"), "two"]),
        meta=[Meta(key="author", value="me"), Meta(key="enabled", value=True)],
        strings=[
            PlainString(identifier="$a", value="x"),
            HexString(identifier="$b", tokens=[HexByte(value=0x41)]),
            RegexString(identifier="$c", regex="ab.*"),
        ],
    )

    serialized_rule = serialize_rule(rule)
    assert serialized_rule["meta"][0] == {"type": "Meta", "key": "author", "value": "me"}
    assert serialize_meta(Meta(key="score", value=7)) == {
        "type": "Meta",
        "key": "score",
        "value": 7,
    }
    assert serialize_string(StringDefinition(identifier="$z"))["type"] == "StringDefinition"

    restored_rule = deserialize_rule(serialized_rule)
    assert [t.name for t in restored_rule.tags] == ["one", "two"]
    assert deserialize_meta({"key": "author", "value": "me"}).key == "author"
    assert deserialize_string({"type": "Unknown", "identifier": "$x", "data": "raw"}).value == "raw"

    path = tmp_path / "helper.json"
    serialize_to_file(
        YaraFile(imports=[Import(module="pe")], includes=[Include(path="inc.yar")], rules=[rule]),
        path,
    )
    restored_file = deserialize_from_file(path)
    assert isinstance(restored_file, YaraFile)
    assert restored_file.rules[0].name == "helper_rule"


def test_simple_roundtrip_helpers_preserve_meta_entry_scope() -> None:
    private_meta = MetaEntry.from_key_value("classification", "restricted", "private")

    serialized = serialize_meta(private_meta)

    assert serialized == {
        "type": "MetaEntry",
        "key": "classification",
        "value": "restricted",
        "scope": "private",
    }

    restored = deserialize_meta(serialized)
    assert isinstance(restored, MetaEntry)
    assert restored.scope == MetaScope.PRIVATE


def test_simple_roundtrip_helpers_file_io_preserves_xor_range_modifier(tmp_path: Path) -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="xor_range",
                strings=[
                    PlainString(
                        identifier="$a",
                        value="abc",
                        modifiers=[StringModifier.from_name_value("xor", (1, 3))],
                    )
                ],
                condition=StringIdentifier("$a"),
            )
        ]
    )
    path = tmp_path / "simple.json"

    serialize_to_file(ast, path)
    restored = deserialize_from_file(path)

    assert isinstance(restored, YaraFile)
    assert restored.rules[0].strings[0].modifiers[0].value == (1, 3)


def test_simple_roundtrip_helpers_preserve_file_extensions_and_pragmas() -> None:
    ast = YaraFile(
        extern_rules=[
            ExternRule(
                name="ExternalRule",
                modifiers=[RuleModifier.from_string("private")],
                namespace="legacy",
            ),
        ],
        extern_imports=[ExternImport("external_rules", alias="ext", rules=["ExternalRule"])],
        pragmas=[
            CustomPragma(
                "optimize",
                arguments=["off"],
                parameters={"level": 2},
                scope=PragmaScope.FILE,
            )
        ],
        namespaces=[ExternNamespace("corp", extern_rules=[ExternRule(name="NamespacedRule")])],
        rules=[
            Rule(
                name="uses_external",
                pragmas=[
                    InRulePragma(
                        CustomPragma("rule_hint", parameters={"enabled": True}),
                        position="before_condition",
                    )
                ],
                condition=cast(
                    Any,
                    ExternRuleReference("ExternalRule", namespace="legacy"),
                ),
            )
        ],
    )

    restored = deserialize_node(serialize_node(ast))

    assert isinstance(restored, YaraFile)
    assert restored.extern_rules[0].name == "ExternalRule"
    assert str(restored.extern_rules[0].modifiers[0]) == "private"
    assert restored.extern_rules[0].namespace == "legacy"
    assert restored.extern_imports[0].module_path == "external_rules"
    assert restored.extern_imports[0].alias == "ext"
    assert restored.extern_imports[0].rules == ["ExternalRule"]
    restored_file_pragma = restored.pragmas[0]
    assert isinstance(restored_file_pragma, CustomPragma)
    assert restored_file_pragma.parameters == {"level": 2}
    assert restored.namespaces[0].name == "corp"
    assert restored.namespaces[0].extern_rules[0].name == "NamespacedRule"
    restored_rule_pragma = restored.rules[0].pragmas[0]
    assert restored_rule_pragma.position == "before_condition"
    assert isinstance(restored_rule_pragma.pragma, CustomPragma)
    assert restored_rule_pragma.pragma.parameters == {"enabled": True}
    assert isinstance(restored.rules[0].condition, ExternRuleReference)
    assert restored.rules[0].condition.qualified_name == "legacy.ExternalRule"


def test_simple_roundtrip_helpers_preserve_extended_expression_nodes() -> None:
    nodes = [
        StringWildcard("$a*"),
        StringOffset("$a", IntegerLiteral(1)),
        StringLength("$a", IntegerLiteral(2)),
        RegexLiteral("ab.*", "i"),
        ParenthesesExpression(BinaryExpression(IntegerLiteral(1), "+", IntegerLiteral(2))),
        SetExpression([StringIdentifier("$a"), StringWildcard("$b*")]),
        RangeExpression(IntegerLiteral(0), IntegerLiteral(10)),
        FunctionCall("math.entropy", [IntegerLiteral(0), IntegerLiteral(10)]),
        ArrayAccess(Identifier("arr"), IntegerLiteral(1)),
        MemberAccess(ModuleReference("pe"), "is_dll"),
        ForExpression(
            "any",
            "i",
            RangeExpression(IntegerLiteral(1), IntegerLiteral(3)),
            BinaryExpression(Identifier("i"), ">", IntegerLiteral(1)),
        ),
        ForOfExpression(
            "all",
            SetExpression([StringIdentifier("$a")]),
            condition=AtExpression("$a", IntegerLiteral(0)),
        ),
        InExpression(
            OfExpression("any", Identifier("them")),
            RangeExpression(IntegerLiteral(0), IntegerLiteral(20)),
        ),
        OfExpression(IntegerLiteral(1), ["$a", "$b"]),
        DictionaryAccess(MemberAccess(ModuleReference("pe"), "version_info"), "CompanyName"),
        DictionaryAccess(Identifier("arr"), IntegerLiteral(0)),
        DefinedExpression(DictionaryAccess(ModuleReference("pe"), "rich_signature")),
        StringOperatorExpression(StringLiteral("abc"), "icontains", StringLiteral("b")),
        WithDeclaration("xs", ListExpression([IntegerLiteral(1)])),
        DictItem(Identifier("key"), IntegerLiteral(1)),
        MatchCase(IntegerLiteral(1), BooleanLiteral(True)),
        ListExpression([IntegerLiteral(1), SpreadOperator(Identifier("more"))]),
        DictExpression(
            [
                DictItem(Identifier("key"), IntegerLiteral(1)),
                DictItem(Identifier("base"), SpreadOperator(Identifier("defaults"), True)),
            ]
        ),
        TupleExpression([IntegerLiteral(1), IntegerLiteral(2)]),
        TupleIndexing(TupleExpression([IntegerLiteral(1), IntegerLiteral(2)]), IntegerLiteral(0)),
        SliceExpression(Identifier("xs"), stop=IntegerLiteral(2)),
        LambdaExpression(["x"], BinaryExpression(Identifier("x"), ">", IntegerLiteral(0))),
        ArrayComprehension(
            expression=Identifier("x"),
            variable="x",
            iterable=Identifier("xs"),
            condition=BinaryExpression(Identifier("x"), ">", IntegerLiteral(0)),
        ),
        DictComprehension(
            key_expression=Identifier("k"),
            value_expression=Identifier("v"),
            key_variable="k",
            value_variable="v",
            iterable=Identifier("mapping"),
        ),
        PatternMatch(
            value=Identifier("first"),
            cases=[MatchCase(IntegerLiteral(1), BooleanLiteral(True))],
            default=BooleanLiteral(False),
        ),
        WithStatement(
            declarations=[
                WithDeclaration("xs", ListExpression([IntegerLiteral(1)])),
            ],
            body=PatternMatch(
                value=Identifier("xs"),
                cases=[MatchCase(IntegerLiteral(1), BooleanLiteral(True))],
                default=BooleanLiteral(False),
            ),
        ),
    ]

    for node in nodes:
        assert deserialize_node(serialize_node(node)) == node


def test_simple_roundtrip_helpers_preserve_direct_misc_ast_nodes() -> None:
    nodes = [
        Tag("packed"),
        Meta("score", 7),
        Comment("lead", is_multiline=True),
        CommentGroup([Comment("a"), Comment("b", is_multiline=True)]),
        PlainString(
            identifier="$a",
            value="abc",
            modifiers=[StringModifier.from_name_value("wide")],
        ),
        RegexString("$r", [StringModifier.from_name_value("nocase")], "ab.*"),
        HexString(
            "$h",
            [],
            [
                HexByte(0x41),
                HexNegatedByte(0x42),
                HexWildcard(),
                HexJump(1, 3),
                HexAlternative([[HexByte(0x43)], [HexNibble(False, 0xF)]]),
            ],
        ),
        HexByte(0x41),
        HexNegatedByte(0x42),
        HexWildcard(),
        HexJump(1, 3),
        HexNibble(True, 0xA),
        HexAlternative([[HexByte(0x41)], [HexByte(0x42)]]),
        StringModifier.from_name_value("xor", (4, 8)),
        PragmaBlock([CustomPragma("vendor", ["on"])], scope=PragmaScope.RULE),
    ]

    for node in nodes:
        assert deserialize_node(serialize_node(node)) == node


def test_simple_roundtrip_helpers_preserve_node_comment_metadata(tmp_path: Path) -> None:
    plain = PlainString(identifier="$a", value="abc")
    plain.leading_comments = [Comment("string lead", is_multiline=True)]
    condition = StringIdentifier("$a")
    condition.trailing_comment = Comment("condition tail")
    rule = Rule(name="commented", strings=[plain], condition=condition)
    rule.leading_comments = [Comment("rule lead")]
    rule.trailing_comment = Comment("rule tail")
    ast = YaraFile(rules=[rule])
    ast.location = Location(1, 1, file="sample.yar", end_line=6, end_column=1)
    ast.trailing_comment = cast(Any, CommentGroup([Comment("file end"), Comment("final")]))
    path = tmp_path / "comments.json"

    serialize_to_file(ast, path)
    restored = deserialize_from_file(path)

    assert isinstance(restored, YaraFile)
    assert restored.location == Location(1, 1, file="sample.yar", end_line=6, end_column=1)
    assert isinstance(restored.trailing_comment, CommentGroup)
    assert restored.trailing_comment.comments[1].text == "final"
    assert restored.rules[0].leading_comments[0].text == "rule lead"
    assert restored.rules[0].trailing_comment is not None
    assert restored.rules[0].trailing_comment.text == "rule tail"
    restored_plain = restored.rules[0].strings[0]
    assert restored_plain.leading_comments[0].is_multiline is True
    restored_condition = restored.rules[0].condition
    assert restored_condition is not None
    assert restored_condition.trailing_comment is not None
    assert restored_condition.trailing_comment.text == "condition tail"


def test_simple_roundtrip_helpers_compare_and_error_paths(tmp_path: Path) -> None:
    ok, differences = _compare_normalized("a\nb\nc", "a\nb\nc")
    assert ok is True
    assert differences == []

    ok_equal_len, differences_equal_len = _compare_normalized("a\nb\nc", "a\nx\nc")
    assert ok_equal_len is False
    assert differences_equal_len == ["Line 2 differs: 'b' vs 'x'"]

    ok2, differences2 = _compare_normalized(
        "1\n2\n3\n4\n5\n6\n7\n8",
        "x\ny\nz\nu\nv\nw",
    )
    assert ok2 is False
    assert differences2[0].startswith("Line count differs:")
    assert differences2[-1] == "... more differences"

    bad_json = tmp_path / "bad.json"
    bad_json.write_text("{not-json", encoding="utf-8")
    try:
        deserialize_from_file(bad_json)
    except Exception:
        pass
    else:
        raise AssertionError("deserialize_from_file should fail on invalid JSON")

    valid, diff = validate_roundtrip(cast(Any, None))
    assert valid is False
    assert "error" in diff

    fallback = deserialize_string({"type": "HexString", "identifier": "$h", "tokens": "{ 41 }"})
    assert isinstance(fallback, HexString)  # preserves type instead of converting to PlainString
    assert fallback.tokens == [HexByte(value=0x41)]

    negated_hex = deserialize_string(
        {
            "type": "HexString",
            "identifier": "$negated",
            "tokens": [{"type": "HexNegatedByte", "value": 0x4D}],
        }
    )
    assert isinstance(negated_hex, HexString)
    assert negated_hex.tokens == [HexNegatedByte(value=0x4D)]

    with pytest.raises(SerializationError, match="Unknown hex token type"):
        deserialize_string(
            {
                "type": "HexString",
                "identifier": "$bad_hex",
                "tokens": [{"type": "Unknown", "data": "literal"}],
            }
        )

    default_condition_rule = deserialize_rule({"name": "fallback", "condition": None})
    assert isinstance(default_condition_rule.condition, BooleanLiteral)
