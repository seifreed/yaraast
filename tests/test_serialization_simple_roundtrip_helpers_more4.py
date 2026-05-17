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
    deserialize_extern_rule,
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


def test_simple_roundtrip_rule_metadata_nodes_reject_wrong_scalar_types() -> None:
    with pytest.raises(SerializationError, match="Import module must be a string"):
        deserialize_node({"type": "Import", "module": ["pe"]})

    with pytest.raises(SerializationError, match="Import alias must be a string"):
        deserialize_node({"type": "Import", "module": "pe", "alias": True})

    with pytest.raises(SerializationError, match="Include path must be a string"):
        deserialize_node({"type": "Include", "path": ["x.yar"]})

    with pytest.raises(SerializationError, match="Rule name must be a string"):
        deserialize_rule({"name": ["r1"], "condition": None})

    with pytest.raises(SerializationError, match="Tag name must be a string"):
        deserialize_node({"type": "Tag", "name": 7})

    with pytest.raises(SerializationError, match="Meta key must be a string"):
        deserialize_meta({"key": ["author"], "value": "me"})

    with pytest.raises(
        SerializationError, match="Meta value must be a string, integer, or boolean"
    ):
        deserialize_meta({"key": "score", "value": 1.5})

    with pytest.raises(SerializationError, match="Tag name must be a string"):
        deserialize_rule({"name": "r1", "tags": [{"name": 7}], "condition": None})


def test_simple_roundtrip_extern_nodes_reject_wrong_scalar_types() -> None:
    with pytest.raises(SerializationError, match="ExternImport module_path must be a string"):
        deserialize_node({"type": "ExternImport", "module_path": ["external"]})

    with pytest.raises(SerializationError, match="ExternImport alias must be a string"):
        deserialize_node({"type": "ExternImport", "module_path": "external", "alias": True})

    with pytest.raises(SerializationError, match="ExternImport rules must be a list of strings"):
        deserialize_node({"type": "ExternImport", "module_path": "external", "rules": "RuleA"})

    with pytest.raises(SerializationError, match="ExternRule name must be a string"):
        deserialize_extern_rule({"name": ["RuleA"]})

    with pytest.raises(SerializationError, match="ExternRule namespace must be a string"):
        deserialize_extern_rule({"name": "RuleA", "namespace": True})

    with pytest.raises(SerializationError, match="ExternNamespace name must be a string"):
        deserialize_node({"type": "ExternNamespace", "name": ["ns"]})

    with pytest.raises(SerializationError, match="ExternRuleReference rule_name must be a string"):
        deserialize_node({"type": "ExternRuleReference", "rule_name": ["RuleA"]})

    with pytest.raises(SerializationError, match="ExternRuleReference namespace must be a string"):
        deserialize_node({"type": "ExternRuleReference", "rule_name": "RuleA", "namespace": True})


def test_simple_roundtrip_pragmas_reject_wrong_scalar_types() -> None:
    with pytest.raises(SerializationError, match="Pragma name must be a string"):
        deserialize_node({"type": "Pragma", "pragma_type": "custom", "name": ["vendor"]})

    with pytest.raises(SerializationError, match="Pragma arguments must be a list of strings"):
        deserialize_node(
            {"type": "Pragma", "pragma_type": "custom", "name": "vendor", "arguments": "on"}
        )

    with pytest.raises(SerializationError, match="Pragma parameters must be a dictionary"):
        deserialize_node(
            {
                "type": "Pragma",
                "pragma_type": "custom",
                "name": "vendor",
                "parameters": ["level", "strict"],
            }
        )

    with pytest.raises(SerializationError, match="Pragma macro_name must be a string"):
        deserialize_node({"type": "Pragma", "pragma_type": "define", "macro_name": True})

    with pytest.raises(SerializationError, match="Pragma macro_value must be a string"):
        deserialize_node(
            {
                "type": "Pragma",
                "pragma_type": "define",
                "macro_name": "LIMIT",
                "macro_value": ["10"],
            }
        )

    with pytest.raises(SerializationError, match="Pragma condition must be a string"):
        deserialize_node({"type": "Pragma", "pragma_type": "ifdef", "condition": True})

    with pytest.raises(SerializationError, match="InRulePragma position must be a string"):
        deserialize_node(
            {
                "type": "InRulePragma",
                "pragma": {"pragma_type": "custom", "name": "vendor"},
                "position": True,
            }
        )


def test_simple_roundtrip_node_metadata_rejects_wrong_scalar_types() -> None:
    with pytest.raises(SerializationError, match="Location line must be an integer"):
        deserialize_node(
            {"type": "Import", "module": "pe", "location": {"line": True, "column": 1}}
        )

    with pytest.raises(SerializationError, match="Location file must be a string"):
        deserialize_node(
            {"type": "Import", "module": "pe", "location": {"line": 1, "column": 1, "file": []}}
        )

    with pytest.raises(SerializationError, match="leading_comments must be a list"):
        deserialize_node(
            {"type": "Import", "module": "pe", "leading_comments": {"type": "Comment"}}
        )

    with pytest.raises(SerializationError, match="Comment text must be a string"):
        deserialize_node(
            {
                "type": "Import",
                "module": "pe",
                "leading_comments": [{"type": "Comment", "text": ["bad"]}],
            }
        )

    with pytest.raises(SerializationError, match="Comment is_multiline must be a boolean"):
        deserialize_node(
            {
                "type": "Import",
                "module": "pe",
                "leading_comments": [{"type": "Comment", "text": "bad", "is_multiline": "yes"}],
            }
        )


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


def test_simple_roundtrip_helpers_preserve_unknown_extern_rule_modifier() -> None:
    restored = deserialize_node(
        {
            "type": "ExternRule",
            "name": "RemoteRule",
            "modifiers": ["private", "vendor_modifier"],
        }
    )

    assert isinstance(restored, ExternRule)
    modifiers = cast(list[Any], restored.modifiers)
    assert isinstance(modifiers[0], RuleModifier)
    assert modifiers[0].name == "private"
    assert modifiers[1] == "vendor_modifier"


def test_simple_roundtrip_helpers_preserve_string_modifier_aliases() -> None:
    regex = RegexString(
        identifier="$r",
        regex="ab.*",
        modifiers=["i", "s", StringModifier.from_name_value("fullword")],
    )
    plain = PlainString(
        identifier="$a",
        value="abc",
        modifiers=["vendor_modifier"],
    )

    restored_regex = deserialize_node(serialize_node(regex))
    restored_plain = deserialize_node(serialize_node(plain))
    escaped_plain = deserialize_string(
        {
            "type": "PlainString",
            "identifier": "$b",
            "value": "abc",
            "modifiers": [{"name": "vendor_modifier", "value": 'a"\\b\n'}],
        }
    )

    assert isinstance(restored_regex, RegexString)
    regex_modifiers = restored_regex.modifiers
    assert regex_modifiers[:2] == ["i", "s"]
    assert isinstance(regex_modifiers[2], StringModifier)
    assert regex_modifiers[2].name == "fullword"
    assert isinstance(restored_plain, PlainString)
    assert restored_plain.modifiers == ["vendor_modifier"]
    assert isinstance(escaped_plain, PlainString)
    assert escaped_plain.modifiers == ['vendor_modifier("a\\"\\\\b\\n")']


def test_simple_roundtrip_deserialize_string_requires_literal_true_for_anonymous_flag() -> None:
    plain = deserialize_string(
        {
            "type": "PlainString",
            "identifier": "$a",
            "value": "abc",
            "modifiers": [],
            "is_anonymous": "false",
        }
    )

    assert isinstance(plain, PlainString)
    assert plain.is_anonymous is False


def test_simple_roundtrip_deserialize_strings_reject_wrong_scalar_types() -> None:
    with pytest.raises(SerializationError, match="PlainString identifier must be a string"):
        deserialize_string(
            {"type": "PlainString", "identifier": ["$a"], "value": "abc", "modifiers": []}
        )

    with pytest.raises(SerializationError, match="PlainString value must be a string or bytes"):
        deserialize_string(
            {"type": "PlainString", "identifier": "$a", "value": True, "modifiers": []}
        )

    with pytest.raises(SerializationError, match="HexString identifier must be a string"):
        deserialize_string(
            {"type": "HexString", "identifier": ["$h"], "tokens": [], "modifiers": []}
        )

    with pytest.raises(SerializationError, match="RegexString regex must be a string"):
        deserialize_string(
            {"type": "RegexString", "identifier": "$r", "regex": 123, "modifiers": []}
        )


def test_simple_roundtrip_hex_tokens_reject_invalid_scalar_fields() -> None:
    for token in (
        {"type": "HexByte", "value": True},
        {"type": "HexByte", "value": "GG"},
        {"type": "HexNegatedByte", "value": True},
        {"type": "HexJump", "min_jump": True, "max_jump": 3},
        {"type": "HexJump", "min_jump": 5, "max_jump": 3},
        {"type": "HexNibble", "high": "true", "value": 10},
        {"type": "HexNibble", "high": True, "value": True},
        {"type": "HexNibble", "high": True, "value": 16},
    ):
        with pytest.raises(SerializationError):
            deserialize_string(
                {"type": "HexString", "identifier": "$h", "tokens": [token], "modifiers": []}
            )


def test_simple_roundtrip_deserialize_literal_nodes_reject_wrong_scalar_types() -> None:
    with pytest.raises(SerializationError, match="IntegerLiteral value must be an integer"):
        deserialize_node({"type": "IntegerLiteral", "value": True})

    with pytest.raises(SerializationError, match="BooleanLiteral value must be a boolean"):
        deserialize_node({"type": "BooleanLiteral", "value": "false"})

    with pytest.raises(SerializationError, match="DoubleLiteral value must be numeric"):
        deserialize_node({"type": "DoubleLiteral", "value": True})

    with pytest.raises(SerializationError, match="DoubleLiteral value must be numeric"):
        deserialize_node({"type": "DoubleLiteral", "value": "1.5"})

    with pytest.raises(SerializationError, match="StringLiteral value must be a string"):
        deserialize_node({"type": "StringLiteral", "value": True})

    with pytest.raises(SerializationError, match="Identifier name must be a string"):
        deserialize_node({"type": "Identifier", "name": ["id"]})

    true_expr = {"type": "BooleanLiteral", "value": True}

    with pytest.raises(SerializationError, match="BinaryExpression operator must be a string"):
        deserialize_node(
            {
                "type": "BinaryExpression",
                "left": true_expr,
                "operator": ["and"],
                "right": true_expr,
            }
        )

    with pytest.raises(SerializationError, match="UnaryExpression operator must be a string"):
        deserialize_node({"type": "UnaryExpression", "operator": ["not"], "operand": true_expr})

    with pytest.raises(SerializationError, match="FunctionCall function must be a string"):
        deserialize_node({"type": "FunctionCall", "function": ["fn"], "arguments": []})

    with pytest.raises(SerializationError, match="MemberAccess member must be a string"):
        deserialize_node(
            {"type": "MemberAccess", "object": {"type": "Identifier", "name": "pe"}, "member": []}
        )

    with pytest.raises(SerializationError, match="AtExpression string_id must be a string"):
        deserialize_node(
            {
                "type": "AtExpression",
                "string_id": ["$a"],
                "offset": {"type": "IntegerLiteral", "value": 0},
            }
        )

    with pytest.raises(SerializationError, match="ModuleReference module must be a string"):
        deserialize_node({"type": "ModuleReference", "module": ["pe"]})

    with pytest.raises(SerializationError, match="RegexLiteral pattern must be a string"):
        deserialize_node({"type": "RegexLiteral", "pattern": 123})

    with pytest.raises(SerializationError, match="RegexLiteral modifiers must be a string"):
        deserialize_node({"type": "RegexLiteral", "pattern": "abc", "modifiers": ["i"]})


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

    scalar_alt = deserialize_node(serialize_node(HexAlternative([0x90, "91"])))
    assert scalar_alt == HexAlternative([[HexByte(0x90)], [HexByte("91")]])


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
