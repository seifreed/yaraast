"""Additional real coverage for simple_roundtrip_helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest

from yaraast.ast.base import ASTNode, Location, YaraFile
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
    DoubleLiteral,
    FunctionCall,
    Identifier,
    IntegerLiteral,
    MemberAccess,
    ParenthesesExpression,
    RangeExpression,
    RegexLiteral,
    SetExpression,
    StringCount,
    StringIdentifier,
    StringLength,
    StringLiteral,
    StringOffset,
    StringWildcard,
    UnaryExpression,
)
from yaraast.ast.extern import ExternImport, ExternNamespace, ExternRule, ExternRuleReference
from yaraast.ast.meta import Meta
from yaraast.ast.modifiers import MetaEntry, MetaScope, RuleModifier, StringModifier
from yaraast.ast.modules import DictionaryAccess, ModuleReference
from yaraast.ast.operators import DefinedExpression, StringOperatorExpression
from yaraast.ast.pragmas import (
    CustomPragma,
    InRulePragma,
    Pragma,
    PragmaBlock,
    PragmaScope,
    PragmaType,
)
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
    deserialize_pragma,
    deserialize_rule,
    deserialize_string,
    serialize_extern_rule,
    serialize_meta,
    serialize_node,
    serialize_pragma,
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


class UnsupportedSimpleNode(ASTNode):
    def accept(self, visitor: Any) -> Any:
        return visitor.visit_unsupported_simple_node(self)


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

    with pytest.raises(SerializationError, match="Unknown string type: Import"):
        deserialize_string({"type": "Import", "module": "pe"})

    with pytest.raises(SerializationError, match="String identifier must be a string"):
        deserialize_string({"type": "Unknown", "identifier": ["$x"], "data": "raw"})

    with pytest.raises(SerializationError, match="String data must be a string or bytes"):
        deserialize_string({"type": "Unknown", "identifier": "$x", "data": 7})

    path = tmp_path / "helper.json"
    serialize_to_file(
        YaraFile(imports=[Import(module="pe")], includes=[Include(path="inc.yar")], rules=[rule]),
        path,
    )
    restored_file = deserialize_from_file(path)
    assert isinstance(restored_file, YaraFile)
    assert restored_file.rules[0].name == "helper_rule"


def test_simple_roundtrip_preserves_base_string_definition_fields() -> None:
    string_def = StringDefinition(
        identifier="$z",
        modifiers=[StringModifier.from_name_value("wide")],
        is_anonymous=True,
    )

    restored = deserialize_string(serialize_string(string_def))

    assert isinstance(restored, StringDefinition)
    assert not isinstance(restored, PlainString | HexString | RegexString)
    assert restored.identifier == "$z"
    assert restored.modifiers == [StringModifier.from_name_value("wide")]
    assert restored.is_anonymous is True


def test_simple_roundtrip_deserializes_legacy_hex_xor_modifier_values() -> None:
    key = deserialize_node(
        {
            "type": "PlainString",
            "identifier": "$key",
            "value": "abc",
            "modifiers": [{"name": "xor", "value": "0xff"}],
        }
    )
    range_string = deserialize_node(
        {
            "type": "PlainString",
            "identifier": "$range",
            "value": "abc",
            "modifiers": [{"name": "xor", "value": "0x01-0xff"}],
        }
    )

    assert isinstance(key, PlainString)
    assert isinstance(range_string, PlainString)
    assert key.modifiers[0].value == 255
    assert range_string.modifiers[0].value == (1, 255)


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

    with pytest.raises(SerializationError, match="Meta type must be Meta or MetaEntry"):
        deserialize_meta({"type": "Rule", "key": "author", "value": "me"})

    with pytest.raises(
        SerializationError, match="Meta value must be a string, integer, or boolean"
    ):
        deserialize_meta({"key": "score", "value": 1.5})

    with pytest.raises(
        SerializationError, match="Meta scope must be public, private, or protected"
    ):
        deserialize_meta({"type": "MetaEntry", "key": "owner", "value": "team", "scope": "secret"})

    with pytest.raises(SerializationError, match="Tag name must be a string"):
        deserialize_rule({"name": "r1", "tags": [{"name": 7}], "condition": None})


def test_simple_roundtrip_unknown_node_fallback_rejects_invalid_payload() -> None:
    fallback = deserialize_node({"type": "UnknownNode", "data": "fallback"})
    assert isinstance(fallback, Identifier)
    assert fallback.name == "fallback"

    with pytest.raises(SerializationError, match="Serialized node type must be a string"):
        deserialize_node({"type": ["UnknownNode"], "data": "fallback"})

    with pytest.raises(SerializationError, match="Serialized node data must be a string"):
        deserialize_node({"type": "UnknownNode", "data": ["fallback"]})


def test_simple_roundtrip_serialize_rejects_unsupported_ast_nodes() -> None:
    with pytest.raises(SerializationError, match="Unsupported simple AST node type:"):
        serialize_node(UnsupportedSimpleNode())


def test_simple_roundtrip_ast_and_rule_collections_reject_non_lists() -> None:
    with pytest.raises(SerializationError, match="YaraFile imports must be a list"):
        deserialize_node({"type": "YaraFile", "imports": "pe"})

    with pytest.raises(SerializationError, match="Serialized node must be an object"):
        deserialize_node({"type": "YaraFile", "imports": ["pe"]})

    with pytest.raises(SerializationError, match="YaraFile extern_rules must be a list"):
        deserialize_node({"type": "YaraFile", "extern_rules": "RemoteRule"})

    with pytest.raises(SerializationError, match="YaraFile imports must contain Import nodes"):
        deserialize_node({"type": "YaraFile", "imports": [{"type": "Rule", "name": "not_import"}]})

    with pytest.raises(SerializationError, match="YaraFile includes must contain Include nodes"):
        deserialize_node({"type": "YaraFile", "includes": [{"type": "Import", "module": "pe"}]})

    with pytest.raises(SerializationError, match="YaraFile rules must contain Rule nodes"):
        deserialize_node({"type": "YaraFile", "rules": [{"type": "Import", "module": "pe"}]})

    with pytest.raises(
        SerializationError, match="YaraFile extern_rules must contain ExternRule nodes"
    ):
        deserialize_node({"type": "YaraFile", "extern_rules": [{"type": "Rule", "name": "remote"}]})

    with pytest.raises(
        SerializationError, match="YaraFile extern_imports must contain ExternImport nodes"
    ):
        deserialize_node(
            {"type": "YaraFile", "extern_imports": [{"type": "Import", "module": "pe"}]}
        )

    with pytest.raises(SerializationError, match="YaraFile pragmas must contain Pragma nodes"):
        deserialize_node({"type": "YaraFile", "pragmas": [{"type": "Rule", "name": "not_pragma"}]})

    with pytest.raises(
        SerializationError, match="YaraFile namespaces must contain ExternNamespace nodes"
    ):
        deserialize_node({"type": "YaraFile", "namespaces": [{"type": "Import", "module": "pe"}]})

    with pytest.raises(SerializationError, match="Rule must be an object"):
        deserialize_rule(cast(Any, "rule"))

    with pytest.raises(SerializationError, match="Meta must be an object"):
        deserialize_meta(cast(Any, "meta"))

    with pytest.raises(SerializationError, match="String must be an object"):
        deserialize_string(cast(Any, "string"))

    with pytest.raises(SerializationError, match="Pragma must be an object"):
        deserialize_pragma(cast(Any, "pragma"))

    with pytest.raises(SerializationError, match="Rule meta must be a list"):
        deserialize_rule({"name": "r1", "meta": "author", "condition": None})

    with pytest.raises(SerializationError, match="Rule strings must be a list"):
        deserialize_rule({"name": "r1", "strings": "$a", "condition": None})

    with pytest.raises(SerializationError, match="Rule tags must be a list"):
        deserialize_rule({"name": "r1", "tags": "tag", "condition": None})

    with pytest.raises(SerializationError, match="Rule tags must contain Tag nodes"):
        deserialize_rule(
            {
                "name": "r1",
                "tags": [{"type": "Import", "name": "not_tag", "module": "pe"}],
                "condition": None,
            }
        )

    with pytest.raises(SerializationError, match="Rule pragmas must be a list"):
        deserialize_rule({"name": "r1", "pragmas": "pragma", "condition": None})

    with pytest.raises(SerializationError, match="Rule pragmas must contain InRulePragma nodes"):
        deserialize_rule(
            {
                "name": "r1",
                "pragmas": [{"type": "Pragma", "pragma_type": "custom", "name": "vendor"}],
                "condition": None,
            }
        )

    with pytest.raises(SerializationError, match="Serialized node must be an object"):
        deserialize_rule({"name": "r1", "condition": "true"})

    with pytest.raises(SerializationError, match="PragmaBlock pragmas must be a list"):
        deserialize_node({"type": "PragmaBlock", "pragmas": "pragma"})


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
    invalid_text: Any = 123
    invalid_arguments: Any = "on"
    invalid_argument_item: Any = ["on", 1]
    invalid_parameters: Any = [("key", "value")]
    invalid_parameter_key: Any = {1: "value"}

    pragma_with_bad_type = Pragma(PragmaType.CUSTOM, "vendor")
    cast(Any, pragma_with_bad_type).pragma_type = invalid_text
    with pytest.raises(SerializationError, match="Pragma pragma_type must be a string"):
        serialize_pragma(pragma_with_bad_type)

    with pytest.raises(SerializationError, match="Pragma name must be a string"):
        serialize_pragma(Pragma(PragmaType.CUSTOM, invalid_text))

    for invalid_value in (invalid_arguments, invalid_argument_item):
        pragma_with_bad_arguments = Pragma(PragmaType.CUSTOM, "vendor")
        cast(Any, pragma_with_bad_arguments).arguments = invalid_value
        with pytest.raises(SerializationError, match="Pragma arguments must be a list of strings"):
            serialize_pragma(pragma_with_bad_arguments)

    custom_with_bad_parameters = CustomPragma("vendor")
    cast(Any, custom_with_bad_parameters).parameters = invalid_parameters
    with pytest.raises(SerializationError, match="Pragma parameters must be a dictionary"):
        serialize_pragma(custom_with_bad_parameters)

    custom_with_bad_parameter_key = CustomPragma("vendor")
    cast(Any, custom_with_bad_parameter_key).parameters = invalid_parameter_key
    with pytest.raises(SerializationError, match="Pragma parameters keys must be strings"):
        serialize_pragma(custom_with_bad_parameter_key)

    pragma_with_unknown_scope = Pragma(PragmaType.CUSTOM, "vendor")
    cast(Any, pragma_with_unknown_scope).scope = "secret"
    with pytest.raises(SerializationError, match="Pragma scope must be a valid pragma scope"):
        serialize_pragma(pragma_with_unknown_scope)

    block_with_unknown_scope = PragmaBlock([Pragma(PragmaType.CUSTOM, "vendor")])
    cast(Any, block_with_unknown_scope).scope = "secret"
    with pytest.raises(SerializationError, match="PragmaBlock scope must be a valid pragma scope"):
        serialize_node(block_with_unknown_scope)

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

    with pytest.raises(SerializationError, match="InRulePragma pragma is required"):
        deserialize_node({"type": "InRulePragma", "position": "before_condition"})

    with pytest.raises(SerializationError, match="InRulePragma position must be a string"):
        deserialize_node(
            {
                "type": "InRulePragma",
                "pragma": {"pragma_type": "custom", "name": "vendor"},
                "position": True,
            }
        )


def test_simple_roundtrip_node_metadata_rejects_wrong_scalar_types() -> None:
    with pytest.raises(SerializationError, match="Location line is required"):
        deserialize_node({"type": "Import", "module": "pe", "location": {"column": 1}})

    with pytest.raises(SerializationError, match="Location column is required"):
        deserialize_node({"type": "Import", "module": "pe", "location": {"line": 1}})

    with pytest.raises(SerializationError, match="Location line must be an integer"):
        deserialize_node(
            {"type": "Import", "module": "pe", "location": {"line": True, "column": 1}}
        )

    with pytest.raises(SerializationError, match="Location file must be a string"):
        deserialize_node(
            {"type": "Import", "module": "pe", "location": {"line": 1, "column": 1, "file": []}}
        )

    with pytest.raises(SerializationError, match="location must be an object"):
        deserialize_node({"type": "Import", "module": "pe", "location": "1:1"})

    with pytest.raises(SerializationError, match="leading_comments must be a list"):
        deserialize_node({"type": "Import", "module": "pe", "leading_comments": {}})

    with pytest.raises(SerializationError, match="leading_comments must be a list"):
        deserialize_node(
            {"type": "Import", "module": "pe", "leading_comments": {"type": "Comment"}}
        )

    with pytest.raises(SerializationError, match="trailing_comment must be an object"):
        deserialize_node({"type": "Import", "module": "pe", "trailing_comment": "bad"})

    with pytest.raises(SerializationError, match="CommentGroup comments must be a list"):
        deserialize_node(
            {
                "type": "Import",
                "module": "pe",
                "trailing_comment": {"type": "CommentGroup", "comments": "bad"},
            }
        )

    with pytest.raises(SerializationError, match="Unknown comment metadata type"):
        deserialize_node(
            {
                "type": "Import",
                "module": "pe",
                "leading_comments": [{"type": "UnknownComment", "text": "bad"}],
            }
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

    with pytest.raises(
        SerializationError, match="CommentGroup comments must contain Comment nodes"
    ):
        deserialize_node(
            {
                "type": "Import",
                "module": "pe",
                "trailing_comment": {
                    "type": "CommentGroup",
                    "comments": [
                        {"type": "CommentGroup", "comments": [{"type": "Comment", "text": "bad"}]}
                    ],
                },
            }
        )


def test_simple_roundtrip_node_metadata_preserves_leading_comment_groups() -> None:
    node = deserialize_node(
        {
            "type": "Import",
            "module": "pe",
            "leading_comments": [
                {"type": "CommentGroup", "comments": [{"type": "Comment", "text": "lead"}]}
            ],
        }
    )

    assert isinstance(node.leading_comments[0], CommentGroup)
    assert node.leading_comments[0].comments[0].text == "lead"


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

    invalid_meta = MetaEntry("owner", "team")
    cast(Any, invalid_meta).scope = "secret"
    with pytest.raises(
        SerializationError, match="Meta scope must be public, private, or protected"
    ):
        serialize_meta(invalid_meta)


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


def test_simple_roundtrip_modifier_and_token_collections_reject_non_lists() -> None:
    with pytest.raises(SerializationError, match="Rule modifiers must be a list"):
        deserialize_rule({"name": "r1", "modifiers": "private", "condition": None})

    with pytest.raises(SerializationError, match="Rule modifiers must be a list of strings"):
        deserialize_rule({"name": "r1", "modifiers": [7], "condition": None})

    with pytest.raises(SerializationError, match="ExternRule modifiers must be a list"):
        deserialize_extern_rule({"name": "RemoteRule", "modifiers": "private"})

    with pytest.raises(SerializationError, match="ExternRule modifiers must be a list of strings"):
        deserialize_extern_rule({"name": "RemoteRule", "modifiers": [7]})

    with pytest.raises(SerializationError, match="ExternNamespace extern_rules must be a list"):
        deserialize_node(
            {"type": "ExternNamespace", "name": "remote", "extern_rules": "RemoteRule"}
        )

    with pytest.raises(SerializationError, match="PlainString modifiers must be a list"):
        deserialize_string(
            {"type": "PlainString", "identifier": "$a", "value": "abc", "modifiers": "ascii"}
        )

    with pytest.raises(SerializationError, match="StringModifier name must be a string"):
        deserialize_string(
            {
                "type": "PlainString",
                "identifier": "$a",
                "value": "abc",
                "modifiers": [{"name": 7}],
            }
        )

    with pytest.raises(SerializationError, match="StringModifier must be a string or object"):
        deserialize_string(
            {"type": "PlainString", "identifier": "$a", "value": "abc", "modifiers": [7]}
        )

    with pytest.raises(SerializationError, match="HexAlternative alternatives must be a list"):
        deserialize_string(
            {
                "type": "HexString",
                "identifier": "$h",
                "tokens": [{"type": "HexAlternative", "alternatives": "AA"}],
                "modifiers": [],
            }
        )

    with pytest.raises(SerializationError, match="Hex token must be an object"):
        deserialize_string(
            {"type": "HexString", "identifier": "$h", "tokens": ["AA"], "modifiers": []}
        )


def test_simple_roundtrip_serializers_reject_non_list_collections() -> None:
    rule = Rule(name="r1", condition=BooleanLiteral(True))
    cast(Any, rule).modifiers = "private"
    with pytest.raises(SerializationError, match="Rule modifiers must be a list"):
        serialize_rule(rule)

    cast(Any, rule).modifiers = []
    cast(Any, rule).tags = "tag"
    with pytest.raises(SerializationError, match="Rule tags must be a list"):
        serialize_rule(rule)

    extern_rule = ExternRule(name="RemoteRule")
    cast(Any, extern_rule).modifiers = "private"
    with pytest.raises(SerializationError, match="ExternRule modifiers must be a list"):
        serialize_extern_rule(extern_rule)

    plain = PlainString(identifier="$a", value="abc")
    cast(Any, plain).modifiers = "ascii"
    with pytest.raises(SerializationError, match="PlainString modifiers must be a list"):
        serialize_string(plain)


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

    with pytest.raises(SerializationError, match="PlainString value must be a string or bytes"):
        deserialize_string(
            {
                "type": "PlainString",
                "identifier": "$a",
                "value": 1234,
                "value_encoding": "base64",
                "modifiers": [],
            }
        )

    with pytest.raises(SerializationError, match="HexString identifier must be a string"):
        deserialize_string(
            {"type": "HexString", "identifier": ["$h"], "tokens": [], "modifiers": []}
        )

    with pytest.raises(SerializationError, match="HexString identifier is required"):
        deserialize_string({"type": "HexString", "tokens": 7, "modifiers": []})

    with pytest.raises(SerializationError, match="Invalid legacy HexString tokens"):
        deserialize_string(
            {"type": "HexString", "identifier": "$h", "tokens": "{ GG }", "modifiers": []}
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

    with pytest.raises(SerializationError, match="IntegerLiteral value is required"):
        deserialize_node({"type": "IntegerLiteral"})

    with pytest.raises(SerializationError, match="BooleanLiteral value must be a boolean"):
        deserialize_node({"type": "BooleanLiteral", "value": "false"})

    with pytest.raises(SerializationError, match="DoubleLiteral value must be numeric"):
        deserialize_node({"type": "DoubleLiteral", "value": True})

    with pytest.raises(SerializationError, match="DoubleLiteral value must be numeric"):
        deserialize_node({"type": "DoubleLiteral", "value": "1.5"})

    for invalid_number in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(SerializationError, match="DoubleLiteral value must be finite"):
            deserialize_node({"type": "DoubleLiteral", "value": invalid_number})

    with pytest.raises(SerializationError, match="StringLiteral value must be a string"):
        deserialize_node({"type": "StringLiteral", "value": True})

    with pytest.raises(SerializationError, match="Identifier name must be a string"):
        deserialize_node({"type": "Identifier", "name": ["id"]})

    true_expr = {"type": "BooleanLiteral", "value": True}

    with pytest.raises(SerializationError, match="BinaryExpression left is required"):
        deserialize_node({"type": "BinaryExpression", "operator": "and", "right": true_expr})

    with pytest.raises(SerializationError, match="BinaryExpression right is required"):
        deserialize_node({"type": "BinaryExpression", "left": true_expr, "operator": "and"})

    missing_expression_cases = (
        (
            {"type": "UnaryExpression", "operator": "not"},
            "UnaryExpression operand is required",
        ),
        ({"type": "ParenthesesExpression"}, "ParenthesesExpression expression is required"),
        (
            {"type": "RangeExpression", "high": {"type": "IntegerLiteral", "value": 1}},
            "RangeExpression low is required",
        ),
        (
            {"type": "RangeExpression", "low": {"type": "IntegerLiteral", "value": 1}},
            "RangeExpression high is required",
        ),
        (
            {"type": "ArrayAccess", "index": {"type": "IntegerLiteral", "value": 0}},
            "ArrayAccess array is required",
        ),
        (
            {"type": "ArrayAccess", "array": {"type": "Identifier", "name": "items"}},
            "ArrayAccess index is required",
        ),
        ({"type": "MemberAccess", "member": "name"}, "MemberAccess object is required"),
    )
    for payload, message in missing_expression_cases:
        with pytest.raises(SerializationError, match=message):
            deserialize_node(payload)

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

    with pytest.raises(SerializationError, match="SetExpression elements must be a list"):
        deserialize_node({"type": "SetExpression", "elements": "x"})

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

    int_expr = {"type": "IntegerLiteral", "value": 1}
    missing_condition_cases = (
        (
            {"type": "ForExpression", "variable": "i", "iterable": int_expr, "body": int_expr},
            "ForExpression quantifier is required",
        ),
        (
            {"type": "ForExpression", "quantifier": "any", "variable": "i", "body": int_expr},
            "ForExpression iterable is required",
        ),
        (
            {
                "type": "ForExpression",
                "quantifier": "any",
                "variable": "i",
                "iterable": int_expr,
            },
            "ForExpression body is required",
        ),
        (
            {"type": "ForOfExpression", "string_set": "them"},
            "ForOfExpression quantifier is required",
        ),
        (
            {"type": "ForOfExpression", "quantifier": "any"},
            "ForOfExpression string_set is required",
        ),
        ({"type": "AtExpression", "string_id": "$a"}, "AtExpression offset is required"),
        ({"type": "InExpression", "subject": "$a"}, "InExpression range is required"),
        ({"type": "OfExpression", "string_set": "them"}, "OfExpression quantifier is required"),
        ({"type": "OfExpression", "quantifier": "any"}, "OfExpression string_set is required"),
        ({"type": "DictionaryAccess", "key": "name"}, "DictionaryAccess object is required"),
    )
    for payload, message in missing_condition_cases:
        with pytest.raises(SerializationError, match=message):
            deserialize_node(payload)

    with pytest.raises(SerializationError, match="ModuleReference module must be a string"):
        deserialize_node({"type": "ModuleReference", "module": ["pe"]})

    with pytest.raises(SerializationError, match="ModuleReference module is required"):
        deserialize_node({"type": "ModuleReference"})

    with pytest.raises(SerializationError, match="DictionaryAccess key must be a string"):
        deserialize_node(
            {"type": "DictionaryAccess", "object": {"type": "ModuleReference", "module": "pe"}}
        )

    with pytest.raises(SerializationError, match="DictionaryAccess key must be a string"):
        deserialize_node(
            {
                "type": "DictionaryAccess",
                "object": {"type": "ModuleReference", "module": "pe"},
                "key": ["CompanyName"],
            }
        )

    with pytest.raises(SerializationError, match="RegexLiteral pattern must be a string"):
        deserialize_node({"type": "RegexLiteral", "pattern": 123})

    with pytest.raises(SerializationError, match="RegexLiteral modifiers must be a string"):
        deserialize_node({"type": "RegexLiteral", "pattern": "abc", "modifiers": ["i"]})

    with pytest.raises(SerializationError, match="Serialized node must be an object"):
        deserialize_node({"type": "StringOffset", "string_id": "a", "index": False})

    with pytest.raises(SerializationError, match="Serialized node must be an object"):
        deserialize_node({"type": "StringLength", "string_id": "a", "index": False})


def test_simple_roundtrip_serialize_literal_nodes_reject_wrong_scalar_types() -> None:
    invalid_cases = (
        (IntegerLiteral(cast(Any, True)), "IntegerLiteral value must be an integer"),
        (BooleanLiteral(cast(Any, "false")), "BooleanLiteral value must be a boolean"),
        (DoubleLiteral(cast(Any, True)), "DoubleLiteral value must be numeric"),
        (DoubleLiteral(float("nan")), "DoubleLiteral value must be finite"),
        (DoubleLiteral(float("inf")), "DoubleLiteral value must be finite"),
        (StringLiteral(cast(Any, True)), "StringLiteral value must be a string"),
        (Identifier(cast(Any, ["id"])), "Identifier name must be a string"),
    )

    for node, message in invalid_cases:
        with pytest.raises(SerializationError, match=message):
            serialize_node(node)


def test_simple_roundtrip_serialize_string_reference_nodes_reject_wrong_scalar_types() -> None:
    invalid_cases = (
        (RegexLiteral(cast(Any, 123)), "RegexLiteral pattern must be a string"),
        (RegexLiteral("abc", cast(Any, ["i"])), "RegexLiteral modifiers must be a string"),
        (StringIdentifier(cast(Any, ["$a"])), "StringIdentifier name must be a string"),
        (StringWildcard(cast(Any, ["$a*"])), "StringWildcard pattern must be a string"),
        (StringCount(cast(Any, 7)), "StringCount string_id must be a string"),
        (StringOffset(cast(Any, 7)), "StringOffset string_id must be a string"),
        (StringLength(cast(Any, 7)), "StringLength string_id must be a string"),
    )

    for node, message in invalid_cases:
        with pytest.raises(SerializationError, match=message):
            serialize_node(node)


def test_simple_roundtrip_serialize_expression_scalar_fields_reject_wrong_types() -> None:
    true_expr = BooleanLiteral(True)
    invalid_cases = (
        (
            BinaryExpression(true_expr, cast(Any, ["and"]), BooleanLiteral(False)),
            "BinaryExpression operator must be a string",
        ),
        (
            UnaryExpression(cast(Any, ["not"]), true_expr),
            "UnaryExpression operator must be a string",
        ),
        (FunctionCall(cast(Any, ["fn"]), []), "FunctionCall function must be a string"),
        (
            MemberAccess(Identifier("pe"), cast(Any, ["machine"])),
            "MemberAccess member must be a string",
        ),
        (AtExpression(cast(Any, 7), IntegerLiteral(0)), "AtExpression string_id must be a string"),
        (
            ForExpression("any", cast(Any, ["i"]), SetExpression([]), true_expr),
            "ForExpression variable must be a string",
        ),
        (ModuleReference(cast(Any, ["pe"])), "ModuleReference module must be a string"),
        (
            WithDeclaration(cast(Any, ["x"]), IntegerLiteral(1)),
            "WithDeclaration identifier must be a string",
        ),
        (
            LambdaExpression(cast(Any, "x"), true_expr),
            "LambdaExpression parameters must be a list of strings",
        ),
        (
            SpreadOperator(Identifier("x"), cast(Any, "true")),
            "SpreadOperator is_dict must be a boolean",
        ),
    )

    for node, message in invalid_cases:
        with pytest.raises(SerializationError, match=message):
            serialize_node(node)


def test_simple_roundtrip_serialize_structural_nodes_reject_wrong_scalar_types() -> None:
    invalid_cases = (
        (Import(cast(Any, 123)), "Import module must be a string"),
        (Import("pe", alias=cast(Any, 123)), "Import alias must be a string"),
        (Include(cast(Any, 123)), "Include path must be a string"),
        (Tag(cast(Any, 123)), "Tag name must be a string"),
        (Comment(cast(Any, 123)), "Comment text must be a string"),
        (
            Comment("note", is_multiline=cast(Any, "false")),
            "Comment is_multiline must be a boolean",
        ),
        (Rule(cast(Any, 123), condition=BooleanLiteral(True)), "Rule name must be a string"),
        (ExternRule(cast(Any, 123)), "ExternRule name must be a string"),
        (ExternRule("remote", namespace=cast(Any, 123)), "ExternRule namespace must be a string"),
        (
            ExternRuleReference(cast(Any, 123)),
            "ExternRuleReference rule_name must be a string",
        ),
        (
            ExternRuleReference("remote", namespace=cast(Any, 123)),
            "ExternRuleReference namespace must be a string",
        ),
        (ExternImport(cast(Any, 123)), "ExternImport module_path must be a string"),
        (ExternImport("external", alias=cast(Any, 123)), "ExternImport alias must be a string"),
        (
            ExternImport("external", rules=cast(Any, "RemoteRule")),
            "ExternImport rules must be a list of strings",
        ),
        (ExternNamespace(cast(Any, 123)), "ExternNamespace name must be a string"),
    )

    for node, message in invalid_cases:
        with pytest.raises(SerializationError, match=message):
            serialize_node(node)


def test_simple_roundtrip_serialize_meta_string_and_pragma_fields_reject_wrong_types() -> None:
    invalid_cases = (
        (Meta(cast(Any, 123), "value"), "Meta key must be a string"),
        (Meta("key", cast(Any, 1.2)), "Meta value must be a string, integer, or boolean"),
        (
            PlainString(identifier=cast(Any, 123), value="abc"),
            "PlainString identifier must be a string",
        ),
        (
            HexString(identifier=cast(Any, 123), tokens=[]),
            "HexString identifier must be a string",
        ),
        (
            RegexString(identifier=cast(Any, 123), regex="abc"),
            "RegexString identifier must be a string",
        ),
        (RegexString(identifier="$r", regex=cast(Any, 123)), "RegexString regex must be a string"),
        (
            StringModifier(cast(Any, 123)),
            "StringModifier name must be a string",
        ),
        (
            InRulePragma(Pragma(PragmaType.CUSTOM, "vendor"), cast(Any, 123)),
            "InRulePragma position must be a string",
        ),
    )

    for node, message in invalid_cases:
        with pytest.raises(SerializationError, match=message):
            serialize_node(node)


def test_simple_roundtrip_serialize_hex_tokens_and_location_reject_wrong_types() -> None:
    invalid_alternatives = HexAlternative([[HexByte(0x90)]])
    cast(Any, invalid_alternatives).alternatives = False
    invalid_alternative_token = HexAlternative([[object()]])

    invalid_nodes = (
        (HexByte(cast(Any, True)), "HexByte value must be a byte"),
        (HexByte(cast(Any, "GG")), "HexByte value must be a byte"),
        (HexNegatedByte(cast(Any, True)), "HexNegatedByte value must be a byte"),
        (HexJump(cast(Any, True), 3), "HexJump min_jump must be a non-negative integer"),
        (HexJump(5, 3), "HexJump min_jump cannot exceed max_jump"),
        (HexNibble(cast(Any, "true"), 10), "HexNibble high must be a boolean"),
        (HexNibble(True, cast(Any, True)), "HexNibble value must be a nibble"),
        (HexNibble(True, 16), "HexNibble value must be a nibble"),
        (invalid_alternatives, "HexAlternative alternatives must be a list"),
        (invalid_alternative_token, "Unsupported hex token type: object"),
        (
            HexString(identifier="$h", tokens=[cast(Any, object())]),
            "Unsupported hex token type: object",
        ),
    )

    for node, message in invalid_nodes:
        with pytest.raises(SerializationError, match=message):
            serialize_node(node)

    import_with_bad_line = Import("pe")
    import_with_bad_line.location = Location(cast(Any, True), 1)
    with pytest.raises(SerializationError, match="Location line must be an integer"):
        serialize_node(import_with_bad_line)

    import_with_bad_file = Import("pe")
    import_with_bad_file.location = Location(1, 1, file=cast(Any, []))
    with pytest.raises(SerializationError, match="Location file must be a string"):
        serialize_node(import_with_bad_file)


def test_simple_roundtrip_string_set_values_reject_empty_payloads() -> None:
    empty_string_set_cases: tuple[tuple[dict[str, Any], str], ...] = (
        (
            {"type": "ForOfExpression", "quantifier": "any", "string_set": None},
            "ForOfExpression string_set is required",
        ),
        (
            {"type": "ForOfExpression", "quantifier": "any", "string_set": {}},
            "ForOfExpression string_set is required",
        ),
        (
            {"type": "ForOfExpression", "quantifier": "any", "string_set": [None]},
            "ForOfExpression string_set must contain values",
        ),
        (
            {"type": "ForOfExpression", "quantifier": "any", "string_set": [{}]},
            "ForOfExpression string_set must contain values",
        ),
        (
            {"type": "OfExpression", "quantifier": "any", "string_set": None},
            "OfExpression string_set is required",
        ),
        (
            {"type": "OfExpression", "quantifier": "any", "string_set": {}},
            "OfExpression string_set is required",
        ),
        (
            {"type": "OfExpression", "quantifier": "any", "string_set": [None]},
            "OfExpression string_set must contain values",
        ),
        (
            {"type": "OfExpression", "quantifier": "any", "string_set": [{}]},
            "OfExpression string_set must contain values",
        ),
    )
    for payload, message in empty_string_set_cases:
        with pytest.raises(SerializationError, match=message):
            deserialize_node(payload)


def test_simple_roundtrip_string_sets_reject_invalid_raw_values() -> None:
    invalid_string_set_cases: tuple[tuple[dict[str, Any], str], ...] = (
        (
            {"type": "ForOfExpression", "quantifier": "any", "string_set": True},
            "ForOfExpression string_set must be",
        ),
        (
            {"type": "OfExpression", "quantifier": "any", "string_set": 123},
            "OfExpression string_set must be",
        ),
        (
            {"type": "ForOfExpression", "quantifier": "any", "string_set": ["$a", False]},
            "ForOfExpression string_set must contain strings or expressions",
        ),
        (
            {"type": "OfExpression", "quantifier": "any", "string_set": ["$a", 123]},
            "OfExpression string_set must contain strings or expressions",
        ),
    )
    for payload, message in invalid_string_set_cases:
        with pytest.raises(SerializationError, match=message):
            deserialize_node(payload)


def test_simple_roundtrip_quantifiers_reject_invalid_raw_values() -> None:
    int_expr = {"type": "IntegerLiteral", "value": 1}

    invalid_quantifier_cases: tuple[dict[str, Any], ...] = (
        {
            "type": "ForExpression",
            "quantifier": [int_expr],
            "variable": "i",
            "iterable": int_expr,
            "body": int_expr,
        },
        {
            "type": "ForOfExpression",
            "quantifier": [int_expr],
            "string_set": "them",
        },
        {
            "type": "OfExpression",
            "quantifier": [int_expr],
            "string_set": "them",
        },
        {
            "type": "ForExpression",
            "quantifier": True,
            "variable": "i",
            "iterable": int_expr,
            "body": int_expr,
        },
        {
            "type": "ForOfExpression",
            "quantifier": False,
            "string_set": "them",
        },
        {
            "type": "OfExpression",
            "quantifier": True,
            "string_set": "them",
        },
    )
    for payload in invalid_quantifier_cases:
        with pytest.raises(SerializationError, match="quantifier must be"):
            deserialize_node(payload)

    non_finite_quantifier_cases: tuple[tuple[dict[str, Any], str], ...] = (
        (
            {
                "type": "ForExpression",
                "quantifier": float("nan"),
                "variable": "i",
                "iterable": int_expr,
                "body": int_expr,
            },
            "ForExpression quantifier must be finite",
        ),
        (
            {
                "type": "ForOfExpression",
                "quantifier": float("inf"),
                "string_set": "them",
            },
            "ForOfExpression quantifier must be finite",
        ),
        (
            {
                "type": "OfExpression",
                "quantifier": float("-inf"),
                "string_set": "them",
            },
            "OfExpression quantifier must be finite",
        ),
    )
    for payload, message in non_finite_quantifier_cases:
        with pytest.raises(SerializationError, match=message):
            deserialize_node(payload)


def test_simple_roundtrip_extended_expression_fields_reject_wrong_scalar_types() -> None:
    true_expr = {"type": "BooleanLiteral", "value": True}

    with pytest.raises(SerializationError, match="FunctionCall arguments must be a list"):
        deserialize_node({"type": "FunctionCall", "function": "fn", "arguments": "abc"})

    with pytest.raises(SerializationError, match="WithDeclaration identifier must be a string"):
        deserialize_node({"type": "WithDeclaration", "identifier": ["x"], "value": true_expr})

    with pytest.raises(SerializationError, match="WithStatement declarations must be a list"):
        deserialize_node({"type": "WithStatement", "declarations": "x", "body": true_expr})

    with pytest.raises(SerializationError, match="ArrayComprehension variable must be a string"):
        deserialize_node({"type": "ArrayComprehension", "variable": ["x"]})

    with pytest.raises(SerializationError, match="Serialized node must be an object"):
        deserialize_node({"type": "ArrayComprehension", "expression": False})

    with pytest.raises(
        SerializationError, match="DictComprehension value_variable must be a string"
    ):
        deserialize_node({"type": "DictComprehension", "key_variable": "k", "value_variable": True})

    with pytest.raises(SerializationError, match="TupleExpression elements must be a list"):
        deserialize_node({"type": "TupleExpression", "elements": "abc"})

    missing_extended_cases = (
        ({"type": "WithStatement", "declarations": []}, "WithStatement body is required"),
        ({"type": "WithDeclaration", "identifier": "x"}, "WithDeclaration value is required"),
        (
            {"type": "TupleIndexing", "index": true_expr},
            "TupleIndexing tuple_expr is required",
        ),
        (
            {"type": "TupleIndexing", "tuple_expr": {"type": "TupleExpression", "elements": []}},
            "TupleIndexing index is required",
        ),
        ({"type": "DictItem", "value": true_expr}, "DictItem key is required"),
        ({"type": "DictItem", "key": true_expr}, "DictItem value is required"),
        ({"type": "SliceExpression"}, "SliceExpression target is required"),
        ({"type": "LambdaExpression", "parameters": ["x"]}, "LambdaExpression body is required"),
        ({"type": "PatternMatch", "cases": []}, "PatternMatch value is required"),
        ({"type": "MatchCase", "result": true_expr}, "MatchCase pattern is required"),
        ({"type": "MatchCase", "pattern": true_expr}, "MatchCase result is required"),
        ({"type": "SpreadOperator"}, "SpreadOperator expression is required"),
    )
    for payload, message in missing_extended_cases:
        with pytest.raises(SerializationError, match=message):
            deserialize_node(payload)

    with pytest.raises(
        SerializationError, match="LambdaExpression parameters must be a list of strings"
    ):
        deserialize_node({"type": "LambdaExpression", "parameters": "xy", "body": true_expr})

    with pytest.raises(SerializationError, match="PatternMatch cases must be a list"):
        deserialize_node({"type": "PatternMatch", "value": true_expr, "cases": "case"})

    with pytest.raises(SerializationError, match="Serialized node must be an object"):
        deserialize_node({"type": "Rule", "name": "bad_condition", "condition": False})

    with pytest.raises(SerializationError, match="Serialized node must be an object"):
        deserialize_node(
            {
                "type": "ForOfExpression",
                "quantifier": "any",
                "string_set": "them",
                "condition": False,
            }
        )

    with pytest.raises(SerializationError, match="SpreadOperator is_dict must be a boolean"):
        deserialize_node({"type": "SpreadOperator", "expression": true_expr, "is_dict": "yes"})


def test_simple_roundtrip_condition_fields_reject_wrong_scalar_types() -> None:
    true_expr = {"type": "BooleanLiteral", "value": True}

    with pytest.raises(SerializationError, match="ForExpression variable must be a string"):
        deserialize_node(
            {
                "type": "ForExpression",
                "quantifier": "any",
                "variable": ["i"],
                "iterable": true_expr,
                "body": true_expr,
            }
        )

    with pytest.raises(SerializationError, match="InExpression subject must be a string"):
        deserialize_node(
            {
                "type": "InExpression",
                "subject": ["$a"],
                "range": true_expr,
            }
        )


def test_simple_roundtrip_optional_expression_fields_reject_empty_objects() -> None:
    true_expr = {"type": "BooleanLiteral", "value": True}

    with pytest.raises(SerializationError, match="Rule condition must be an expression"):
        deserialize_rule({"name": "bad_condition", "condition": {}})

    empty_optional_cases: tuple[tuple[dict[str, Any], str], ...] = (
        (
            {"type": "StringOffset", "string_id": "$a", "index": {}},
            "StringOffset index must be an expression",
        ),
        (
            {"type": "StringLength", "string_id": "$a", "index": {}},
            "StringLength index must be an expression",
        ),
        (
            {
                "type": "ForOfExpression",
                "quantifier": "any",
                "string_set": "them",
                "condition": {},
            },
            "ForOfExpression condition must be an expression",
        ),
        (
            {"type": "ArrayComprehension", "expression": {}},
            "ArrayComprehension expression must be an expression",
        ),
        (
            {"type": "ArrayComprehension", "iterable": {}},
            "ArrayComprehension iterable must be an expression",
        ),
        (
            {"type": "ArrayComprehension", "condition": {}},
            "ArrayComprehension condition must be an expression",
        ),
        (
            {"type": "DictComprehension", "key_expression": {}},
            "DictComprehension key_expression must be an expression",
        ),
        (
            {"type": "DictComprehension", "value_expression": {}},
            "DictComprehension value_expression must be an expression",
        ),
        (
            {"type": "DictComprehension", "iterable": {}},
            "DictComprehension iterable must be an expression",
        ),
        (
            {"type": "DictComprehension", "condition": {}},
            "DictComprehension condition must be an expression",
        ),
        (
            {"type": "SliceExpression", "target": true_expr, "start": {}},
            "SliceExpression start must be an expression",
        ),
        (
            {"type": "SliceExpression", "target": true_expr, "stop": {}},
            "SliceExpression stop must be an expression",
        ),
        (
            {"type": "SliceExpression", "target": true_expr, "step": {}},
            "SliceExpression step must be an expression",
        ),
        (
            {"type": "PatternMatch", "value": true_expr, "cases": [], "default": {}},
            "PatternMatch default must be an expression",
        ),
    )
    for payload, message in empty_optional_cases:
        with pytest.raises(SerializationError, match=message):
            deserialize_node(payload)


def test_simple_roundtrip_required_expression_fields_reject_empty_objects() -> None:
    true_expr = {"type": "BooleanLiteral", "value": True}
    int_expr = {"type": "IntegerLiteral", "value": 1}

    empty_required_cases: tuple[tuple[dict[str, Any], str], ...] = (
        (
            {"type": "BinaryExpression", "left": {}, "operator": "and", "right": true_expr},
            "BinaryExpression left is required",
        ),
        (
            {"type": "UnaryExpression", "operator": "not", "operand": {}},
            "UnaryExpression operand is required",
        ),
        (
            {"type": "ParenthesesExpression", "expression": {}},
            "ParenthesesExpression expression is required",
        ),
        (
            {"type": "RangeExpression", "low": {}, "high": int_expr},
            "RangeExpression low is required",
        ),
        (
            {"type": "ArrayAccess", "array": {}, "index": int_expr},
            "ArrayAccess array is required",
        ),
        (
            {"type": "MemberAccess", "object": {}, "member": "name"},
            "MemberAccess object is required",
        ),
        (
            {
                "type": "ForExpression",
                "quantifier": "any",
                "iterable": {},
                "body": true_expr,
            },
            "ForExpression iterable is required",
        ),
        (
            {"type": "AtExpression", "string_id": "$a", "offset": {}},
            "AtExpression offset is required",
        ),
        (
            {"type": "InExpression", "subject": {}, "range": int_expr},
            "InExpression subject is required",
        ),
        (
            {"type": "InExpression", "subject": "$a", "range": {}},
            "InExpression range is required",
        ),
        (
            {"type": "DictionaryAccess", "object": {}, "key": "name"},
            "DictionaryAccess object is required",
        ),
        (
            {"type": "DefinedExpression", "expression": {}},
            "DefinedExpression expression is required",
        ),
        (
            {
                "type": "StringOperatorExpression",
                "left": {},
                "operator": "contains",
                "right": true_expr,
            },
            "StringOperatorExpression left is required",
        ),
        (
            {
                "type": "StringOperatorExpression",
                "left": true_expr,
                "operator": "contains",
                "right": {},
            },
            "StringOperatorExpression right is required",
        ),
        (
            {"type": "WithStatement", "declarations": [], "body": {}},
            "WithStatement body is required",
        ),
        (
            {"type": "WithDeclaration", "identifier": "x", "value": {}},
            "WithDeclaration value is required",
        ),
        (
            {"type": "TupleIndexing", "tuple_expr": {}, "index": int_expr},
            "TupleIndexing tuple_expr is required",
        ),
        (
            {"type": "DictItem", "key": {}, "value": int_expr},
            "DictItem key is required",
        ),
        (
            {"type": "SliceExpression", "target": {}},
            "SliceExpression target is required",
        ),
        (
            {"type": "LambdaExpression", "parameters": ["x"], "body": {}},
            "LambdaExpression body is required",
        ),
        (
            {"type": "PatternMatch", "value": {}, "cases": []},
            "PatternMatch value is required",
        ),
        (
            {"type": "MatchCase", "pattern": {}, "result": true_expr},
            "MatchCase pattern is required",
        ),
        (
            {"type": "SpreadOperator", "expression": {}},
            "SpreadOperator expression is required",
        ),
    )
    for payload, message in empty_required_cases:
        with pytest.raises(SerializationError, match=message):
            deserialize_node(payload)


def test_simple_roundtrip_expression_lists_reject_empty_items() -> None:
    true_expr = {"type": "BooleanLiteral", "value": True}

    empty_list_item_cases: tuple[tuple[dict[str, Any], str], ...] = (
        (
            {"type": "SetExpression", "elements": [{}]},
            "SetExpression elements must contain nodes",
        ),
        (
            {"type": "FunctionCall", "function": "fn", "arguments": [{}]},
            "FunctionCall arguments must contain nodes",
        ),
        (
            {"type": "WithStatement", "declarations": [{}], "body": true_expr},
            "WithStatement declarations must contain nodes",
        ),
        (
            {"type": "TupleExpression", "elements": [{}]},
            "TupleExpression elements must contain nodes",
        ),
        (
            {"type": "ListExpression", "elements": [{}]},
            "ListExpression elements must contain nodes",
        ),
        (
            {"type": "DictExpression", "items": [{}]},
            "DictExpression items must contain nodes",
        ),
        (
            {"type": "PatternMatch", "value": true_expr, "cases": [{}]},
            "PatternMatch cases must contain nodes",
        ),
    )
    for payload, message in empty_list_item_cases:
        with pytest.raises(SerializationError, match=message):
            deserialize_node(payload)


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

    negated_nibble_hex = deserialize_string(
        {
            "type": "HexString",
            "identifier": "$negated_nibble",
            "tokens": [{"type": "HexNegatedByte", "value": "?0"}],
        }
    )
    assert isinstance(negated_nibble_hex, HexString)
    assert negated_nibble_hex.tokens == [HexNegatedByte(value="?0")]
    assert serialize_string(negated_nibble_hex)["tokens"] == [
        {"type": "HexNegatedByte", "value": "?0"}
    ]

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
