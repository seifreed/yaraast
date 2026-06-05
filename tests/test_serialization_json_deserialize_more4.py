"""More branch coverage for JSON deserialization helpers."""

from __future__ import annotations

from typing import Any, cast

import pytest

from yaraast.ast.comments import CommentGroup
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
from yaraast.ast.meta import Meta
from yaraast.ast.modifiers import StringModifier
from yaraast.ast.modules import DictionaryAccess, ModuleReference
from yaraast.ast.rules import Import, Include, Rule
from yaraast.ast.strings import (
    HexByte,
    HexJump,
    HexNegatedByte,
    HexString,
    HexWildcard,
    PlainString,
    RegexString,
    StringDefinition,
)
from yaraast.errors import SerializationError
from yaraast.serialization.json_serializer import JsonSerializer


def _serialized_json_pragma(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "type": "Pragma",
        "pragma_type": "custom",
        "name": "vendor",
        "arguments": [],
        "scope": "file",
        "parameters": {},
    }
    data.update(overrides)
    return data


def _serialized_json_rule(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "type": "Rule",
        "name": "r1",
        "modifiers": [],
        "tags": [],
        "meta": [],
        "strings": [],
        "condition": None,
        "pragmas": [],
    }
    data.update(overrides)
    return data


def _serialized_json_yarafile(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "type": "YaraFile",
        "imports": [],
        "includes": [],
        "rules": [],
        "extern_rules": [],
        "extern_imports": [],
        "pragmas": [],
        "namespaces": [],
    }
    data.update(overrides)
    return data


def test_deserialize_import_include_meta_and_rule_meta_variants() -> None:
    s = JsonSerializer()

    imp = s._deserialize_import({"module": "pe", "alias": "p"})
    inc = s._deserialize_include({"path": "x.yar"})
    assert isinstance(imp, Import)
    assert isinstance(inc, Include)

    meta = s._deserialize_meta({"key": "author", "value": "me"})
    assert meta.key == "author"
    typed_meta = s._deserialize_meta({"type": "Meta", "key": "author", "value": "me"})
    assert isinstance(typed_meta, Meta)
    typed_meta_entry = s._deserialize_meta({"type": "MetaEntry", "key": "owner", "value": "team"})
    assert not isinstance(typed_meta_entry, Meta)
    float_meta_entry = s._deserialize_meta({"type": "MetaEntry", "key": "score", "value": 1.5})
    assert float_meta_entry.value == 1.5

    rule_dict_meta = s._deserialize_rule(
        _serialized_json_rule(
            modifiers=["private"],
            tags=[{"name": "t1"}],
            meta={"a": 1, "b": "x", "score": 1.5},
            strings=[{"type": "PlainString", "identifier": "$a", "value": "x", "modifiers": []}],
            condition={"type": "Identifier", "name": "true"},
        )
    )
    assert isinstance(rule_dict_meta, Rule)
    assert len(rule_dict_meta.meta) == 3
    assert rule_dict_meta.meta[2].value == 1.5

    rule_list_meta = s._deserialize_rule(
        _serialized_json_rule(name="r2", meta=[{"key": "k", "value": 1}])
    )
    assert rule_list_meta.condition is None


def test_json_deserialize_rule_metadata_nodes_reject_wrong_scalar_types() -> None:
    s = JsonSerializer()
    true_expr = {"type": "BooleanLiteral", "value": True}

    with pytest.raises(SerializationError, match="Import module must be a string"):
        s._deserialize_import({"module": ["pe"]})

    with pytest.raises(SerializationError, match="Import module must not be empty"):
        s._deserialize_import({"module": ""})

    with pytest.raises(SerializationError, match="Import module must not be empty"):
        s._deserialize_import({"module": "   "})

    with pytest.raises(SerializationError, match="Import alias must be a string"):
        s._deserialize_import({"module": "pe", "alias": True})

    with pytest.raises(SerializationError, match="Import alias is required"):
        s._deserialize_import({"module": "pe"})

    with pytest.raises(SerializationError, match="Import alias must not be empty"):
        s._deserialize_import({"module": "pe", "alias": ""})

    with pytest.raises(SerializationError, match="Import alias must not be empty"):
        s._deserialize_import({"module": "pe", "alias": "\t"})

    with pytest.raises(SerializationError, match="Include path must be a string"):
        s._deserialize_include({"path": ["x.yar"]})

    with pytest.raises(SerializationError, match="Include path must not be empty"):
        s._deserialize_include({"path": ""})

    with pytest.raises(SerializationError, match="Include path must not be empty"):
        s._deserialize_include({"path": "   "})

    with pytest.raises(SerializationError, match="Rule name must be a string"):
        s._deserialize_rule(_serialized_json_rule(name=["r1"]))

    with pytest.raises(SerializationError, match="Rule name must not be empty"):
        s._deserialize_rule(_serialized_json_rule(name="", condition=true_expr))

    with pytest.raises(SerializationError, match="Rule name must not be empty"):
        s._deserialize_rule(_serialized_json_rule(name="   ", condition=true_expr))

    with pytest.raises(SerializationError, match="Tag name must be a string"):
        s._deserialize_tag({"name": 7})

    with pytest.raises(SerializationError, match="Tag name must not be empty"):
        s._deserialize_tag({"name": ""})

    with pytest.raises(SerializationError, match="Tag name must not be empty"):
        s._deserialize_tag({"name": "   "})

    with pytest.raises(SerializationError, match="Meta key must be a string"):
        s._deserialize_meta({"key": ["author"], "value": "me"})

    with pytest.raises(SerializationError, match="Meta key must not be empty"):
        s._deserialize_meta({"key": "", "value": "me"})

    with pytest.raises(SerializationError, match="Meta type must be Meta or MetaEntry"):
        s._deserialize_meta({"type": "Rule", "key": "author", "value": "me"})

    with pytest.raises(
        SerializationError, match="Meta value must be a string, integer, or boolean"
    ):
        s._deserialize_meta({"type": "Meta", "key": "score", "value": 1.5})

    with pytest.raises(
        SerializationError, match="Meta scope must be public, private, or protected"
    ):
        s._deserialize_meta(
            {"type": "MetaEntry", "key": "owner", "value": "team", "scope": "secret"}
        )


def test_json_deserialize_ast_and_rule_collections_reject_non_lists() -> None:
    s = JsonSerializer()

    with pytest.raises(SerializationError, match="YaraFile must be an object"):
        s._deserialize_ast(cast(Any, "rule r"))

    for field in (
        "imports",
        "includes",
        "rules",
        "extern_rules",
        "extern_imports",
        "pragmas",
        "namespaces",
    ):
        data = _serialized_json_yarafile()
        del data[field]
        with pytest.raises(SerializationError, match=f"YaraFile {field} is required"):
            s._deserialize_ast(data)

    with pytest.raises(SerializationError, match="YaraFile imports must be a list"):
        s._deserialize_ast(_serialized_json_yarafile(imports="pe"))

    with pytest.raises(SerializationError, match="Import must be an object"):
        s._deserialize_ast(_serialized_json_yarafile(imports=["pe"]))

    with pytest.raises(SerializationError, match="YaraFile extern_rules must be a list"):
        s._deserialize_ast(_serialized_json_yarafile(extern_rules="RemoteRule"))

    with pytest.raises(SerializationError, match="Rule must be an object"):
        s._deserialize_rule(cast(Any, "rule"))

    with pytest.raises(SerializationError, match="Meta must be an object"):
        s._deserialize_meta(cast(Any, "meta"))

    with pytest.raises(SerializationError, match="String must be an object"):
        s._deserialize_string(cast(Any, "string"))

    with pytest.raises(SerializationError, match="Pragma must be an object"):
        s._deserialize_pragma(cast(Any, "pragma"))

    for field in ("modifiers", "tags", "meta", "strings", "condition", "pragmas"):
        data = _serialized_json_rule()
        del data[field]
        with pytest.raises(SerializationError, match=f"Rule {field} is required"):
            s._deserialize_rule(data)

    with pytest.raises(SerializationError, match="Rule meta must be a list or dictionary"):
        s._deserialize_rule(_serialized_json_rule(meta="author"))

    with pytest.raises(SerializationError, match="Rule strings must be a list"):
        s._deserialize_rule(_serialized_json_rule(strings="$a"))

    with pytest.raises(SerializationError, match="Rule tags must be a list"):
        s._deserialize_rule(_serialized_json_rule(tags="tag"))

    with pytest.raises(SerializationError, match="Rule tags must contain Tag nodes"):
        s._deserialize_rule(
            _serialized_json_rule(tags=[{"type": "Import", "name": "not_tag", "module": "pe"}])
        )

    with pytest.raises(SerializationError, match="Rule pragmas must be a list"):
        s._deserialize_rule(_serialized_json_rule(pragmas="pragma"))

    with pytest.raises(SerializationError, match="Expression must be an object"):
        s._deserialize_rule(_serialized_json_rule(condition="true"))

    with pytest.raises(SerializationError, match="PragmaBlock pragmas is required"):
        s._deserialize_pragma_block({"type": "PragmaBlock"})

    with pytest.raises(SerializationError, match="PragmaBlock pragmas must be a list"):
        s._deserialize_pragma_block({"type": "PragmaBlock", "pragmas": "pragma"})

    with pytest.raises(SerializationError, match="PragmaBlock scope is required"):
        s._deserialize_pragma_block({"type": "PragmaBlock", "pragmas": [_serialized_json_pragma()]})


def test_json_deserialize_extern_nodes_reject_wrong_scalar_types() -> None:
    s = JsonSerializer()

    with pytest.raises(SerializationError, match="ExternImport module_path must be a string"):
        s._deserialize_extern_import({"module_path": ["external"]})

    for module_path in ("", "   ", "\t"):
        with pytest.raises(SerializationError, match="ExternImport module_path must not be empty"):
            s._deserialize_extern_import({"module_path": module_path})

    with pytest.raises(SerializationError, match="ExternImport alias must be a string"):
        s._deserialize_extern_import({"module_path": "external", "alias": True})

    with pytest.raises(SerializationError, match="ExternImport alias is required"):
        s._deserialize_extern_import({"module_path": "external"})

    for alias in ("", "   ", "\t"):
        with pytest.raises(SerializationError, match="ExternImport alias must not be empty"):
            s._deserialize_extern_import({"module_path": "external", "alias": alias})

    with pytest.raises(SerializationError, match="ExternImport rules must be a list of strings"):
        s._deserialize_extern_import({"module_path": "external", "alias": None, "rules": "RuleA"})

    with pytest.raises(SerializationError, match="ExternImport rules is required"):
        s._deserialize_extern_import({"module_path": "external", "alias": None})

    with pytest.raises(
        SerializationError, match="ExternImport rules must contain non-empty strings"
    ):
        for rule_name in ("", "   ", "\t"):
            s._deserialize_extern_import(
                {"module_path": "external", "alias": None, "rules": [rule_name]}
            )

    with pytest.raises(SerializationError, match="ExternRule name must be a string"):
        s._deserialize_extern_rule({"name": ["RuleA"]})

    with pytest.raises(SerializationError, match="ExternRule name must not be empty"):
        s._deserialize_extern_rule({"name": ""})

    with pytest.raises(SerializationError, match="ExternRule namespace must be a string"):
        s._deserialize_extern_rule({"name": "RuleA", "namespace": True})

    with pytest.raises(SerializationError, match="ExternRule namespace is required"):
        s._deserialize_extern_rule({"name": "RuleA"})

    with pytest.raises(SerializationError, match="ExternRule namespace must not be empty"):
        s._deserialize_extern_rule({"name": "RuleA", "namespace": ""})

    with pytest.raises(SerializationError, match="ExternNamespace name must be a string"):
        s._deserialize_extern_namespace({"name": ["ns"]})

    with pytest.raises(SerializationError, match="ExternNamespace name must not be empty"):
        s._deserialize_extern_namespace({"name": ""})

    with pytest.raises(SerializationError, match="ExternRuleReference rule_name must be a string"):
        s._deserialize_expression({"type": "ExternRuleReference", "rule_name": ["RuleA"]})

    with pytest.raises(SerializationError, match="ExternRuleReference rule_name must not be empty"):
        s._deserialize_expression({"type": "ExternRuleReference", "rule_name": ""})

    with pytest.raises(SerializationError, match="ExternRuleReference namespace must be a string"):
        s._deserialize_expression(
            {"type": "ExternRuleReference", "rule_name": "RuleA", "namespace": True}
        )

    with pytest.raises(SerializationError, match="ExternRuleReference namespace is required"):
        s._deserialize_expression({"type": "ExternRuleReference", "rule_name": "RuleA"})

    with pytest.raises(SerializationError, match="ExternRuleReference namespace must not be empty"):
        s._deserialize_expression(
            {"type": "ExternRuleReference", "rule_name": "RuleA", "namespace": ""}
        )


def test_json_deserialize_pragmas_reject_wrong_scalar_types() -> None:
    s = JsonSerializer()

    with pytest.raises(SerializationError, match="Pragma type is required"):
        s._deserialize_pragma({"pragma_type": "custom", "name": "vendor", "arguments": []})

    with pytest.raises(SerializationError, match="Pragma type must be Pragma"):
        s._deserialize_pragma(_serialized_json_pragma(type="Import"))

    with pytest.raises(SerializationError, match="Pragma pragma_type is required"):
        s._deserialize_pragma({"type": "Pragma", "name": "vendor", "arguments": []})

    with pytest.raises(SerializationError, match="Pragma pragma_type must be a valid pragma type"):
        s._deserialize_pragma(_serialized_json_pragma(pragma_type="vendor"))

    with pytest.raises(SerializationError, match="Pragma name is required"):
        s._deserialize_pragma(
            {
                "type": "Pragma",
                "pragma_type": "custom",
                "arguments": [],
                "scope": "file",
                "parameters": {},
            }
        )

    with pytest.raises(SerializationError, match="Pragma arguments is required"):
        s._deserialize_pragma(
            {
                "type": "Pragma",
                "pragma_type": "custom",
                "name": "vendor",
                "scope": "file",
                "parameters": {},
            }
        )

    with pytest.raises(SerializationError, match="Pragma scope is required"):
        s._deserialize_pragma(
            {
                "type": "Pragma",
                "pragma_type": "custom",
                "name": "vendor",
                "arguments": [],
                "parameters": {},
            }
        )

    with pytest.raises(SerializationError, match="Pragma parameters is required"):
        s._deserialize_pragma(
            {
                "type": "Pragma",
                "pragma_type": "custom",
                "name": "vendor",
                "arguments": [],
                "scope": "file",
            }
        )

    with pytest.raises(SerializationError, match="Pragma name must be a string"):
        s._deserialize_pragma(_serialized_json_pragma(name=["vendor"]))

    with pytest.raises(SerializationError, match="Pragma name must not be empty"):
        s._deserialize_pragma(_serialized_json_pragma(name=""))

    with pytest.raises(SerializationError, match="Pragma arguments must be a list of strings"):
        s._deserialize_pragma(_serialized_json_pragma(arguments="on"))

    with pytest.raises(SerializationError, match="Pragma parameters must be a dictionary"):
        s._deserialize_pragma(_serialized_json_pragma(parameters=["level", "strict"]))

    with pytest.raises(SerializationError, match="Pragma parameters value must be scalar"):
        s._deserialize_pragma(_serialized_json_pragma(parameters={"config": {"nested": "value"}}))

    with pytest.raises(SerializationError, match="Pragma macro_name must be a string"):
        s._deserialize_pragma(
            _serialized_json_pragma(pragma_type="define", name="define", macro_name=True)
        )

    with pytest.raises(SerializationError, match="Pragma macro_name is required"):
        s._deserialize_pragma(_serialized_json_pragma(pragma_type="define", name="define"))

    with pytest.raises(SerializationError, match="Pragma macro_name must not be empty"):
        s._deserialize_pragma(
            _serialized_json_pragma(pragma_type="define", name="define", macro_name="")
        )

    with pytest.raises(SerializationError, match="Pragma macro_name is required"):
        s._deserialize_pragma(_serialized_json_pragma(pragma_type="undef", name="undef"))

    with pytest.raises(SerializationError, match="Pragma macro_name must not be empty"):
        s._deserialize_pragma(
            _serialized_json_pragma(pragma_type="undef", name="undef", macro_name="")
        )

    with pytest.raises(SerializationError, match="Pragma macro_value is required"):
        s._deserialize_pragma(
            _serialized_json_pragma(pragma_type="define", name="define", macro_name="LIMIT")
        )

    with pytest.raises(SerializationError, match="Pragma macro_value must be a string"):
        s._deserialize_pragma(
            _serialized_json_pragma(
                pragma_type="define",
                name="define",
                macro_name="LIMIT",
                macro_value=["10"],
            )
        )

    with pytest.raises(SerializationError, match="Pragma condition must be a string"):
        s._deserialize_pragma(
            _serialized_json_pragma(pragma_type="ifdef", name="ifdef", condition=True)
        )

    with pytest.raises(SerializationError, match="Pragma condition must not be empty"):
        s._deserialize_pragma(
            _serialized_json_pragma(pragma_type="ifdef", name="ifdef", condition="")
        )

    with pytest.raises(SerializationError, match="Pragma condition must not be empty"):
        s._deserialize_pragma(
            _serialized_json_pragma(pragma_type="ifndef", name="ifndef", condition="")
        )

    with pytest.raises(SerializationError, match="Pragma condition is required"):
        s._deserialize_pragma(_serialized_json_pragma(pragma_type="ifdef", name="ifdef"))

    with pytest.raises(SerializationError, match="InRulePragma pragma is required"):
        s._deserialize_in_rule_pragma({"position": "before_condition"})

    with pytest.raises(SerializationError, match="InRulePragma position must be a string"):
        s._deserialize_in_rule_pragma(
            {
                "pragma": _serialized_json_pragma(),
                "position": True,
            }
        )

    with pytest.raises(SerializationError, match="InRulePragma position must not be empty"):
        s._deserialize_in_rule_pragma(
            {
                "pragma": _serialized_json_pragma(),
                "position": "",
            }
        )


def test_json_deserialize_node_metadata_rejects_wrong_scalar_types() -> None:
    s = JsonSerializer()

    with pytest.raises(SerializationError, match="Location line is required"):
        s._deserialize_import({"module": "pe", "alias": None, "location": {"column": 1}})

    with pytest.raises(SerializationError, match="Location column is required"):
        s._deserialize_import({"module": "pe", "alias": None, "location": {"line": 1}})

    with pytest.raises(SerializationError, match="Location line must be an integer"):
        s._deserialize_import(
            {"module": "pe", "alias": None, "location": {"line": True, "column": 1}}
        )

    with pytest.raises(SerializationError, match="Location file must be a string"):
        s._deserialize_import(
            {"module": "pe", "alias": None, "location": {"line": 1, "column": 1, "file": []}}
        )

    with pytest.raises(SerializationError, match="location must be an object"):
        s._deserialize_import({"module": "pe", "alias": None, "location": "1:1"})

    with pytest.raises(SerializationError, match="leading_comments must be a list"):
        s._deserialize_import({"module": "pe", "alias": None, "leading_comments": {}})

    with pytest.raises(SerializationError, match="leading_comments must be a list"):
        s._deserialize_import(
            {"module": "pe", "alias": None, "leading_comments": {"type": "Comment"}}
        )

    with pytest.raises(SerializationError, match="trailing_comment must be an object"):
        s._deserialize_import({"module": "pe", "alias": None, "trailing_comment": "bad"})

    with pytest.raises(SerializationError, match="CommentGroup comments is required"):
        s._deserialize_import(
            {
                "module": "pe",
                "alias": None,
                "trailing_comment": {"type": "CommentGroup"},
            }
        )

    with pytest.raises(SerializationError, match="CommentGroup comments must be a list"):
        s._deserialize_import(
            {
                "module": "pe",
                "alias": None,
                "trailing_comment": {"type": "CommentGroup", "comments": "bad"},
            }
        )

    with pytest.raises(SerializationError, match="Unknown comment metadata type"):
        s._deserialize_import(
            {
                "module": "pe",
                "alias": None,
                "leading_comments": [{"type": "UnknownComment", "text": "bad"}],
            }
        )

    with pytest.raises(SerializationError, match="Comment text must be a string"):
        s._deserialize_import(
            {
                "module": "pe",
                "alias": None,
                "leading_comments": [{"type": "Comment", "text": ["bad"]}],
            }
        )

    with pytest.raises(SerializationError, match="Comment is_multiline must be a boolean"):
        s._deserialize_import(
            {
                "module": "pe",
                "alias": None,
                "leading_comments": [{"type": "Comment", "text": "bad", "is_multiline": "yes"}],
            }
        )

    with pytest.raises(
        SerializationError, match="CommentGroup comments must contain Comment nodes"
    ):
        s._deserialize_import(
            {
                "module": "pe",
                "alias": None,
                "trailing_comment": {
                    "type": "CommentGroup",
                    "comments": [
                        {"type": "CommentGroup", "comments": [{"type": "Comment", "text": "bad"}]}
                    ],
                },
            }
        )


def test_json_deserialize_node_metadata_preserves_leading_comment_groups() -> None:
    s = JsonSerializer()
    node = s._deserialize_import(
        {
            "module": "pe",
            "alias": None,
            "leading_comments": [
                {"type": "CommentGroup", "comments": [{"type": "Comment", "text": "lead"}]}
            ],
        }
    )

    assert isinstance(node.leading_comments[0], CommentGroup)
    assert node.leading_comments[0].comments[0].text == "lead"


def test_deserialize_strings_modifiers_and_hex_tokens() -> None:
    s = JsonSerializer()

    mod = s._deserialize_modifier({"name": "ascii", "value": None})
    assert isinstance(mod, StringModifier)
    unknown_mod = s._deserialize_modifier({"name": "vendor_modifier", "value": 'a"\\b\n'})
    assert unknown_mod == 'vendor_modifier("a\\"\\\\b\\n")'

    plain = s._deserialize_string(
        {
            "type": "PlainString",
            "identifier": "$a",
            "value": "abc",
            "modifiers": [{"name": "ascii", "value": None}],
        }
    )
    assert isinstance(plain, PlainString)

    hexs = s._deserialize_string(
        {
            "type": "HexString",
            "identifier": "$h",
            "tokens": [
                {"type": "HexByte", "value": 65},
                {"type": "HexWildcard"},
                {"type": "HexJump", "min_jump": 1, "max_jump": 3},
                {"type": "HexByte", "value": 66},
            ],
            "modifiers": [],
        }
    )
    assert isinstance(hexs, HexString)
    assert isinstance(hexs.tokens[0], HexByte)
    assert isinstance(hexs.tokens[1], HexWildcard)
    assert isinstance(hexs.tokens[2], HexJump)

    regex = s._deserialize_string(
        {
            "type": "RegexString",
            "identifier": "$r",
            "regex": "ab.*",
            "modifiers": [],
        }
    )
    assert isinstance(regex, RegexString)

    base = StringDefinition(
        identifier="$base",
        modifiers=[StringModifier.from_name_value("wide")],
        is_anonymous=True,
    )
    restored_base = s._deserialize_string(s.visit_string_definition(base))
    assert isinstance(restored_base, StringDefinition)
    assert not isinstance(restored_base, PlainString | HexString | RegexString)
    assert restored_base.identifier == "$base"
    assert restored_base.modifiers == [StringModifier.from_name_value("wide")]
    assert restored_base.is_anonymous is True


def test_json_deserialize_modifier_and_token_collections_reject_non_lists() -> None:
    s = JsonSerializer()

    with pytest.raises(SerializationError, match="Rule modifiers must be a list"):
        s._deserialize_rule(_serialized_json_rule(modifiers="private"))

    with pytest.raises(SerializationError, match="Rule modifiers must be a list of strings"):
        s._deserialize_rule(_serialized_json_rule(modifiers=[7]))

    with pytest.raises(SerializationError, match="Rule modifiers must contain non-empty strings"):
        s._deserialize_rule(_serialized_json_rule(modifiers=[""]))

    with pytest.raises(SerializationError, match="ExternRule modifiers must be a list"):
        s._deserialize_extern_rule(
            {"name": "RemoteRule", "modifiers": "private", "namespace": None}
        )

    with pytest.raises(SerializationError, match="ExternRule modifiers must be a list of strings"):
        s._deserialize_extern_rule({"name": "RemoteRule", "modifiers": [7], "namespace": None})

    with pytest.raises(
        SerializationError, match="ExternRule modifiers must contain non-empty strings"
    ):
        s._deserialize_extern_rule({"name": "RemoteRule", "modifiers": [""], "namespace": None})

    with pytest.raises(SerializationError, match="ExternNamespace extern_rules must be a list"):
        s._deserialize_extern_namespace({"name": "remote", "extern_rules": "RemoteRule"})

    with pytest.raises(SerializationError, match="ExternNamespace extern_rules is required"):
        s._deserialize_extern_namespace({"name": "remote"})

    with pytest.raises(SerializationError, match="PlainString modifiers must be a list"):
        s._deserialize_string(
            {"type": "PlainString", "identifier": "$a", "value": "abc", "modifiers": "ascii"}
        )

    for string_data in (
        {"type": "PlainString", "identifier": "$a", "value": "abc"},
        {"type": "HexString", "identifier": "$h", "tokens": [{"type": "HexByte", "value": 65}]},
        {"type": "RegexString", "identifier": "$r", "regex": "abc"},
        {"type": "StringDefinition", "identifier": "$s"},
    ):
        with pytest.raises(SerializationError, match="modifiers is required"):
            s._deserialize_string(string_data)

    with pytest.raises(SerializationError, match="StringModifier name must be a string"):
        s._deserialize_string(
            {
                "type": "PlainString",
                "identifier": "$a",
                "value": "abc",
                "modifiers": [{"name": 7}],
            }
        )

    with pytest.raises(SerializationError, match="StringModifier name must not be empty"):
        s._deserialize_string(
            {
                "type": "PlainString",
                "identifier": "$a",
                "value": "abc",
                "modifiers": [{"name": ""}],
            }
        )

    with pytest.raises(SerializationError, match="StringModifier value is required"):
        s._deserialize_string(
            {
                "type": "PlainString",
                "identifier": "$a",
                "value": "abc",
                "modifiers": [{"name": "xor"}],
            }
        )

    with pytest.raises(SerializationError, match="StringModifier must be a string or object"):
        s._deserialize_string(
            {"type": "PlainString", "identifier": "$a", "value": "abc", "modifiers": [7]}
        )

    with pytest.raises(SerializationError, match="HexString tokens must be a list"):
        s._deserialize_string(
            {"type": "HexString", "identifier": "$h", "tokens": "AA", "modifiers": []}
        )

    with pytest.raises(SerializationError, match="HexString must contain at least one token"):
        s._deserialize_string(
            {"type": "HexString", "identifier": "$h", "tokens": [], "modifiers": []}
        )

    with pytest.raises(
        SerializationError,
        match="HexJump cannot appear at the beginning or end of hex string",
    ):
        s._deserialize_string(
            {
                "type": "HexString",
                "identifier": "$h",
                "tokens": [
                    {"type": "HexJump", "min_jump": 1, "max_jump": 2},
                    {"type": "HexByte", "value": 65},
                ],
                "modifiers": [],
            }
        )

    with pytest.raises(
        SerializationError,
        match="HexJump cannot appear at the beginning or end of hex string",
    ):
        s._deserialize_string(
            {
                "type": "HexString",
                "identifier": "$h",
                "tokens": [
                    {"type": "HexByte", "value": 65},
                    {"type": "HexJump", "min_jump": 1, "max_jump": 2},
                ],
                "modifiers": [],
            }
        )

    with pytest.raises(SerializationError, match="Hex token must be an object"):
        s._deserialize_string(
            {"type": "HexString", "identifier": "$h", "tokens": ["AA"], "modifiers": []}
        )

    with pytest.raises(SerializationError, match="HexAlternative alternatives must be a list"):
        s._deserialize_hex_token({"type": "HexAlternative", "alternatives": "AA"})

    with pytest.raises(SerializationError, match="HexAlternative must contain at least one branch"):
        s._deserialize_hex_token({"type": "HexAlternative", "alternatives": []})

    with pytest.raises(SerializationError, match="HexAlternative branches must not be empty"):
        s._deserialize_hex_token({"type": "HexAlternative", "alternatives": [[]]})

    with pytest.raises(
        SerializationError,
        match="Unbounded HexJump is not allowed inside hex alternatives",
    ):
        s._deserialize_hex_token(
            {
                "type": "HexAlternative",
                "alternatives": [
                    [
                        {"type": "HexByte", "value": 65},
                        {"type": "HexJump", "min_jump": 1},
                        {"type": "HexByte", "value": 66},
                    ]
                ],
            }
        )


def test_json_deserialize_string_rejects_non_bool_anonymous_flag() -> None:
    s = JsonSerializer()

    with pytest.raises(SerializationError, match="is_anonymous must be a boolean"):
        s._deserialize_string(
            {
                "type": "PlainString",
                "identifier": "$a",
                "value": "abc",
                "modifiers": [],
                "is_anonymous": "false",
            }
        )


def test_json_deserialize_strings_reject_wrong_scalar_types() -> None:
    s = JsonSerializer()

    with pytest.raises(SerializationError, match="PlainString identifier must be a string"):
        s._deserialize_string(
            {"type": "PlainString", "identifier": ["$a"], "value": "abc", "modifiers": []}
        )

    with pytest.raises(SerializationError, match="PlainString identifier must not be empty"):
        s._deserialize_string(
            {"type": "PlainString", "identifier": "", "value": "abc", "modifiers": []}
        )

    with pytest.raises(SerializationError, match="PlainString value must be a string or bytes"):
        s._deserialize_string(
            {"type": "PlainString", "identifier": "$a", "value": True, "modifiers": []}
        )

    with pytest.raises(SerializationError, match="PlainString value must be a string or bytes"):
        s._deserialize_string(
            {
                "type": "PlainString",
                "identifier": "$a",
                "value": 1234,
                "value_encoding": "base64",
                "modifiers": [],
            }
        )

    with pytest.raises(SerializationError, match="HexString identifier must be a string"):
        s._deserialize_string(
            {"type": "HexString", "identifier": ["$h"], "tokens": [], "modifiers": []}
        )

    with pytest.raises(SerializationError, match="HexString identifier must not be empty"):
        s._deserialize_string(
            {"type": "HexString", "identifier": "", "tokens": [], "modifiers": []}
        )

    with pytest.raises(SerializationError, match="RegexString identifier must not be empty"):
        s._deserialize_string(
            {"type": "RegexString", "identifier": "", "regex": "abc", "modifiers": []}
        )

    with pytest.raises(SerializationError, match="RegexString regex must be a string"):
        s._deserialize_string(
            {"type": "RegexString", "identifier": "$r", "regex": 123, "modifiers": []}
        )

    with pytest.raises(SerializationError, match="RegexString regex must not be empty"):
        s._deserialize_string(
            {"type": "RegexString", "identifier": "$r", "regex": "", "modifiers": []}
        )

    with pytest.raises(SerializationError, match="StringDefinition identifier must not be empty"):
        s._deserialize_string({"type": "StringDefinition", "identifier": "", "modifiers": []})


def test_json_deserialize_hex_tokens_reject_invalid_scalar_fields() -> None:
    s = JsonSerializer()

    for token in (
        {"type": "HexByte", "value": True},
        {"type": "HexByte", "value": "GG"},
        {"type": "HexNegatedByte", "value": True},
        {"type": "HexJump", "min_jump": True, "max_jump": 3},
        {"type": "HexJump", "min_jump": 5, "max_jump": 3},
        {"type": "HexNibble", "value": 10},
        {"type": "HexNibble", "high": "true", "value": 10},
        {"type": "HexNibble", "high": True, "value": True},
        {"type": "HexNibble", "high": True, "value": 16},
    ):
        with pytest.raises(SerializationError):
            s._deserialize_string(
                {"type": "HexString", "identifier": "$h", "tokens": [token], "modifiers": []}
            )


def test_json_deserialize_literal_nodes_reject_wrong_scalar_types() -> None:
    s = JsonSerializer()
    true_expr = {"type": "BooleanLiteral", "value": True}

    with pytest.raises(SerializationError, match="IntegerLiteral value must be an integer"):
        s._deserialize_expression({"type": "IntegerLiteral", "value": True})

    with pytest.raises(SerializationError, match="IntegerLiteral value is required"):
        s._deserialize_expression({"type": "IntegerLiteral"})

    with pytest.raises(SerializationError, match="BooleanLiteral value must be a boolean"):
        s._deserialize_expression({"type": "BooleanLiteral", "value": "false"})

    with pytest.raises(SerializationError, match="DoubleLiteral value must be numeric"):
        s._deserialize_expression({"type": "DoubleLiteral", "value": True})

    with pytest.raises(SerializationError, match="DoubleLiteral value must be numeric"):
        s._deserialize_expression({"type": "DoubleLiteral", "value": "1.5"})

    for invalid_number in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(SerializationError, match="DoubleLiteral value must be finite"):
            s._deserialize_expression({"type": "DoubleLiteral", "value": invalid_number})

    with pytest.raises(SerializationError, match="StringLiteral value must be a string"):
        s._deserialize_expression({"type": "StringLiteral", "value": True})

    with pytest.raises(SerializationError, match="Identifier name must be a string"):
        s._deserialize_expression({"type": "Identifier", "name": ["id"]})

    with pytest.raises(SerializationError, match="Identifier name must not be empty"):
        s._deserialize_expression({"type": "Identifier", "name": ""})

    empty_string_reference_cases = (
        ({"type": "StringIdentifier", "name": ""}, "StringIdentifier name must not be empty"),
        ({"type": "StringWildcard", "pattern": ""}, "StringWildcard pattern must not be empty"),
        ({"type": "StringCount", "string_id": ""}, "StringCount string_id must not be empty"),
        ({"type": "StringOffset", "string_id": ""}, "StringOffset string_id must not be empty"),
        ({"type": "StringLength", "string_id": ""}, "StringLength string_id must not be empty"),
    )
    for payload, message in empty_string_reference_cases:
        with pytest.raises(SerializationError, match=message):
            s._deserialize_expression(payload)

    with pytest.raises(SerializationError, match="BinaryExpression left is required"):
        s._deserialize_expression(
            {"type": "BinaryExpression", "operator": "and", "right": true_expr}
        )

    with pytest.raises(SerializationError, match="BinaryExpression right is required"):
        s._deserialize_expression(
            {"type": "BinaryExpression", "left": true_expr, "operator": "and"}
        )

    missing_expression_cases: tuple[tuple[dict[str, Any], str], ...] = (
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
            s._deserialize_expression(payload)

    null_expression_cases = (
        (
            {"type": "BinaryExpression", "left": None, "operator": "and", "right": true_expr},
            "BinaryExpression left is required",
        ),
        (
            {"type": "UnaryExpression", "operator": "not", "operand": None},
            "UnaryExpression operand is required",
        ),
        (
            {
                "type": "RangeExpression",
                "low": None,
                "high": {"type": "IntegerLiteral", "value": 1},
            },
            "RangeExpression low is required",
        ),
        (
            {"type": "ArrayAccess", "array": None, "index": {"type": "IntegerLiteral", "value": 0}},
            "ArrayAccess array is required",
        ),
        (
            {"type": "MemberAccess", "object": None, "member": "name"},
            "MemberAccess object is required",
        ),
    )
    for null_payload, message in null_expression_cases:
        with pytest.raises(SerializationError, match=message):
            s._deserialize_expression(null_payload)

    with pytest.raises(SerializationError, match="BinaryExpression operator must be a string"):
        s._deserialize_expression(
            {
                "type": "BinaryExpression",
                "left": true_expr,
                "operator": ["and"],
                "right": true_expr,
            }
        )

    with pytest.raises(SerializationError, match="BinaryExpression operator must not be empty"):
        s._deserialize_expression(
            {
                "type": "BinaryExpression",
                "left": true_expr,
                "operator": "",
                "right": true_expr,
            }
        )

    with pytest.raises(SerializationError, match="UnaryExpression operator must be a string"):
        s._deserialize_expression(
            {"type": "UnaryExpression", "operator": ["not"], "operand": true_expr}
        )

    with pytest.raises(SerializationError, match="UnaryExpression operator must not be empty"):
        s._deserialize_expression({"type": "UnaryExpression", "operator": "", "operand": true_expr})

    with pytest.raises(SerializationError, match="FunctionCall function must be a string"):
        s._deserialize_expression({"type": "FunctionCall", "function": ["fn"], "arguments": []})

    with pytest.raises(SerializationError, match="FunctionCall function must not be empty"):
        s._deserialize_expression({"type": "FunctionCall", "function": "", "arguments": []})

    with pytest.raises(SerializationError, match="SetExpression elements must be a list"):
        s._deserialize_expression({"type": "SetExpression", "elements": "x"})

    with pytest.raises(SerializationError, match="SetExpression elements is required"):
        s._deserialize_expression({"type": "SetExpression"})

    with pytest.raises(SerializationError, match="SetExpression elements must contain expressions"):
        s._deserialize_expression({"type": "SetExpression", "elements": [None]})

    with pytest.raises(SerializationError, match="FunctionCall arguments must contain expressions"):
        s._deserialize_expression({"type": "FunctionCall", "function": "fn", "arguments": [None]})

    with pytest.raises(SerializationError, match="MemberAccess member must be a string"):
        s._deserialize_expression(
            {"type": "MemberAccess", "object": {"type": "Identifier", "name": "pe"}, "member": []}
        )

    with pytest.raises(SerializationError, match="MemberAccess member must not be empty"):
        s._deserialize_expression(
            {"type": "MemberAccess", "object": {"type": "Identifier", "name": "pe"}, "member": ""}
        )

    with pytest.raises(SerializationError, match="AtExpression string_id must be a string"):
        s._deserialize_expression(
            {
                "type": "AtExpression",
                "string_id": ["$a"],
                "offset": {"type": "IntegerLiteral", "value": 0},
            }
        )

    with pytest.raises(SerializationError, match="AtExpression string_id must not be empty"):
        s._deserialize_expression(
            {
                "type": "AtExpression",
                "string_id": "",
                "offset": {"type": "IntegerLiteral", "value": 0},
            }
        )

    int_expr = {"type": "IntegerLiteral", "value": 1}
    missing_condition_cases: tuple[tuple[dict[str, Any], str], ...] = (
        (
            {"type": "ForExpression", "variable": "i", "iterable": int_expr, "body": int_expr},
            "ForExpression quantifier is required",
        ),
        (
            {"type": "ForExpression", "quantifier": "any", "iterable": int_expr, "body": int_expr},
            "ForExpression variable is required",
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
            s._deserialize_expression(payload)

    null_condition_cases: tuple[tuple[dict[str, Any], str], ...] = (
        (
            {
                "type": "ForExpression",
                "quantifier": None,
                "variable": "i",
                "iterable": int_expr,
                "body": int_expr,
            },
            "ForExpression quantifier is required",
        ),
        (
            {
                "type": "ForExpression",
                "quantifier": {},
                "variable": "i",
                "iterable": int_expr,
                "body": int_expr,
            },
            "ForExpression quantifier is required",
        ),
        (
            {
                "type": "ForExpression",
                "quantifier": "any",
                "variable": "i",
                "iterable": None,
                "body": int_expr,
            },
            "ForExpression iterable is required",
        ),
        (
            {"type": "AtExpression", "string_id": "$a", "offset": None},
            "AtExpression offset is required",
        ),
        (
            {"type": "InExpression", "subject": "$a", "range": None},
            "InExpression range is required",
        ),
        (
            {"type": "InExpression", "subject": {}, "range": int_expr},
            "InExpression subject is required",
        ),
        (
            {"type": "ForOfExpression", "quantifier": "any", "string_set": None},
            "ForOfExpression string_set is required",
        ),
        (
            {"type": "OfExpression", "quantifier": "any", "string_set": {}},
            "OfExpression string_set is required",
        ),
        (
            {"type": "DictionaryAccess", "object": None, "key": "name"},
            "DictionaryAccess object is required",
        ),
    )
    for null_payload, message in null_condition_cases:
        with pytest.raises(SerializationError, match=message):
            s._deserialize_expression(null_payload)

    for invalid_quantifier in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(SerializationError, match="ForExpression quantifier must be finite"):
            s._deserialize_expression(
                {
                    "type": "ForExpression",
                    "quantifier": invalid_quantifier,
                    "variable": "i",
                    "iterable": int_expr,
                    "body": int_expr,
                }
            )

    with pytest.raises(SerializationError, match="ModuleReference module must be a string"):
        s._deserialize_expression({"type": "ModuleReference", "module": ["pe"]})

    with pytest.raises(SerializationError, match="ModuleReference module must not be empty"):
        s._deserialize_expression({"type": "ModuleReference", "module": ""})

    with pytest.raises(SerializationError, match="ModuleReference module is required"):
        s._deserialize_expression({"type": "ModuleReference"})

    with pytest.raises(SerializationError, match="DictionaryAccess key must be a string"):
        s._deserialize_expression(
            {"type": "DictionaryAccess", "object": {"type": "ModuleReference", "module": "pe"}}
        )

    with pytest.raises(SerializationError, match="DictionaryAccess key must be a string"):
        s._deserialize_expression(
            {
                "type": "DictionaryAccess",
                "object": {"type": "ModuleReference", "module": "pe"},
                "key": ["CompanyName"],
            }
        )

    with pytest.raises(SerializationError, match="DictionaryAccess key must be a string"):
        s._deserialize_expression(
            {
                "type": "DictionaryAccess",
                "object": {"type": "ModuleReference", "module": "pe"},
                "key": {},
            }
        )

    with pytest.raises(SerializationError, match="RegexLiteral pattern must be a string"):
        s._deserialize_expression({"type": "RegexLiteral", "pattern": 123})

    with pytest.raises(SerializationError, match="RegexLiteral pattern must not be empty"):
        s._deserialize_expression({"type": "RegexLiteral", "pattern": ""})

    with pytest.raises(SerializationError, match="RegexLiteral modifiers is required"):
        s._deserialize_expression({"type": "RegexLiteral", "pattern": "abc"})

    with pytest.raises(SerializationError, match="RegexLiteral modifiers must be a string"):
        s._deserialize_expression({"type": "RegexLiteral", "pattern": "abc", "modifiers": ["i"]})

    with pytest.raises(SerializationError, match="Expression must be an object"):
        s._deserialize_expression({"type": "StringOffset", "string_id": "a", "index": False})

    with pytest.raises(SerializationError, match="Expression must be an object"):
        s._deserialize_expression({"type": "StringLength", "string_id": "a", "index": False})


def test_json_deserialize_string_set_lists_reject_empty_items() -> None:
    s = JsonSerializer()

    empty_string_set_item_cases: tuple[tuple[dict[str, Any], str], ...] = (
        (
            {"type": "ForOfExpression", "quantifier": "any", "string_set": [None]},
            "ForOfExpression string_set must contain values",
        ),
        (
            {"type": "ForOfExpression", "quantifier": "any", "string_set": [{}]},
            "ForOfExpression string_set must contain values",
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
    for payload, message in empty_string_set_item_cases:
        with pytest.raises(SerializationError, match=message):
            s._deserialize_expression(payload)


def test_json_deserialize_string_sets_reject_invalid_raw_values() -> None:
    s = JsonSerializer()

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
            s._deserialize_expression(payload)


def test_json_deserialize_quantifiers_reject_invalid_raw_values() -> None:
    s = JsonSerializer()
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
            s._deserialize_expression(payload)


def test_json_deserialize_extended_expression_fields_reject_wrong_scalar_types() -> None:
    s = JsonSerializer()
    true_expr = {"type": "BooleanLiteral", "value": True}

    with pytest.raises(SerializationError, match="FunctionCall arguments must be a list"):
        s._deserialize_expression({"type": "FunctionCall", "function": "fn", "arguments": "abc"})

    with pytest.raises(SerializationError, match="FunctionCall arguments is required"):
        s._deserialize_expression({"type": "FunctionCall", "function": "fn"})

    with pytest.raises(
        SerializationError, match="StringOperatorExpression operator must not be empty"
    ):
        s._deserialize_expression(
            {
                "type": "StringOperatorExpression",
                "left": true_expr,
                "operator": "",
                "right": true_expr,
            }
        )

    with pytest.raises(SerializationError, match="WithDeclaration identifier must be a string"):
        s._deserialize_expression(
            {"type": "WithDeclaration", "identifier": ["x"], "value": true_expr}
        )

    with pytest.raises(SerializationError, match="WithDeclaration identifier must not be empty"):
        s._deserialize_expression({"type": "WithDeclaration", "identifier": "", "value": true_expr})

    with pytest.raises(SerializationError, match="WithStatement declarations must be a list"):
        s._deserialize_expression({"type": "WithStatement", "declarations": "x", "body": true_expr})

    with pytest.raises(SerializationError, match="WithStatement declarations is required"):
        s._deserialize_expression({"type": "WithStatement", "body": true_expr})

    with pytest.raises(SerializationError, match="ArrayComprehension variable must be a string"):
        s._deserialize_expression({"type": "ArrayComprehension", "variable": ["x"]})

    with pytest.raises(SerializationError, match="ArrayComprehension variable is required"):
        s._deserialize_expression({"type": "ArrayComprehension"})

    with pytest.raises(SerializationError, match="ArrayComprehension variable must not be empty"):
        s._deserialize_expression({"type": "ArrayComprehension", "variable": ""})

    with pytest.raises(SerializationError, match="Expression must be an object"):
        s._deserialize_expression({"type": "ArrayComprehension", "expression": False})

    with pytest.raises(
        SerializationError, match="DictComprehension value_variable must be a string"
    ):
        s._deserialize_expression(
            {"type": "DictComprehension", "key_variable": "k", "value_variable": True}
        )

    with pytest.raises(
        SerializationError, match="DictComprehension key_variable must not be empty"
    ):
        s._deserialize_expression({"type": "DictComprehension", "key_variable": ""})

    with pytest.raises(SerializationError, match="DictComprehension key_variable is required"):
        s._deserialize_expression({"type": "DictComprehension"})

    with pytest.raises(
        SerializationError, match="DictComprehension value_variable must not be empty"
    ):
        s._deserialize_expression(
            {"type": "DictComprehension", "key_variable": "k", "value_variable": ""}
        )

    with pytest.raises(SerializationError, match="TupleExpression elements must be a list"):
        s._deserialize_expression({"type": "TupleExpression", "elements": "abc"})

    with pytest.raises(SerializationError, match="TupleExpression elements is required"):
        s._deserialize_expression({"type": "TupleExpression"})

    with pytest.raises(SerializationError, match="ListExpression elements is required"):
        s._deserialize_expression({"type": "ListExpression"})

    with pytest.raises(SerializationError, match="DictExpression items is required"):
        s._deserialize_expression({"type": "DictExpression"})

    null_list_item_cases = (
        (
            {"type": "WithStatement", "declarations": [None], "body": true_expr},
            "WithStatement declarations must contain expressions",
        ),
        (
            {"type": "TupleExpression", "elements": [None]},
            "TupleExpression elements must contain expressions",
        ),
        (
            {"type": "ListExpression", "elements": [None]},
            "ListExpression elements must contain expressions",
        ),
        (
            {"type": "DictExpression", "items": [None]},
            "DictExpression items must contain expressions",
        ),
        (
            {"type": "PatternMatch", "value": true_expr, "cases": [None]},
            "PatternMatch cases must contain expressions",
        ),
    )
    for null_payload, message in null_list_item_cases:
        with pytest.raises(SerializationError, match=message):
            s._deserialize_expression(null_payload)

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
        ({"type": "StringOffset", "string_id": "$a"}, "StringOffset index is required"),
        ({"type": "StringLength", "string_id": "$a"}, "StringLength index is required"),
        (
            {"type": "ForOfExpression", "quantifier": "any", "string_set": "them"},
            "ForOfExpression condition is required",
        ),
        (
            {"type": "ArrayComprehension", "variable": "x"},
            "ArrayComprehension expression is required",
        ),
        (
            {"type": "ArrayComprehension", "expression": true_expr, "variable": "x"},
            "ArrayComprehension iterable is required",
        ),
        (
            {
                "type": "ArrayComprehension",
                "expression": true_expr,
                "variable": "x",
                "iterable": true_expr,
            },
            "ArrayComprehension condition is required",
        ),
        (
            {
                "type": "DictComprehension",
                "key_variable": "k",
                "value_variable": None,
            },
            "DictComprehension key_expression is required",
        ),
        (
            {
                "type": "DictComprehension",
                "key_expression": true_expr,
                "key_variable": "k",
                "value_variable": None,
            },
            "DictComprehension value_expression is required",
        ),
        (
            {
                "type": "DictComprehension",
                "key_expression": true_expr,
                "value_expression": true_expr,
                "key_variable": "k",
            },
            "DictComprehension value_variable is required",
        ),
        (
            {
                "type": "DictComprehension",
                "key_expression": true_expr,
                "value_expression": true_expr,
                "key_variable": "k",
                "value_variable": None,
            },
            "DictComprehension iterable is required",
        ),
        (
            {
                "type": "DictComprehension",
                "key_expression": true_expr,
                "value_expression": true_expr,
                "key_variable": "k",
                "value_variable": None,
                "iterable": true_expr,
            },
            "DictComprehension condition is required",
        ),
        ({"type": "SliceExpression"}, "SliceExpression target is required"),
        ({"type": "SliceExpression", "target": true_expr}, "SliceExpression start is required"),
        (
            {"type": "SliceExpression", "target": true_expr, "start": None},
            "SliceExpression stop is required",
        ),
        (
            {"type": "SliceExpression", "target": true_expr, "start": None, "stop": None},
            "SliceExpression step is required",
        ),
        ({"type": "LambdaExpression", "parameters": ["x"]}, "LambdaExpression body is required"),
        ({"type": "PatternMatch", "cases": []}, "PatternMatch value is required"),
        (
            {"type": "PatternMatch", "value": true_expr, "cases": []},
            "PatternMatch default is required",
        ),
        ({"type": "MatchCase", "result": true_expr}, "MatchCase pattern is required"),
        ({"type": "MatchCase", "pattern": true_expr}, "MatchCase result is required"),
        ({"type": "SpreadOperator"}, "SpreadOperator expression is required"),
    )
    for payload, message in missing_extended_cases:
        with pytest.raises(SerializationError, match=message):
            s._deserialize_expression(payload)

    null_extended_cases: tuple[tuple[dict[str, Any], str], ...] = (
        (
            {"type": "WithStatement", "declarations": [], "body": None},
            "WithStatement body is required",
        ),
        (
            {"type": "TupleIndexing", "tuple_expr": None, "index": true_expr},
            "TupleIndexing tuple_expr is required",
        ),
        (
            {"type": "DictItem", "key": None, "value": true_expr},
            "DictItem key is required",
        ),
        (
            {"type": "SliceExpression", "target": None},
            "SliceExpression target is required",
        ),
        (
            {"type": "SpreadOperator", "expression": None},
            "SpreadOperator expression is required",
        ),
    )
    for null_payload, message in null_extended_cases:
        with pytest.raises(SerializationError, match=message):
            s._deserialize_expression(null_payload)

    with pytest.raises(
        SerializationError, match="LambdaExpression parameters must be a list of strings"
    ):
        s._deserialize_expression(
            {"type": "LambdaExpression", "parameters": "xy", "body": true_expr}
        )

    with pytest.raises(SerializationError, match="LambdaExpression parameters is required"):
        s._deserialize_expression({"type": "LambdaExpression", "body": true_expr})

    with pytest.raises(
        SerializationError, match="LambdaExpression parameters must contain non-empty strings"
    ):
        s._deserialize_expression(
            {"type": "LambdaExpression", "parameters": [""], "body": true_expr}
        )

    with pytest.raises(SerializationError, match="PatternMatch cases must be a list"):
        s._deserialize_expression({"type": "PatternMatch", "value": true_expr, "cases": "case"})

    with pytest.raises(SerializationError, match="PatternMatch cases is required"):
        s._deserialize_expression({"type": "PatternMatch", "value": true_expr})

    with pytest.raises(SerializationError, match="SpreadOperator is_dict must be a boolean"):
        s._deserialize_expression(
            {"type": "SpreadOperator", "expression": true_expr, "is_dict": "yes"}
        )

    with pytest.raises(SerializationError, match="SpreadOperator is_dict is required"):
        s._deserialize_expression({"type": "SpreadOperator", "expression": true_expr})


def test_json_deserialize_condition_fields_reject_wrong_scalar_types() -> None:
    s = JsonSerializer()
    true_expr = {"type": "BooleanLiteral", "value": True}

    with pytest.raises(SerializationError, match="ForExpression variable must be a string"):
        s._deserialize_expression(
            {
                "type": "ForExpression",
                "quantifier": "any",
                "variable": ["i"],
                "iterable": true_expr,
                "body": true_expr,
            }
        )

    with pytest.raises(SerializationError, match="ForExpression variable must not be empty"):
        s._deserialize_expression(
            {
                "type": "ForExpression",
                "quantifier": "any",
                "variable": "",
                "iterable": true_expr,
                "body": true_expr,
            }
        )

    with pytest.raises(SerializationError, match="InExpression subject must be a string"):
        s._deserialize_expression(
            {
                "type": "InExpression",
                "subject": ["$a"],
                "range": true_expr,
            }
        )

    with pytest.raises(SerializationError, match="Expression must be an object"):
        s._deserialize_rule(_serialized_json_rule(name="bad_condition", condition=False))

    with pytest.raises(SerializationError, match="Expression must be an object"):
        s._deserialize_expression(
            {
                "type": "ForOfExpression",
                "quantifier": "any",
                "string_set": "them",
                "condition": False,
            }
        )


def test_json_deserialize_optional_expression_fields_reject_empty_objects() -> None:
    s = JsonSerializer()
    true_expr = {"type": "BooleanLiteral", "value": True}

    with pytest.raises(SerializationError, match="Rule condition must be an expression"):
        s._deserialize_rule(_serialized_json_rule(name="bad_condition", condition={}))

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
            {"type": "ArrayComprehension", "expression": {}, "variable": "x"},
            "ArrayComprehension expression must be an expression",
        ),
        (
            {"type": "ArrayComprehension", "variable": "x", "iterable": {}},
            "ArrayComprehension iterable must be an expression",
        ),
        (
            {"type": "ArrayComprehension", "variable": "x", "condition": {}},
            "ArrayComprehension condition must be an expression",
        ),
        (
            {"type": "DictComprehension", "key_expression": {}, "key_variable": "k"},
            "DictComprehension key_expression must be an expression",
        ),
        (
            {"type": "DictComprehension", "value_expression": {}, "key_variable": "k"},
            "DictComprehension value_expression must be an expression",
        ),
        (
            {"type": "DictComprehension", "key_variable": "k", "iterable": {}},
            "DictComprehension iterable must be an expression",
        ),
        (
            {"type": "DictComprehension", "key_variable": "k", "condition": {}},
            "DictComprehension condition must be an expression",
        ),
        (
            {"type": "SliceExpression", "target": true_expr, "start": {}},
            "SliceExpression start must be an expression",
        ),
        (
            {"type": "SliceExpression", "target": true_expr, "start": None, "stop": {}},
            "SliceExpression stop must be an expression",
        ),
        (
            {
                "type": "SliceExpression",
                "target": true_expr,
                "start": None,
                "stop": None,
                "step": {},
            },
            "SliceExpression step must be an expression",
        ),
        (
            {"type": "PatternMatch", "value": true_expr, "cases": [], "default": {}},
            "PatternMatch default must be an expression",
        ),
    )
    for payload, message in empty_optional_cases:
        with pytest.raises(SerializationError, match=message):
            s._deserialize_expression(payload)


def test_deserialize_expression_comprehensive_branches() -> None:
    s = JsonSerializer()

    assert s._deserialize_expression({}) is None

    b = s._deserialize_expression(
        {
            "type": "BinaryExpression",
            "left": {"type": "IntegerLiteral", "value": 1},
            "operator": "+",
            "right": {"type": "IntegerLiteral", "value": 2},
        }
    )
    assert isinstance(b, BinaryExpression)

    assert isinstance(
        s._deserialize_expression(
            {
                "type": "UnaryExpression",
                "operator": "not",
                "operand": {"type": "BooleanLiteral", "value": True},
            }
        ),
        UnaryExpression,
    )
    assert isinstance(
        s._deserialize_expression(
            {
                "type": "ParenthesesExpression",
                "expression": {"type": "Identifier", "name": "x"},
            }
        ),
        ParenthesesExpression,
    )
    assert isinstance(
        s._deserialize_expression(
            {
                "type": "SetExpression",
                "elements": [
                    {"type": "Identifier", "name": "x"},
                    {"type": "Identifier", "name": "y"},
                ],
            }
        ),
        SetExpression,
    )
    assert isinstance(
        s._deserialize_expression(
            {
                "type": "RangeExpression",
                "low": {"type": "IntegerLiteral", "value": 1},
                "high": {"type": "IntegerLiteral", "value": 9},
            }
        ),
        RangeExpression,
    )
    assert isinstance(
        s._deserialize_expression(
            {
                "type": "FunctionCall",
                "function": "f",
                "arguments": [{"type": "IntegerLiteral", "value": 1}],
            }
        ),
        FunctionCall,
    )
    assert isinstance(
        s._deserialize_expression(
            {
                "type": "ArrayAccess",
                "array": {"type": "Identifier", "name": "arr"},
                "index": {"type": "IntegerLiteral", "value": 0},
            }
        ),
        ArrayAccess,
    )
    assert isinstance(
        s._deserialize_expression(
            {
                "type": "MemberAccess",
                "object": {"type": "Identifier", "name": "obj"},
                "member": "x",
            }
        ),
        MemberAccess,
    )

    assert isinstance(s._deserialize_expression({"type": "Identifier", "name": "id"}), Identifier)
    assert isinstance(
        s._deserialize_expression({"type": "StringIdentifier", "name": "$a"}),
        StringIdentifier,
    )
    assert isinstance(
        s._deserialize_expression({"type": "StringWildcard", "pattern": "$a*"}),
        StringWildcard,
    )
    string_count = s._deserialize_expression({"type": "StringCount", "string_id": "$a"})
    assert isinstance(string_count, StringCount)
    assert string_count.string_id == "$a"
    assert isinstance(
        s._deserialize_expression(
            {
                "type": "StringOffset",
                "string_id": "$a",
                "index": {"type": "IntegerLiteral", "value": 1},
            }
        ),
        StringOffset,
    )
    assert isinstance(
        s._deserialize_expression(
            {
                "type": "StringLength",
                "string_id": "$a",
                "index": {"type": "IntegerLiteral", "value": 2},
            }
        ),
        StringLength,
    )

    assert isinstance(
        s._deserialize_expression({"type": "IntegerLiteral", "value": 1}),
        IntegerLiteral,
    )
    assert isinstance(
        s._deserialize_expression({"type": "DoubleLiteral", "value": 1.5}),
        DoubleLiteral,
    )
    assert isinstance(
        s._deserialize_expression({"type": "StringLiteral", "value": "x"}),
        StringLiteral,
    )
    assert isinstance(
        s._deserialize_expression({"type": "RegexLiteral", "pattern": "ab", "modifiers": "i"}),
        RegexLiteral,
    )
    assert isinstance(
        s._deserialize_expression({"type": "BooleanLiteral", "value": True}),
        BooleanLiteral,
    )


def test_deserialize_expression_condition_module_operator_paths() -> None:
    s = JsonSerializer()

    for_expr = s._deserialize_expression(
        {
            "type": "ForExpression",
            "quantifier": "any",
            "variable": "i",
            "iterable": {"type": "Identifier", "name": "them"},
            "body": {"type": "BooleanLiteral", "value": True},
        }
    )
    assert isinstance(for_expr, ForExpression)

    for_of = s._deserialize_expression(
        {
            "type": "ForOfExpression",
            "quantifier": "all",
            "string_set": {"type": "SetExpression", "elements": []},
            "condition": {"type": "BooleanLiteral", "value": True},
        }
    )
    assert isinstance(for_of, ForOfExpression)

    at_expr = s._deserialize_expression(
        {
            "type": "AtExpression",
            "string_id": "$a",
            "offset": {"type": "IntegerLiteral", "value": 10},
        }
    )
    assert isinstance(at_expr, AtExpression)

    at_of_expr = s._deserialize_expression(
        {
            "type": "AtExpression",
            "string_id": {
                "type": "OfExpression",
                "quantifier": "all",
                "string_set": {"type": "Identifier", "name": "them"},
            },
            "offset": {"type": "IntegerLiteral", "value": 10},
        }
    )
    assert isinstance(at_of_expr, AtExpression)
    assert isinstance(at_of_expr.string_id, OfExpression)

    in_str = s._deserialize_expression(
        {
            "type": "InExpression",
            "string_id": "$a",
            "range": {"type": "IntegerLiteral", "value": 50},
        }
    )
    assert isinstance(in_str, InExpression)
    assert in_str.subject == "$a"

    in_dict_subject = s._deserialize_expression(
        {
            "type": "InExpression",
            "subject": {"type": "Identifier", "name": "x"},
            "range": {"type": "IntegerLiteral", "value": 5},
        }
    )
    assert isinstance(in_dict_subject.subject, Identifier)

    of_expr = s._deserialize_expression(
        {
            "type": "OfExpression",
            "quantifier": {"type": "IntegerLiteral", "value": 1},
            "string_set": {"type": "SetExpression", "elements": []},
        }
    )
    assert isinstance(of_expr, OfExpression)

    mod_ref = s._deserialize_expression({"type": "ModuleReference", "module": "pe"})
    assert isinstance(mod_ref, ModuleReference)

    dacc_plain = s._deserialize_expression(
        {
            "type": "DictionaryAccess",
            "object": {"type": "ModuleReference", "module": "pe"},
            "key": "k",
        }
    )
    assert isinstance(dacc_plain, DictionaryAccess)

    dacc_expr_key = s._deserialize_expression(
        {
            "type": "DictionaryAccess",
            "object": {"type": "ModuleReference", "module": "pe"},
            "key": {"type": "StringLiteral", "value": "CompanyName"},
        }
    )
    assert isinstance(dacc_expr_key.key, StringLiteral)

    with pytest.raises(SerializationError, match="DefinedExpression expression is required"):
        s._deserialize_expression(
            {
                "type": "DefinedExpression",
                "identifier": "foo",
            }
        )

    with pytest.raises(SerializationError, match="DefinedExpression expression is required"):
        s._deserialize_expression({"type": "DefinedExpression"})

    with pytest.raises(SerializationError, match="DefinedExpression expression is required"):
        s._deserialize_expression({"type": "DefinedExpression", "expression": {}})

    with pytest.raises(SerializationError, match="StringOperatorExpression left is required"):
        s._deserialize_expression(
            {
                "type": "StringOperatorExpression",
                "subject": {"type": "Identifier", "name": "x"},
                "operator": "contains",
                "pattern": "abc",
            }
        )

    with pytest.raises(SerializationError, match="StringOperatorExpression left is required"):
        s._deserialize_expression(
            {
                "type": "StringOperatorExpression",
                "operator": "contains",
                "right": {"type": "StringLiteral", "value": "abc"},
            }
        )

    with pytest.raises(SerializationError, match="StringOperatorExpression left is required"):
        s._deserialize_expression(
            {
                "type": "StringOperatorExpression",
                "left": {},
                "operator": "contains",
                "right": {"type": "StringLiteral", "value": "abc"},
            }
        )

    with pytest.raises(SerializationError, match="StringOperatorExpression right is required"):
        s._deserialize_expression(
            {
                "type": "StringOperatorExpression",
                "left": {"type": "StringLiteral", "value": "abc"},
                "operator": "contains",
                "right": {},
            }
        )

    with pytest.raises(SerializationError, match="StringOperatorExpression right is required"):
        s._deserialize_expression(
            {
                "type": "StringOperatorExpression",
                "left": {"type": "StringLiteral", "value": "abc"},
                "operator": "contains",
            }
        )

    with pytest.raises(SerializationError, match="StringOperatorExpression left is required"):
        s._deserialize_expression(
            {
                "type": "StringOperatorExpression",
                "operator": "matches",
            }
        )

    with pytest.raises(SerializationError, match="Unknown expression type"):
        s._deserialize_expression({"type": "Nope"})

    negated = s._deserialize_hex_token({"type": "HexNegatedByte", "value": 0x4D})
    assert isinstance(negated, HexNegatedByte)
    assert negated.value == 0x4D

    with pytest.raises(SerializationError, match="Unknown hex token type"):
        s._deserialize_hex_token({"type": "HexUnknownType"})
