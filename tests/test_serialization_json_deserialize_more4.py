"""More branch coverage for JSON deserialization helpers."""

from __future__ import annotations

import pytest

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
from yaraast.ast.modifiers import StringModifier
from yaraast.ast.modules import DictionaryAccess, ModuleReference
from yaraast.ast.operators import DefinedExpression
from yaraast.ast.rules import Import, Include, Rule
from yaraast.ast.strings import (
    HexByte,
    HexJump,
    HexNegatedByte,
    HexString,
    HexWildcard,
    PlainString,
    RegexString,
)
from yaraast.errors import SerializationError
from yaraast.serialization.json_serializer import JsonSerializer


def test_deserialize_import_include_meta_and_rule_meta_variants() -> None:
    s = JsonSerializer()

    imp = s._deserialize_import({"module": "pe", "alias": "p"})
    inc = s._deserialize_include({"path": "x.yar"})
    assert isinstance(imp, Import)
    assert isinstance(inc, Include)

    meta = s._deserialize_meta({"key": "author", "value": "me"})
    assert meta.key == "author"

    rule_dict_meta = s._deserialize_rule(
        {
            "name": "r1",
            "modifiers": ["private"],
            "tags": [{"name": "t1"}],
            "meta": {"a": 1, "b": "x"},
            "strings": [{"type": "PlainString", "identifier": "$a", "value": "x", "modifiers": []}],
            "condition": {"type": "Identifier", "name": "true"},
        }
    )
    assert isinstance(rule_dict_meta, Rule)
    assert len(rule_dict_meta.meta) == 2

    rule_list_meta = s._deserialize_rule(
        {
            "name": "r2",
            "meta": [{"key": "k", "value": 1}],
            "strings": [],
            "tags": [],
            "condition": None,
        }
    )
    assert rule_list_meta.condition is None


def test_json_deserialize_rule_metadata_nodes_reject_wrong_scalar_types() -> None:
    s = JsonSerializer()

    with pytest.raises(SerializationError, match="Import module must be a string"):
        s._deserialize_import({"module": ["pe"]})

    with pytest.raises(SerializationError, match="Import alias must be a string"):
        s._deserialize_import({"module": "pe", "alias": True})

    with pytest.raises(SerializationError, match="Include path must be a string"):
        s._deserialize_include({"path": ["x.yar"]})

    with pytest.raises(SerializationError, match="Rule name must be a string"):
        s._deserialize_rule({"name": ["r1"], "condition": None})

    with pytest.raises(SerializationError, match="Tag name must be a string"):
        s._deserialize_tag({"name": 7})

    with pytest.raises(SerializationError, match="Meta key must be a string"):
        s._deserialize_meta({"key": ["author"], "value": "me"})

    with pytest.raises(
        SerializationError, match="Meta value must be a string, integer, or boolean"
    ):
        s._deserialize_meta({"key": "score", "value": 1.5})

    with pytest.raises(
        SerializationError, match="Meta value must be a string, integer, or boolean"
    ):
        s._deserialize_rule(
            {"name": "r1", "meta": {"score": 1.5}, "strings": [], "condition": None}
        )


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
            "modifiers": [{"name": "ascii"}],
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


def test_json_deserialize_string_requires_literal_true_for_anonymous_flag() -> None:
    s = JsonSerializer()

    plain = s._deserialize_string(
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


def test_json_deserialize_strings_reject_wrong_scalar_types() -> None:
    s = JsonSerializer()

    with pytest.raises(SerializationError, match="PlainString identifier must be a string"):
        s._deserialize_string(
            {"type": "PlainString", "identifier": ["$a"], "value": "abc", "modifiers": []}
        )

    with pytest.raises(SerializationError, match="PlainString value must be a string or bytes"):
        s._deserialize_string(
            {"type": "PlainString", "identifier": "$a", "value": True, "modifiers": []}
        )

    with pytest.raises(SerializationError, match="HexString identifier must be a string"):
        s._deserialize_string(
            {"type": "HexString", "identifier": ["$h"], "tokens": [], "modifiers": []}
        )

    with pytest.raises(SerializationError, match="RegexString regex must be a string"):
        s._deserialize_string(
            {"type": "RegexString", "identifier": "$r", "regex": 123, "modifiers": []}
        )


def test_json_deserialize_hex_tokens_reject_invalid_scalar_fields() -> None:
    s = JsonSerializer()

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
            s._deserialize_string(
                {"type": "HexString", "identifier": "$h", "tokens": [token], "modifiers": []}
            )


def test_json_deserialize_literal_nodes_reject_wrong_scalar_types() -> None:
    s = JsonSerializer()

    with pytest.raises(SerializationError, match="IntegerLiteral value must be an integer"):
        s._deserialize_expression({"type": "IntegerLiteral", "value": True})

    with pytest.raises(SerializationError, match="BooleanLiteral value must be a boolean"):
        s._deserialize_expression({"type": "BooleanLiteral", "value": "false"})

    with pytest.raises(SerializationError, match="DoubleLiteral value must be numeric"):
        s._deserialize_expression({"type": "DoubleLiteral", "value": True})

    with pytest.raises(SerializationError, match="DoubleLiteral value must be numeric"):
        s._deserialize_expression({"type": "DoubleLiteral", "value": "1.5"})

    with pytest.raises(SerializationError, match="StringLiteral value must be a string"):
        s._deserialize_expression({"type": "StringLiteral", "value": True})

    with pytest.raises(SerializationError, match="Identifier name must be a string"):
        s._deserialize_expression({"type": "Identifier", "name": ["id"]})

    with pytest.raises(SerializationError, match="RegexLiteral pattern must be a string"):
        s._deserialize_expression({"type": "RegexLiteral", "pattern": 123})

    with pytest.raises(SerializationError, match="RegexLiteral modifiers must be a string"):
        s._deserialize_expression({"type": "RegexLiteral", "pattern": "abc", "modifiers": ["i"]})


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

    defined_with_identifier = s._deserialize_expression(
        {
            "type": "DefinedExpression",
            "identifier": "foo",
        }
    )
    assert isinstance(defined_with_identifier, DefinedExpression)

    sop_subject_pattern = s._deserialize_expression(
        {
            "type": "StringOperatorExpression",
            "subject": {"type": "Identifier", "name": "x"},
            "operator": "contains",
            "pattern": "abc",
        }
    )
    assert sop_subject_pattern.operator == "contains"

    sop_defaults = s._deserialize_expression(
        {
            "type": "StringOperatorExpression",
            "operator": "matches",
        }
    )
    assert sop_defaults.left == Identifier("true")
    assert sop_defaults.right == Identifier("true")

    with pytest.raises(SerializationError, match="Unknown expression type"):
        s._deserialize_expression({"type": "Nope"})

    negated = s._deserialize_hex_token({"type": "HexNegatedByte", "value": 0x4D})
    assert isinstance(negated, HexNegatedByte)
    assert negated.value == 0x4D

    with pytest.raises(SerializationError, match="Unknown hex token type"):
        s._deserialize_hex_token({"type": "HexUnknownType"})
