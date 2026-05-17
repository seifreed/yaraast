"""Additional tests for JSON serializer (no mocks)."""

from __future__ import annotations

import json

import pytest

from yaraast.ast.base import YaraFile
from yaraast.ast.conditions import ForExpression, ForOfExpression, InExpression, OfExpression
from yaraast.ast.expressions import (
    BinaryExpression,
    BooleanLiteral,
    Identifier,
    IntegerLiteral,
    StringCount,
    StringIdentifier,
)
from yaraast.ast.extern import ExternImport, ExternNamespace, ExternRule, ExternRuleReference
from yaraast.ast.modifiers import MetaEntry, MetaScope, RuleModifier, StringModifier
from yaraast.ast.modules import DictionaryAccess, ModuleReference
from yaraast.ast.pragmas import CustomPragma, DefineDirective, InRulePragma, PragmaScope
from yaraast.ast.rules import Import, Rule
from yaraast.ast.strings import (
    HexAlternative,
    HexByte,
    HexJump,
    HexString,
    PlainString,
    RegexString,
)
from yaraast.errors import SerializationError
from yaraast.parser import Parser
from yaraast.serialization.json_serializer import JsonSerializer


def _sample_ast() -> YaraFile:
    rule = Rule(
        name="r1",
        tags=[],
        meta={"author": "me"},
        strings=[
            PlainString(
                identifier="$a",
                value="x",
                modifiers=[StringModifier.from_name_value("ascii")],
            ),
            RegexString(identifier="$b", regex="ab.*"),
            HexString(identifier="$c", tokens=[HexJump(min_jump=1, max_jump=2)]),
        ],
        condition=BinaryExpression(
            left=Identifier(name="true"),
            operator="and",
            right=InExpression(subject="a", range=IntegerLiteral(value=10)),
        ),
    )
    return YaraFile(imports=[Import(module="pe")], includes=[], rules=[rule])


def test_json_serialize_deserialize_roundtrip() -> None:
    serializer = JsonSerializer(include_metadata=True)
    ast = _sample_ast()

    json_str = serializer.serialize(ast)
    data = json.loads(json_str)
    assert data["metadata"]["rules_count"] == 1

    restored = serializer.deserialize(json_str)
    assert restored.rules[0].name == "r1"
    assert restored.rules[0].strings


def test_json_roundtrip_preserves_plain_string_bytes() -> None:
    serializer = JsonSerializer(include_metadata=False)
    ast = YaraFile(
        rules=[
            Rule(
                name="bytes_rule",
                strings=[PlainString(identifier="$b", value=b'A"\x00\xff\\\n')],
                condition=BooleanLiteral(True),
            )
        ]
    )

    json_str = serializer.serialize(ast)
    data = json.loads(json_str)

    serialized_string = data["ast"]["rules"][0]["strings"][0]
    assert serialized_string["value_encoding"] == "base64"
    assert isinstance(serialized_string["value"], str)

    restored = serializer.deserialize(json_str)
    restored_string = restored.rules[0].strings[0]

    assert isinstance(restored_string, PlainString)
    assert restored_string.value == b'A"\x00\xff\\\n'


def test_json_serializer_normalizes_scalar_hex_alternatives() -> None:
    serializer = JsonSerializer(include_metadata=False)
    ast = YaraFile(
        rules=[
            Rule(
                name="scalar_hex_alternative",
                strings=[HexString(identifier="$h", tokens=[HexAlternative([0x90, "91"])])],
                condition=BooleanLiteral(value=True),
            )
        ]
    )

    restored = serializer.deserialize(serializer.serialize(ast))
    string_def = restored.rules[0].strings[0]

    assert isinstance(string_def, HexString)
    assert string_def.tokens == [HexAlternative([[HexByte(0x90)], [HexByte("91")]])]


def test_json_roundtrip_preserves_string_count_conditions() -> None:
    ast = Parser('rule r { strings: $a = "x" condition: #a > 0 }').parse()
    serializer = JsonSerializer(include_metadata=True)

    restored = serializer.deserialize(serializer.serialize(ast))
    condition = restored.rules[0].condition

    assert isinstance(condition, BinaryExpression)
    assert isinstance(condition.left, StringCount)
    assert condition.left.string_id == "a"


def test_json_roundtrip_preserves_raw_for_of_values() -> None:
    serializer = JsonSerializer(include_metadata=False)
    ast = YaraFile(
        rules=[
            Rule(
                name="raw_them",
                condition=ForOfExpression(
                    quantifier="all",
                    string_set="them",
                    condition=None,
                ),
            ),
            Rule(
                name="raw_list",
                condition=OfExpression(
                    quantifier=IntegerLiteral(2),
                    string_set=["$a", "$b"],
                ),
            ),
            Rule(
                name="raw_tuple",
                condition=OfExpression(
                    quantifier=IntegerLiteral(2),
                    string_set=("$a", "$b"),
                ),
            ),
            Rule(
                name="raw_frozenset",
                condition=OfExpression(
                    quantifier=IntegerLiteral(2),
                    string_set=frozenset(("$a", "$b")),
                ),
            ),
            Rule(
                name="expression_quantifier",
                condition=ForExpression(
                    quantifier=IntegerLiteral(2),
                    variable="i",
                    iterable=Identifier("items"),
                    body=BooleanLiteral(True),
                ),
            ),
        ]
    )

    serialized = json.loads(serializer.serialize(ast))
    conditions = [rule["condition"] for rule in serialized["ast"]["rules"]]
    assert conditions[0]["string_set"] == "them"
    assert conditions[1]["string_set"] == ["$a", "$b"]
    assert conditions[2]["string_set"] == ["$a", "$b"]
    assert conditions[3]["string_set"] == ["$a", "$b"]
    assert conditions[4]["quantifier"] == {"type": "IntegerLiteral", "value": 2}

    restored = serializer.deserialize(json.dumps(serialized))
    raw_them = restored.rules[0].condition
    raw_list = restored.rules[1].condition
    raw_tuple = restored.rules[2].condition
    raw_frozenset = restored.rules[3].condition
    expression_quantifier = restored.rules[4].condition

    assert isinstance(raw_them, ForOfExpression)
    assert raw_them.string_set == "them"
    assert isinstance(raw_list, OfExpression)
    assert raw_list.string_set == ["$a", "$b"]
    assert isinstance(raw_tuple, OfExpression)
    assert raw_tuple.string_set == ["$a", "$b"]
    assert isinstance(raw_frozenset, OfExpression)
    assert raw_frozenset.string_set == ["$a", "$b"]
    assert isinstance(expression_quantifier, ForExpression)
    assert isinstance(expression_quantifier.quantifier, IntegerLiteral)
    assert expression_quantifier.quantifier.value == 2


def test_json_roundtrip_preserves_typed_string_modifier_values() -> None:
    serializer = JsonSerializer(include_metadata=False)
    ast = YaraFile(
        rules=[
            Rule(
                name="typed_modifiers",
                strings=[
                    PlainString(
                        identifier="$a",
                        value="a",
                        modifiers=[StringModifier.from_name_value("xor", 5)],
                    ),
                    PlainString(
                        identifier="$b",
                        value="b",
                        modifiers=[StringModifier.from_name_value("xor", (1, 3))],
                    ),
                    PlainString(
                        identifier="$c",
                        value="c",
                        modifiers=[StringModifier.from_name_value("base64", "alphabet")],
                    ),
                ],
                condition=BooleanLiteral(True),
            )
        ]
    )

    restored = serializer.deserialize(serializer.serialize(ast))
    restored_strings = restored.rules[0].strings

    assert [string.modifiers[0].value for string in restored_strings] == [
        5,
        (1, 3),
        "alphabet",
    ]


def test_json_roundtrip_preserves_string_modifier_aliases() -> None:
    serializer = JsonSerializer(include_metadata=False)
    ast = YaraFile(
        rules=[
            Rule(
                name="regex_aliases",
                strings=[
                    RegexString(
                        identifier="$r",
                        regex="ab.*",
                        modifiers=["i", "s", StringModifier.from_name_value("fullword")],
                    ),
                ],
                condition=StringIdentifier("$r"),
            )
        ]
    )

    restored = serializer.deserialize(serializer.serialize(ast))
    modifiers = restored.rules[0].strings[0].modifiers

    assert modifiers[:2] == ["i", "s"]
    assert isinstance(modifiers[2], StringModifier)
    assert modifiers[2].name == "fullword"

    legacy = serializer.deserialize(
        json.dumps(
            {
                "type": "YaraFile",
                "rules": [
                    {
                        "type": "Rule",
                        "name": "legacy_aliases",
                        "strings": [
                            {
                                "type": "RegexString",
                                "identifier": "$r",
                                "regex": "ab.*",
                                "modifiers": ["i", "s"],
                            }
                        ],
                        "condition": {"type": "StringIdentifier", "name": "$r"},
                    }
                ],
            }
        )
    )
    assert legacy.rules[0].strings[0].modifiers == ["i", "s"]


def test_json_roundtrip_preserves_meta_entry_scope() -> None:
    serializer = JsonSerializer(include_metadata=False)
    ast = YaraFile(
        rules=[
            Rule(
                name="meta_scope",
                meta=[
                    MetaEntry.from_key_value("secret", "token", "private"),
                    MetaEntry.from_key_value("owner", "team"),
                ],
                condition=BooleanLiteral(True),
            )
        ]
    )

    serialized = json.loads(serializer.serialize(ast))
    restored = serializer.deserialize(json.dumps(serialized))

    assert serialized["ast"]["rules"][0]["meta"][0]["scope"] == "private"
    assert [entry.scope for entry in restored.rules[0].meta] == [
        MetaScope.PRIVATE,
        MetaScope.PUBLIC,
    ]
    assert [entry.key for entry in restored.rules[0].get_private_meta()] == ["secret"]


def test_json_roundtrip_preserves_externs_and_pragmas() -> None:
    serializer = JsonSerializer(include_metadata=True)
    ast = YaraFile(
        extern_rules=[
            ExternRule(
                name="ExternalRule",
                modifiers=[RuleModifier.from_string("private")],
                namespace="ns",
            )
        ],
        extern_imports=[
            ExternImport(
                module_path="external.yar",
                alias="ext",
                rules=["ExternalRule"],
            )
        ],
        pragmas=[
            CustomPragma(
                name="vendor",
                arguments=["on"],
                parameters={"level": "strict"},
                scope=PragmaScope.FILE,
            )
        ],
        namespaces=[
            ExternNamespace(
                name="ns",
                extern_rules=[ExternRule(name="NestedRule", namespace="ns")],
            )
        ],
        rules=[
            Rule(
                name="r1",
                pragmas=[
                    InRulePragma(
                        pragma=DefineDirective("LIMIT", "10"),
                        position="before_condition",
                    )
                ],
                condition=BooleanLiteral(True),
            )
        ],
    )

    serialized = json.loads(serializer.serialize(ast))
    ast_data = serialized["ast"]
    assert ast_data["extern_imports"][0]["module_path"] == "external.yar"
    assert ast_data["extern_rules"][0]["namespace"] == "ns"
    assert ast_data["pragmas"][0]["parameters"] == {"level": "strict"}
    assert ast_data["rules"][0]["pragmas"][0]["pragma"]["macro_name"] == "LIMIT"

    restored = serializer.deserialize(json.dumps(serialized))
    assert isinstance(restored.extern_imports[0], ExternImport)
    assert restored.extern_imports[0].module_path == "external.yar"
    assert restored.extern_imports[0].alias == "ext"
    assert restored.extern_imports[0].rules == ["ExternalRule"]
    assert isinstance(restored.extern_rules[0], ExternRule)
    assert str(restored.extern_rules[0].modifiers[0]) == "private"
    assert restored.extern_rules[0].namespace == "ns"
    assert isinstance(restored.pragmas[0], CustomPragma)
    assert restored.pragmas[0].parameters["level"] == "strict"
    assert isinstance(restored.namespaces[0], ExternNamespace)
    assert restored.namespaces[0].extern_rules[0].name == "NestedRule"
    assert restored.rules[0].pragmas[0].position == "before_condition"
    assert isinstance(restored.rules[0].pragmas[0].pragma, DefineDirective)
    assert restored.rules[0].pragmas[0].pragma.macro_value == "10"

    reference = serializer._deserialize_expression(
        serializer.visit_extern_rule_reference(ExternRuleReference("ExternalRule", namespace="ns"))
    )
    assert isinstance(reference, ExternRuleReference)
    assert reference.qualified_name == "ns.ExternalRule"


def test_json_deserialize_expressions() -> None:
    serializer = JsonSerializer()

    expr_data = {
        "type": "DictionaryAccess",
        "object": {"type": "ModuleReference", "module": "pe"},
        "key": {"type": "StringLiteral", "value": "CompanyName"},
    }
    expr = serializer._deserialize_expression(expr_data)
    assert isinstance(expr, DictionaryAccess)
    assert isinstance(expr.object, ModuleReference)

    in_expr_data = {
        "type": "InExpression",
        "string_id": {"type": "StringIdentifier", "name": "$a"},
        "range": {"type": "IntegerLiteral", "value": 5},
    }
    in_expr = serializer._deserialize_expression(in_expr_data)
    assert isinstance(in_expr.subject, StringIdentifier)


def test_json_deserialize_errors() -> None:
    serializer = JsonSerializer()

    with pytest.raises(SerializationError):
        serializer._deserialize_string({"type": "UnknownString"})

    with pytest.raises(SerializationError):
        serializer._deserialize_expression({"type": "UnknownExpr"})
