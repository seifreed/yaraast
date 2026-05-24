"""Additional tests for JSON serializer (no mocks)."""

from __future__ import annotations

import json
from typing import Any

import pytest

from yaraast.ast.base import YaraFile
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
from yaraast.ast.modifiers import MetaEntry, MetaScope, RuleModifier, StringModifier
from yaraast.ast.modules import DictionaryAccess, ModuleReference
from yaraast.ast.operators import DefinedExpression, StringOperatorExpression
from yaraast.ast.pragmas import CustomPragma, DefineDirective, InRulePragma, PragmaScope
from yaraast.ast.rules import Import, Include, Rule, Tag
from yaraast.ast.strings import (
    HexAlternative,
    HexByte,
    HexJump,
    HexString,
    PlainString,
    RegexString,
)
from yaraast.codegen.generator import CodeGenerator
from yaraast.errors import SerializationError
from yaraast.parser import Parser
from yaraast.serialization.json_serializer import JsonSerializer
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


def test_json_roundtrip_preserves_anonymous_strings_for_codegen() -> None:
    serializer = JsonSerializer(include_metadata=False)
    ast = Parser(
        'rule r { strings: $ = "abc" $ = { 41 } $ = /def/ condition: any of them }'
    ).parse()

    restored = serializer.deserialize(serializer.serialize(ast))
    restored_strings = restored.rules[0].strings

    assert [string.is_anonymous for string in restored_strings] == [True, True, True]
    output = CodeGenerator().generate(restored)
    assert '$ = "abc"' in output
    assert "$ = { 41 }" in output
    assert "$ = /def/" in output
    assert "$anon_" not in output


def test_json_serializer_rejects_invalid_raw_conditions() -> None:
    serializer = JsonSerializer(include_metadata=False)
    invalid_conditions: list[Any] = [False, 0, object()]

    for condition in invalid_conditions:
        ast = YaraFile(rules=[Rule(name="invalid_condition", condition=condition)])
        with pytest.raises(SerializationError, match="Rule condition must be an AST expression"):
            serializer.serialize(ast)


def test_json_serializer_rejects_invalid_raw_for_of_conditions() -> None:
    serializer = JsonSerializer(include_metadata=False)
    invalid_condition: Any = False
    ast = YaraFile(
        rules=[
            Rule(
                name="invalid_for_of_condition",
                condition=ForOfExpression("any", Identifier("them"), invalid_condition),
            )
        ]
    )

    with pytest.raises(
        SerializationError,
        match="ForOfExpression condition must be an AST expression",
    ):
        serializer.serialize(ast)


def test_json_serializer_rejects_invalid_raw_quantifiers() -> None:
    serializer = JsonSerializer(include_metadata=False)
    invalid_quantifiers: list[Any] = [False, [], {}, None, object()]

    for quantifier in invalid_quantifiers:
        expressions = [
            ForExpression(
                quantifier,
                "i",
                IntegerLiteral(0),
                BooleanLiteral(True),
            ),
            ForOfExpression(quantifier, Identifier("them"), None),
            OfExpression(quantifier, Identifier("them")),
        ]
        for expression in expressions:
            ast = YaraFile(rules=[Rule(name="invalid_quantifier", condition=expression)])
            with pytest.raises(SerializationError, match="quantifier must be"):
                serializer.serialize(ast)


def test_json_serializer_rejects_non_expression_ast_quantifiers() -> None:
    serializer = JsonSerializer(include_metadata=False)
    invalid_quantifier: Any = Import("pe")

    expressions = [
        ForExpression(
            invalid_quantifier,
            "i",
            Identifier("items"),
            BooleanLiteral(True),
        ),
        ForOfExpression(invalid_quantifier, "them", None),
        OfExpression(invalid_quantifier, "them"),
    ]
    for expression in expressions:
        ast = YaraFile(rules=[Rule(name="invalid_quantifier", condition=expression)])
        with pytest.raises(SerializationError, match="quantifier must be"):
            serializer.serialize(ast)


def test_json_serializer_rejects_invalid_string_or_expression_fields() -> None:
    serializer = JsonSerializer(include_metadata=False)
    invalid_values: list[Any] = [False, 123, None, [], {}, object(), Import("pe")]

    for invalid_value in invalid_values:
        expressions = [
            InExpression(invalid_value, IntegerLiteral(1)),
            DictionaryAccess(Identifier("items"), invalid_value),
        ]
        for expression in expressions:
            ast = YaraFile(rules=[Rule(name="invalid_string_or_expression", condition=expression)])
            with pytest.raises(SerializationError, match="must be a string or expression"):
                serializer.serialize(ast)


def test_json_serializer_rejects_invalid_required_expression_fields() -> None:
    serializer = JsonSerializer(include_metadata=False)
    invalid_values: list[Any] = [False, Import("pe")]

    for invalid_value in invalid_values:
        expressions = [
            BinaryExpression(invalid_value, "and", BooleanLiteral(True)),
            BinaryExpression(BooleanLiteral(True), "and", invalid_value),
            UnaryExpression("not", invalid_value),
            ParenthesesExpression(invalid_value),
            SetExpression([invalid_value]),
            RangeExpression(invalid_value, IntegerLiteral(1)),
            RangeExpression(IntegerLiteral(0), invalid_value),
            FunctionCall("fn", [invalid_value]),
            ArrayAccess(invalid_value, IntegerLiteral(0)),
            ArrayAccess(Identifier("items"), invalid_value),
            MemberAccess(invalid_value, "field"),
            ForExpression("any", "i", invalid_value, BooleanLiteral(True)),
            ForExpression("any", "i", Identifier("items"), invalid_value),
            AtExpression("$a", invalid_value),
            InExpression("$a", invalid_value),
            DictionaryAccess(invalid_value, "key"),
            DefinedExpression(invalid_value),
            StringOperatorExpression(invalid_value, "contains", StringLiteral("x")),
            StringOperatorExpression(StringLiteral("x"), "contains", invalid_value),
            WithStatement([], invalid_value),
            WithStatement([WithDeclaration("x", invalid_value)], BooleanLiteral(True)),
            TupleExpression([invalid_value]),
            TupleIndexing(invalid_value, IntegerLiteral(0)),
            TupleIndexing(Identifier("tuple"), invalid_value),
            ListExpression([invalid_value]),
            DictExpression([DictItem(invalid_value, IntegerLiteral(1))]),
            DictExpression([DictItem(StringLiteral("k"), invalid_value)]),
            SliceExpression(invalid_value),
            LambdaExpression(["x"], invalid_value),
            PatternMatch(invalid_value, []),
            PatternMatch(Identifier("subject"), [MatchCase(invalid_value, BooleanLiteral(True))]),
            PatternMatch(Identifier("subject"), [MatchCase(StringLiteral("p"), invalid_value)]),
            SpreadOperator(invalid_value),
        ]
        for expression in expressions:
            ast = YaraFile(rules=[Rule(name="invalid_required", condition=expression)])
            with pytest.raises(SerializationError, match="must be an AST expression"):
                serializer.serialize(ast)


def test_json_serializer_rejects_invalid_leaf_values() -> None:
    serializer = JsonSerializer(include_metadata=False)
    invalid_list: Any = ["name"]
    invalid_text: Any = 123
    invalid_integer: Any = "1"
    invalid_number: Any = "1.2"
    invalid_string: Any = True
    invalid_regex_modifiers: Any = ["i"]
    invalid_bool: Any = "true"

    invalid_cases = [
        (Identifier(invalid_list), "Identifier name must be a string"),
        (StringIdentifier(invalid_text), "StringIdentifier name must be a string"),
        (StringWildcard(invalid_text), "StringWildcard pattern must be a string"),
        (StringCount(invalid_text), "StringCount string_id must be a string"),
        (StringOffset(invalid_text), "StringOffset string_id must be a string"),
        (StringLength(invalid_text), "StringLength string_id must be a string"),
        (IntegerLiteral(True), "IntegerLiteral value must be an integer"),
        (IntegerLiteral(invalid_integer), "IntegerLiteral value must be an integer"),
        (DoubleLiteral(invalid_number), "DoubleLiteral value must be numeric"),
        (StringLiteral(invalid_string), "StringLiteral value must be a string"),
        (RegexLiteral(invalid_text), "RegexLiteral pattern must be a string"),
        (RegexLiteral("abc", invalid_regex_modifiers), "RegexLiteral modifiers must be a string"),
        (BooleanLiteral(invalid_bool), "BooleanLiteral value must be a boolean"),
        (ModuleReference(invalid_list), "ModuleReference module must be a string"),
        (AtExpression(invalid_text, IntegerLiteral(0)), "AtExpression string_id must be a string"),
    ]

    for expression, message in invalid_cases:
        ast = YaraFile(rules=[Rule(name="invalid_leaf", condition=expression)])
        with pytest.raises(SerializationError, match=message):
            serializer.serialize(ast)


def test_json_serializer_rejects_invalid_declaration_string_fields() -> None:
    serializer = JsonSerializer(include_metadata=False)
    invalid_text: Any = 123

    invalid_cases: list[tuple[YaraFile, str]] = [
        (
            YaraFile(imports=[Import(module=invalid_text)]),
            "Import module must be a string",
        ),
        (
            YaraFile(imports=[Import(module="pe", alias=invalid_text)]),
            "Import alias must be a string",
        ),
        (
            YaraFile(includes=[Include(path=invalid_text)]),
            "Include path must be a string",
        ),
        (
            YaraFile(rules=[Rule(name=invalid_text, condition=BooleanLiteral(True))]),
            "Rule name must be a string",
        ),
        (
            YaraFile(
                rules=[
                    Rule(
                        name="invalid_tag",
                        tags=[Tag(name=invalid_text)],
                        condition=BooleanLiteral(True),
                    )
                ]
            ),
            "Tag name must be a string",
        ),
        (
            YaraFile(
                rules=[
                    Rule(
                        name="invalid_plain_identifier",
                        strings=[PlainString(identifier=invalid_text, value="x")],
                        condition=BooleanLiteral(True),
                    )
                ]
            ),
            "PlainString identifier must be a string",
        ),
        (
            YaraFile(
                rules=[
                    Rule(
                        name="invalid_plain_value",
                        strings=[PlainString(identifier="$a", value=invalid_text)],
                        condition=BooleanLiteral(True),
                    )
                ]
            ),
            "PlainString value must be a string or bytes",
        ),
        (
            YaraFile(
                rules=[
                    Rule(
                        name="invalid_hex_identifier",
                        strings=[HexString(identifier=invalid_text, tokens=[])],
                        condition=BooleanLiteral(True),
                    )
                ]
            ),
            "HexString identifier must be a string",
        ),
        (
            YaraFile(
                rules=[
                    Rule(
                        name="invalid_regex_identifier",
                        strings=[RegexString(identifier=invalid_text, regex="x")],
                        condition=BooleanLiteral(True),
                    )
                ]
            ),
            "RegexString identifier must be a string",
        ),
        (
            YaraFile(
                rules=[
                    Rule(
                        name="invalid_regex_value",
                        strings=[RegexString(identifier="$a", regex=invalid_text)],
                        condition=BooleanLiteral(True),
                    )
                ]
            ),
            "RegexString regex must be a string",
        ),
    ]

    for ast, message in invalid_cases:
        with pytest.raises(SerializationError, match=message):
            serializer.serialize(ast)


def test_json_serializer_rejects_invalid_expression_scalar_fields() -> None:
    serializer = JsonSerializer(include_metadata=False)
    invalid_text: Any = 123
    invalid_bool: Any = "true"
    invalid_parameters: Any = ["x", 123]

    invalid_cases = [
        (
            BinaryExpression(BooleanLiteral(True), invalid_text, BooleanLiteral(False)),
            "BinaryExpression operator must be a string",
        ),
        (
            UnaryExpression(invalid_text, BooleanLiteral(True)),
            "UnaryExpression operator must be a string",
        ),
        (
            FunctionCall(invalid_text, []),
            "FunctionCall function must be a string",
        ),
        (
            MemberAccess(Identifier("pe"), invalid_text),
            "MemberAccess member must be a string",
        ),
        (
            ForExpression("any", invalid_text, Identifier("items"), BooleanLiteral(True)),
            "ForExpression variable must be a string",
        ),
        (
            StringOperatorExpression(StringLiteral("a"), invalid_text, StringLiteral("b")),
            "StringOperatorExpression operator must be a string",
        ),
        (
            WithStatement(
                [WithDeclaration(invalid_text, IntegerLiteral(1))],
                BooleanLiteral(True),
            ),
            "WithDeclaration identifier must be a string",
        ),
        (
            ArrayComprehension(variable=invalid_text),
            "ArrayComprehension variable must be a string",
        ),
        (
            DictComprehension(key_variable=invalid_text),
            "DictComprehension key_variable must be a string",
        ),
        (
            DictComprehension(value_variable=invalid_text),
            "DictComprehension value_variable must be a string",
        ),
        (
            LambdaExpression(invalid_parameters, BooleanLiteral(True)),
            "LambdaExpression parameters must be a list of strings",
        ),
        (
            SpreadOperator(Identifier("items"), is_dict=invalid_bool),
            "SpreadOperator is_dict must be a boolean",
        ),
    ]

    for expression, message in invalid_cases:
        ast = YaraFile(rules=[Rule(name="invalid_scalar", condition=expression)])
        with pytest.raises(SerializationError, match=message):
            serializer.serialize(ast)


def test_json_serializer_rejects_invalid_extern_scalar_fields() -> None:
    serializer = JsonSerializer(include_metadata=False)
    invalid_text: Any = 123
    invalid_rules: Any = ["rule_a", 123]

    invalid_cases: list[tuple[YaraFile, str]] = [
        (
            YaraFile(extern_imports=[ExternImport(invalid_text)]),
            "ExternImport module_path must be a string",
        ),
        (
            YaraFile(extern_imports=[ExternImport("external", alias=invalid_text)]),
            "ExternImport alias must be a string",
        ),
        (
            YaraFile(extern_imports=[ExternImport("external", rules=invalid_rules)]),
            "ExternImport rules must be a list of strings",
        ),
        (
            YaraFile(extern_rules=[ExternRule(invalid_text)]),
            "ExternRule name must be a string",
        ),
        (
            YaraFile(extern_rules=[ExternRule("external_rule", namespace=invalid_text)]),
            "ExternRule namespace must be a string",
        ),
        (
            YaraFile(namespaces=[ExternNamespace(invalid_text)]),
            "ExternNamespace name must be a string",
        ),
    ]

    for ast, message in invalid_cases:
        with pytest.raises(SerializationError, match=message):
            serializer.serialize(ast)

    invalid_reference = ExternRuleReference(invalid_text)
    with pytest.raises(SerializationError, match="ExternRuleReference rule_name must be a string"):
        serializer.visit(invalid_reference)

    invalid_namespace = ExternRuleReference("external_rule", namespace=invalid_text)
    with pytest.raises(SerializationError, match="ExternRuleReference namespace must be a string"):
        serializer.visit(invalid_namespace)


def test_json_serializer_rejects_invalid_raw_string_sets() -> None:
    serializer = JsonSerializer(include_metadata=False)
    invalid_string_sets: list[Any] = [
        True,
        123,
        None,
        {},
        object(),
        [False],
        [123],
        [None],
        [{}],
        [object()],
    ]

    for string_set in invalid_string_sets:
        expressions = [
            ForOfExpression("any", string_set, None),
            OfExpression("any", string_set),
        ]
        for expression in expressions:
            ast = YaraFile(rules=[Rule(name="invalid_string_set", condition=expression)])
            with pytest.raises(SerializationError, match="string_set"):
                serializer.serialize(ast)


def test_json_serializer_rejects_invalid_optional_expression_fields() -> None:
    serializer = JsonSerializer(include_metadata=False)
    invalid_values: list[Any] = [False, 0, "", [], {}, object()]

    for invalid_value in invalid_values:
        expressions = [
            StringOffset("$a", invalid_value),
            StringLength("$a", invalid_value),
            ArrayComprehension(expression=invalid_value),
            ArrayComprehension(iterable=invalid_value),
            ArrayComprehension(condition=invalid_value),
            DictComprehension(key_expression=invalid_value),
            DictComprehension(value_expression=invalid_value),
            DictComprehension(iterable=invalid_value),
            DictComprehension(condition=invalid_value),
            SliceExpression(Identifier("items"), start=invalid_value),
            SliceExpression(Identifier("items"), stop=invalid_value),
            SliceExpression(Identifier("items"), step=invalid_value),
            PatternMatch(Identifier("subject"), [], default=invalid_value),
        ]
        for expression in expressions:
            ast = YaraFile(rules=[Rule(name="invalid_optional", condition=expression)])
            with pytest.raises(SerializationError, match="must be an AST expression"):
                serializer.serialize(ast)


def test_json_serializer_rejects_non_expression_optional_ast_nodes() -> None:
    serializer = JsonSerializer(include_metadata=False)
    invalid_node: Any = Import("pe")

    ast = YaraFile(rules=[Rule(name="invalid_condition", condition=invalid_node)])
    with pytest.raises(SerializationError, match="Rule condition must be an AST expression"):
        serializer.serialize(ast)

    expressions = [
        ForOfExpression("any", "them", invalid_node),
        StringOffset("$a", invalid_node),
        StringLength("$a", invalid_node),
        ArrayComprehension(expression=invalid_node),
        ArrayComprehension(iterable=invalid_node),
        ArrayComprehension(condition=invalid_node),
        DictComprehension(key_expression=invalid_node),
        DictComprehension(value_expression=invalid_node),
        DictComprehension(iterable=invalid_node),
        DictComprehension(condition=invalid_node),
        SliceExpression(Identifier("items"), start=invalid_node),
        SliceExpression(Identifier("items"), stop=invalid_node),
        SliceExpression(Identifier("items"), step=invalid_node),
        PatternMatch(Identifier("subject"), [], default=invalid_node),
    ]
    for expression in expressions:
        ast = YaraFile(rules=[Rule(name="invalid_optional", condition=expression)])
        with pytest.raises(SerializationError, match="must be an AST expression"):
            serializer.serialize(ast)


def test_json_deserializer_parses_legacy_hex_xor_modifier_values() -> None:
    payload = {
        "type": "YaraFile",
        "imports": [],
        "includes": [],
        "rules": [
            {
                "type": "Rule",
                "name": "hex_xor",
                "modifiers": [],
                "tags": [],
                "meta": [],
                "strings": [
                    {
                        "type": "PlainString",
                        "identifier": "$key",
                        "value": "abc",
                        "modifiers": [{"name": "xor", "value": "0xff"}],
                    },
                    {
                        "type": "PlainString",
                        "identifier": "$range",
                        "value": "abc",
                        "modifiers": [{"name": "xor", "value": "0x01-0xff"}],
                    },
                ],
                "condition": {"type": "BooleanLiteral", "value": True},
            }
        ],
    }

    restored = JsonSerializer(include_metadata=False).deserialize(json.dumps(payload))

    assert [string.modifiers[0].value for string in restored.rules[0].strings] == [
        255,
        (1, 255),
    ]


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
                name="expression_string_set",
                condition=OfExpression(
                    quantifier="any",
                    string_set=[StringIdentifier("$a"), "$b"],
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
    assert conditions[2]["string_set"] == [{"type": "StringIdentifier", "name": "$a"}, "$b"]
    assert conditions[3]["string_set"] == ["$a", "$b"]
    assert conditions[4]["string_set"] == ["$a", "$b"]
    assert conditions[5]["quantifier"] == {"type": "IntegerLiteral", "value": 2}

    restored = serializer.deserialize(json.dumps(serialized))
    raw_them = restored.rules[0].condition
    raw_list = restored.rules[1].condition
    expression_string_set = restored.rules[2].condition
    raw_tuple = restored.rules[3].condition
    raw_frozenset = restored.rules[4].condition
    expression_quantifier = restored.rules[5].condition

    assert isinstance(raw_them, ForOfExpression)
    assert raw_them.string_set == "them"
    assert isinstance(raw_list, OfExpression)
    assert raw_list.string_set == ["$a", "$b"]
    assert isinstance(expression_string_set, OfExpression)
    assert isinstance(expression_string_set.string_set, list)
    assert isinstance(expression_string_set.string_set[0], StringIdentifier)
    assert expression_string_set.string_set[0].name == "$a"
    assert expression_string_set.string_set[1] == "$b"
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
