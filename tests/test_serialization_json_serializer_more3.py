"""Additional tests for JSON serializer (no mocks)."""

from __future__ import annotations

import json
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
    ConditionalDirective,
    CustomPragma,
    DefineDirective,
    InRulePragma,
    Pragma,
    PragmaBlock,
    PragmaScope,
    PragmaType,
    UndefDirective,
)
from yaraast.ast.rules import Import, Include, Rule, Tag
from yaraast.ast.strings import (
    HexAlternative,
    HexByte,
    HexJump,
    HexNegatedByte,
    HexNibble,
    HexString,
    PlainString,
    RegexString,
    StringDefinition,
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
            HexString(
                identifier="$c",
                tokens=[HexByte(0x41), HexJump(min_jump=1, max_jump=2), HexByte(0x42)],
            ),
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

    true_expr = BooleanLiteral(True)
    string_set = SetExpression([StringIdentifier("$a")])
    blank_quantifier_expressions: list[Any] = [
        ForExpression("any", "i", string_set, true_expr),
        ForOfExpression("any", ["$a"], true_expr),
        OfExpression("any", ["$a"]),
    ]
    for expression in blank_quantifier_expressions:
        cast(Any, expression).quantifier = "   "
        ast = YaraFile(rules=[Rule(name="blank_quantifier", condition=expression)])
        with pytest.raises(SerializationError, match="quantifier must not be empty"):
            serializer.serialize(ast)


def test_json_serializer_rejects_invalid_yara_file_node_lists() -> None:
    serializer = JsonSerializer(include_metadata=False)
    field_names = (
        "imports",
        "includes",
        "rules",
        "extern_rules",
        "extern_imports",
        "pragmas",
        "namespaces",
    )

    for field_name in field_names:
        ast = YaraFile()
        setattr(ast, field_name, False)
        with pytest.raises(
            SerializationError,
            match=f"YaraFile {field_name} must be a list",
        ):
            serializer.serialize(ast)

        ast = YaraFile()
        setattr(ast, field_name, [object()])
        with pytest.raises(
            SerializationError,
            match=f"YaraFile {field_name} item must be",
        ):
            serializer.serialize(ast)


def test_json_serializer_rejects_invalid_rule_lists() -> None:
    serializer = JsonSerializer(include_metadata=False)
    field_names = ("modifiers", "tags", "meta", "strings", "pragmas")

    for field_name in field_names:
        rule = Rule("invalid_rule", condition=BooleanLiteral(True))
        setattr(rule, field_name, False)
        ast = YaraFile(rules=[rule])
        with pytest.raises(
            SerializationError,
            match=f"Rule {field_name} must be a list",
        ):
            serializer.serialize(ast)

        rule = Rule("invalid_rule", condition=BooleanLiteral(True))
        setattr(rule, field_name, [object()])
        ast = YaraFile(rules=[rule])
        with pytest.raises(
            SerializationError,
            match=f"Rule {field_name} item must be",
        ):
            serializer.serialize(ast)

    rule = Rule("invalid_rule", condition=BooleanLiteral(True))
    cast(Any, rule).modifiers = [""]
    with pytest.raises(
        SerializationError,
        match="Rule modifiers must contain non-empty strings",
    ):
        serializer.serialize(YaraFile(rules=[rule]))

    rule = Rule("invalid_rule", modifiers=["bad modifier"], condition=BooleanLiteral(True))
    with pytest.raises(SerializationError, match="Invalid rule modifier identifier"):
        serializer.serialize(YaraFile(rules=[rule]))

    rule = Rule(
        "invalid_rule",
        modifiers=[RuleModifier(cast(Any, object()))],
        condition=BooleanLiteral(True),
    )
    with pytest.raises(SerializationError, match="Rule modifier name must be a string"):
        serializer.serialize(YaraFile(rules=[rule]))


def test_json_serializer_rejects_invalid_string_definition_lists() -> None:
    serializer = JsonSerializer(include_metadata=False)
    string_definitions = [
        PlainString(identifier="$a", value="a"),
        HexString(identifier="$h", tokens=[HexByte(0x41)]),
        RegexString(identifier="$r", regex="r"),
    ]

    for string_definition in string_definitions:
        context = type(string_definition).__name__
        cast(Any, string_definition).modifiers = False
        ast = YaraFile(
            rules=[
                Rule(
                    name="invalid_string_lists",
                    strings=[string_definition],
                    condition=BooleanLiteral(True),
                )
            ]
        )
        with pytest.raises(
            SerializationError,
            match=f"{context} modifiers must be a list",
        ):
            serializer.serialize(ast)

        cast(Any, string_definition).modifiers = [object()]
        with pytest.raises(
            SerializationError,
            match=f"{context} modifiers item must be",
        ):
            serializer.serialize(ast)

        cast(Any, string_definition).modifiers = [""]
        with pytest.raises(
            SerializationError,
            match="StringModifier name must not be empty",
        ):
            serializer.serialize(ast)

    hex_string = HexString(identifier="$h", tokens=[HexByte(0x41)])
    cast(Any, hex_string).tokens = False
    ast = YaraFile(
        rules=[
            Rule(
                name="invalid_hex_tokens",
                strings=[hex_string],
                condition=BooleanLiteral(True),
            )
        ]
    )
    with pytest.raises(SerializationError, match="HexString tokens must be a list"):
        serializer.serialize(ast)

    cast(Any, hex_string).tokens = [object()]
    with pytest.raises(SerializationError, match="HexString tokens item must be"):
        serializer.serialize(ast)

    cast(Any, hex_string).tokens = []
    with pytest.raises(SerializationError, match="HexString must contain at least one token"):
        serializer.serialize(ast)


def test_json_serializer_rejects_non_finite_numbers() -> None:
    serializer = JsonSerializer(include_metadata=False)
    invalid_numbers = [float("nan"), float("inf"), float("-inf")]

    for invalid_number in invalid_numbers:
        ast = YaraFile(rules=[Rule(name="invalid_double", condition=DoubleLiteral(invalid_number))])
        with pytest.raises(SerializationError, match="DoubleLiteral value must be finite"):
            serializer.serialize(ast)

        expressions = [
            ForExpression(
                invalid_number,
                "i",
                Identifier("items"),
                BooleanLiteral(True),
            ),
            ForOfExpression(invalid_number, "them", None),
            OfExpression(invalid_number, "them"),
        ]
        for expression in expressions:
            ast = YaraFile(rules=[Rule(name="invalid_quantifier_number", condition=expression)])
            with pytest.raises(SerializationError, match="quantifier must be finite"):
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


def test_json_serializer_rejects_invalid_expression_container_fields() -> None:
    serializer = JsonSerializer(include_metadata=False)

    with_bad_declarations = WithStatement(
        [WithDeclaration("x", IntegerLiteral(1))],
        BooleanLiteral(True),
    )
    cast(Any, with_bad_declarations).declarations = False

    with_bad_declaration_item = WithStatement(
        [WithDeclaration("x", IntegerLiteral(1))],
        BooleanLiteral(True),
    )
    cast(Any, with_bad_declaration_item).declarations = [object()]

    dict_with_bad_items = DictExpression([DictItem(StringLiteral("k"), IntegerLiteral(1))])
    cast(Any, dict_with_bad_items).items = False

    dict_with_bad_item = DictExpression([DictItem(StringLiteral("k"), IntegerLiteral(1))])
    cast(Any, dict_with_bad_item).items = [object()]

    match_with_bad_cases = PatternMatch(
        Identifier("subject"),
        [MatchCase(StringLiteral("p"), BooleanLiteral(True))],
    )
    cast(Any, match_with_bad_cases).cases = False

    match_with_bad_case = PatternMatch(
        Identifier("subject"),
        [MatchCase(StringLiteral("p"), BooleanLiteral(True))],
    )
    cast(Any, match_with_bad_case).cases = [object()]

    invalid_cases = [
        (with_bad_declarations, "WithStatement declarations must be a list"),
        (with_bad_declaration_item, "WithStatement declarations item must be"),
        (dict_with_bad_items, "DictExpression items must be a list"),
        (dict_with_bad_item, "DictExpression items item must be"),
        (match_with_bad_cases, "PatternMatch cases must be a list"),
        (match_with_bad_case, "PatternMatch cases item must be"),
    ]

    for expression, message in invalid_cases:
        ast = YaraFile(rules=[Rule(name="invalid_container", condition=expression)])
        with pytest.raises(SerializationError, match=message):
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
        (Identifier(""), "Identifier name must not be empty"),
        (Identifier(invalid_list), "Identifier name must be a string"),
        (StringIdentifier(""), "StringIdentifier name must not be empty"),
        (StringIdentifier(invalid_text), "StringIdentifier name must be a string"),
        (StringIdentifier("$bad-name"), "Invalid string reference"),
        (StringIdentifier("$a*"), "Invalid string reference"),
        (StringWildcard(""), "StringWildcard pattern must not be empty"),
        (StringWildcard(invalid_text), "StringWildcard pattern must be a string"),
        (StringWildcard("$bad-name*"), "Invalid string reference"),
        (StringCount(""), "StringCount string_id must not be empty"),
        (StringCount(invalid_text), "StringCount string_id must be a string"),
        (StringCount("#a"), "Invalid string reference"),
        (StringCount("$bad-name"), "Invalid string reference"),
        (StringOffset(""), "StringOffset string_id must not be empty"),
        (StringOffset(invalid_text), "StringOffset string_id must be a string"),
        (StringOffset("@a"), "Invalid string reference"),
        (StringOffset("$bad-name"), "Invalid string reference"),
        (StringLength(""), "StringLength string_id must not be empty"),
        (StringLength(invalid_text), "StringLength string_id must be a string"),
        (StringLength("!a"), "Invalid string reference"),
        (StringLength("$bad-name"), "Invalid string reference"),
        (IntegerLiteral(True), "IntegerLiteral value must be an integer"),
        (IntegerLiteral(invalid_integer), "IntegerLiteral value must be an integer"),
        (DoubleLiteral(invalid_number), "DoubleLiteral value must be numeric"),
        (StringLiteral(invalid_string), "StringLiteral value must be a string"),
        (RegexLiteral(invalid_text), "RegexLiteral pattern must be a string"),
        (RegexLiteral(""), "RegexLiteral pattern must not be empty"),
        (RegexLiteral("abc", invalid_regex_modifiers), "RegexLiteral modifiers must be a string"),
        (BooleanLiteral(invalid_bool), "BooleanLiteral value must be a boolean"),
        (ModuleReference(""), "ModuleReference module must not be empty"),
        (ModuleReference(invalid_list), "ModuleReference module must be a string"),
        (AtExpression("", IntegerLiteral(0)), "AtExpression string_id must not be empty"),
        (AtExpression(invalid_text, IntegerLiteral(0)), "AtExpression string_id must be a string"),
        (AtExpression("@a", IntegerLiteral(0)), "Invalid string reference"),
        (AtExpression("$bad-name", IntegerLiteral(0)), "Invalid string reference"),
        (
            InExpression("@a", RangeExpression(IntegerLiteral(0), IntegerLiteral(1))),
            "Invalid string reference",
        ),
        (
            InExpression("$bad-name", RangeExpression(IntegerLiteral(0), IntegerLiteral(1))),
            "Invalid string reference",
        ),
    ]

    for expression, message in invalid_cases:
        ast = YaraFile(rules=[Rule(name="invalid_leaf", condition=expression)])
        with pytest.raises(SerializationError, match=message):
            serializer.serialize(ast)


def test_json_serializer_accepts_placeholder_string_references() -> None:
    serializer = JsonSerializer(include_metadata=False)
    ast = YaraFile(
        rules=[
            Rule(name="count_placeholder", condition=StringCount("$")),
            Rule(name="offset_placeholder", condition=StringOffset("$", IntegerLiteral(0))),
            Rule(name="length_placeholder", condition=StringLength("$", IntegerLiteral(0))),
        ]
    )

    payload = json.loads(serializer.serialize(ast))

    conditions = [rule["condition"] for rule in payload["ast"]["rules"]]
    assert [condition["string_id"] for condition in conditions] == ["$", "$", "$"]


def test_json_serializer_rejects_invalid_declaration_string_fields() -> None:
    serializer = JsonSerializer(include_metadata=False)
    invalid_text: Any = 123

    invalid_cases: list[tuple[YaraFile, str]] = [
        (
            YaraFile(imports=[Import(module=invalid_text)]),
            "Import module must be a string",
        ),
        (
            YaraFile(imports=[Import(module="")]),
            "Import module must not be empty",
        ),
        (
            YaraFile(imports=[Import(module="   ")]),
            "Import module must not be empty",
        ),
        (
            YaraFile(imports=[Import(module="pe", alias=invalid_text)]),
            "Import alias must be a string",
        ),
        (
            YaraFile(imports=[Import(module="pe", alias="")]),
            "Import alias must not be empty",
        ),
        (
            YaraFile(imports=[Import(module="pe", alias="\t")]),
            "Import alias must not be empty",
        ),
        (
            YaraFile(includes=[Include(path=invalid_text)]),
            "Include path must be a string",
        ),
        (
            YaraFile(includes=[Include(path="")]),
            "Include path must not be empty",
        ),
        (
            YaraFile(includes=[Include(path="   ")]),
            "Include path must not be empty",
        ),
        (
            YaraFile(rules=[Rule(name=invalid_text, condition=BooleanLiteral(True))]),
            "Rule name must be a string",
        ),
        (
            YaraFile(rules=[Rule(name="", condition=BooleanLiteral(True))]),
            "Rule name must not be empty",
        ),
        (
            YaraFile(rules=[Rule(name="   ", condition=BooleanLiteral(True))]),
            "Rule name must not be empty",
        ),
        (
            YaraFile(rules=[Rule(name="bad-name", condition=BooleanLiteral(True))]),
            "Invalid rule identifier",
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
                        name="empty_tag",
                        tags=[Tag(name="")],
                        condition=BooleanLiteral(True),
                    )
                ]
            ),
            "Tag name must not be empty",
        ),
        (
            YaraFile(
                rules=[
                    Rule(
                        name="invalid_tag",
                        tags=[Tag(name="bad-name")],
                        condition=BooleanLiteral(True),
                    )
                ]
            ),
            "Invalid tag identifier",
        ),
        (
            YaraFile(
                rules=[
                    Rule(
                        name="empty_tag",
                        tags=[Tag(name="   ")],
                        condition=BooleanLiteral(True),
                    )
                ]
            ),
            "Tag name must not be empty",
        ),
        (
            YaraFile(
                rules=[
                    Rule(
                        name="empty_meta",
                        meta=[Meta("", "x")],
                        condition=BooleanLiteral(True),
                    )
                ]
            ),
            "Meta key must not be empty",
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
                        name="empty_plain_identifier",
                        strings=[PlainString(identifier="", value="x")],
                        condition=BooleanLiteral(True),
                    )
                ]
            ),
            "PlainString identifier must not be empty",
        ),
        (
            YaraFile(
                rules=[
                    Rule(
                        name="empty_plain_identifier",
                        strings=[PlainString(identifier="\t", value="x")],
                        condition=BooleanLiteral(True),
                    )
                ]
            ),
            "PlainString identifier must not be empty",
        ),
        (
            YaraFile(
                rules=[
                    Rule(
                        name="empty_string_definition_identifier",
                        strings=[StringDefinition(identifier="")],
                        condition=BooleanLiteral(True),
                    )
                ]
            ),
            "StringDefinition identifier must not be empty",
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
                        name="empty_hex_identifier",
                        strings=[HexString(identifier="", tokens=[])],
                        condition=BooleanLiteral(True),
                    )
                ]
            ),
            "HexString identifier must not be empty",
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
                        name="empty_regex_identifier",
                        strings=[RegexString(identifier="", regex="x")],
                        condition=BooleanLiteral(True),
                    )
                ]
            ),
            "RegexString identifier must not be empty",
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
        (
            YaraFile(
                rules=[
                    Rule(
                        name="empty_regex_value",
                        strings=[RegexString(identifier="$a", regex="")],
                        condition=BooleanLiteral(True),
                    )
                ]
            ),
            "RegexString regex must not be empty",
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
            BinaryExpression(BooleanLiteral(True), "", BooleanLiteral(False)),
            "BinaryExpression operator must not be empty",
        ),
        (
            BinaryExpression(BooleanLiteral(True), invalid_text, BooleanLiteral(False)),
            "BinaryExpression operator must be a string",
        ),
        (
            UnaryExpression("", BooleanLiteral(True)),
            "UnaryExpression operator must not be empty",
        ),
        (
            UnaryExpression(invalid_text, BooleanLiteral(True)),
            "UnaryExpression operator must be a string",
        ),
        (
            FunctionCall("", []),
            "FunctionCall function must not be empty",
        ),
        (
            FunctionCall(invalid_text, []),
            "FunctionCall function must be a string",
        ),
        (
            MemberAccess(Identifier("pe"), ""),
            "MemberAccess member must not be empty",
        ),
        (
            MemberAccess(Identifier("pe"), invalid_text),
            "MemberAccess member must be a string",
        ),
        (
            ForExpression("any", "", Identifier("items"), BooleanLiteral(True)),
            "ForExpression variable must not be empty",
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
            StringOperatorExpression(StringLiteral("a"), "", StringLiteral("b")),
            "StringOperatorExpression operator must not be empty",
        ),
        (
            WithStatement([WithDeclaration("", IntegerLiteral(1))], BooleanLiteral(True)),
            "WithDeclaration identifier must not be empty",
        ),
        (
            WithStatement(
                [WithDeclaration(invalid_text, IntegerLiteral(1))],
                BooleanLiteral(True),
            ),
            "WithDeclaration identifier must be a string",
        ),
        (
            ArrayComprehension(variable=""),
            "ArrayComprehension variable must not be empty",
        ),
        (
            ArrayComprehension(variable=invalid_text),
            "ArrayComprehension variable must be a string",
        ),
        (
            DictComprehension(key_variable=""),
            "DictComprehension key_variable must not be empty",
        ),
        (
            DictComprehension(key_variable=invalid_text),
            "DictComprehension key_variable must be a string",
        ),
        (
            DictComprehension(key_variable="k", value_variable=""),
            "DictComprehension value_variable must not be empty",
        ),
        (
            DictComprehension(key_variable="k", value_variable=invalid_text),
            "DictComprehension value_variable must be a string",
        ),
        (
            LambdaExpression([""], BooleanLiteral(True)),
            "LambdaExpression parameters must contain non-empty strings",
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


@pytest.mark.parametrize(
    ("condition", "message"),
    [
        (
            ForExpression("any", "bad-name", Identifier("items"), BooleanLiteral(True)),
            "Invalid local variable identifier: bad-name",
        ),
        (
            WithStatement([WithDeclaration("bad-name", IntegerLiteral(1))], BooleanLiteral(True)),
            "Invalid local variable identifier: bad-name",
        ),
        (
            ArrayComprehension(variable="1bad"),
            "Invalid local variable identifier: 1bad",
        ),
        (
            DictComprehension(key_variable="for"),
            "Invalid local variable identifier: for",
        ),
        (
            DictComprehension(key_variable="k", value_variable="bad-name"),
            "Invalid local variable identifier: bad-name",
        ),
        (
            LambdaExpression(["1bad"], BooleanLiteral(True)),
            "Invalid local variable identifier: 1bad",
        ),
    ],
)
def test_json_serializer_rejects_invalid_local_identifier_fields(
    condition: Any,
    message: str,
) -> None:
    serializer = JsonSerializer(include_metadata=False)
    ast = YaraFile(rules=[Rule(name="invalid_local_identifier", condition=condition)])

    with pytest.raises(SerializationError, match=message):
        serializer.serialize(ast)


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        (
            {
                "type": "ForExpression",
                "quantifier": "any",
                "variable": "bad-name",
                "iterable": {"type": "Identifier", "name": "items"},
                "body": {"type": "BooleanLiteral", "value": True},
            },
            "Invalid local variable identifier: bad-name",
        ),
        (
            {
                "type": "WithStatement",
                "declarations": [
                    {
                        "type": "WithDeclaration",
                        "identifier": "bad-name",
                        "value": {"type": "IntegerLiteral", "value": 1},
                    }
                ],
                "body": {"type": "BooleanLiteral", "value": True},
            },
            "Invalid local variable identifier: bad-name",
        ),
        (
            {
                "type": "ArrayComprehension",
                "expression": {"type": "Identifier", "name": "x"},
                "variable": "1bad",
                "iterable": {"type": "Identifier", "name": "xs"},
                "condition": None,
            },
            "Invalid local variable identifier: 1bad",
        ),
        (
            {
                "type": "DictComprehension",
                "key_expression": {"type": "Identifier", "name": "k"},
                "value_expression": {"type": "Identifier", "name": "v"},
                "key_variable": "for",
                "value_variable": None,
                "iterable": {"type": "Identifier", "name": "xs"},
                "condition": None,
            },
            "Invalid local variable identifier: for",
        ),
        (
            {
                "type": "DictComprehension",
                "key_expression": {"type": "Identifier", "name": "k"},
                "value_expression": {"type": "Identifier", "name": "v"},
                "key_variable": "k",
                "value_variable": "bad-name",
                "iterable": {"type": "Identifier", "name": "xs"},
                "condition": None,
            },
            "Invalid local variable identifier: bad-name",
        ),
        (
            {
                "type": "LambdaExpression",
                "parameters": ["1bad"],
                "body": {"type": "BooleanLiteral", "value": True},
            },
            "Invalid local variable identifier: 1bad",
        ),
    ],
)
def test_json_deserializer_rejects_invalid_local_identifier_fields(
    payload: dict[str, Any],
    message: str,
) -> None:
    serializer = JsonSerializer(include_metadata=False)
    ast_payload = {
        "ast": {
            "type": "YaraFile",
            "imports": [],
            "includes": [],
            "rules": [
                {
                    "type": "Rule",
                    "name": "invalid_local_identifier",
                    "modifiers": [],
                    "tags": [],
                    "meta": [],
                    "strings": [],
                    "condition": payload,
                    "pragmas": [],
                }
            ],
            "extern_rules": [],
            "extern_imports": [],
            "pragmas": [],
            "namespaces": [],
        }
    }

    with pytest.raises(SerializationError, match=message):
        serializer.deserialize(json.dumps(ast_payload))


def test_json_serializer_rejects_invalid_extern_scalar_fields() -> None:
    serializer = JsonSerializer(include_metadata=False)
    invalid_text: Any = 123
    invalid_rules: Any = ["rule_a", 123]
    invalid_extern_rule_modifier_list = ExternRule("external_rule")
    cast(Any, invalid_extern_rule_modifier_list).modifiers = False
    invalid_extern_rule_modifier_item = ExternRule("external_rule")
    cast(Any, invalid_extern_rule_modifier_item).modifiers = [object()]
    invalid_namespace_rules_list = ExternNamespace("external")
    cast(Any, invalid_namespace_rules_list).extern_rules = False
    invalid_namespace_rules_item = ExternNamespace("external")
    cast(Any, invalid_namespace_rules_item).extern_rules = [object()]

    invalid_cases: list[tuple[YaraFile, str]] = [
        (
            YaraFile(extern_imports=[ExternImport("")]),
            "ExternImport module_path must not be empty",
        ),
        (
            YaraFile(extern_imports=[ExternImport("   ")]),
            "ExternImport module_path must not be empty",
        ),
        (
            YaraFile(extern_imports=[ExternImport(invalid_text)]),
            "ExternImport module_path must be a string",
        ),
        (
            YaraFile(extern_imports=[ExternImport("external", alias="")]),
            "ExternImport alias must not be empty",
        ),
        (
            YaraFile(extern_imports=[ExternImport("external", alias="   ")]),
            "ExternImport alias must not be empty",
        ),
        (
            YaraFile(extern_imports=[ExternImport("external", alias=invalid_text)]),
            "ExternImport alias must be a string",
        ),
        (
            YaraFile(extern_imports=[ExternImport("external", rules=[""])]),
            "ExternImport rules must contain non-empty strings",
        ),
        (
            YaraFile(extern_imports=[ExternImport("external", rules=["   "])]),
            "ExternImport rules must contain non-empty strings",
        ),
        (
            YaraFile(extern_imports=[ExternImport("external", rules=invalid_rules)]),
            "ExternImport rules must be a list of strings",
        ),
        (
            YaraFile(extern_rules=[ExternRule("")]),
            "ExternRule name must not be empty",
        ),
        (
            YaraFile(extern_rules=[ExternRule(invalid_text)]),
            "ExternRule name must be a string",
        ),
        (
            YaraFile(extern_rules=[ExternRule("external_rule", namespace="")]),
            "ExternRule namespace must not be empty",
        ),
        (
            YaraFile(extern_rules=[ExternRule("external_rule", namespace=invalid_text)]),
            "ExternRule namespace must be a string",
        ),
        (
            YaraFile(extern_rules=[invalid_extern_rule_modifier_list]),
            "ExternRule modifiers must be a list",
        ),
        (
            YaraFile(extern_rules=[invalid_extern_rule_modifier_item]),
            "ExternRule modifiers item must be",
        ),
        (
            YaraFile(extern_rules=[ExternRule("external_rule", modifiers=cast(Any, [""]))]),
            "ExternRule modifiers must contain non-empty strings",
        ),
        (
            YaraFile(namespaces=[ExternNamespace(invalid_text)]),
            "ExternNamespace name must be a string",
        ),
        (
            YaraFile(namespaces=[ExternNamespace("")]),
            "ExternNamespace name must not be empty",
        ),
        (
            YaraFile(namespaces=[invalid_namespace_rules_list]),
            "ExternNamespace extern_rules must be a list",
        ),
        (
            YaraFile(namespaces=[invalid_namespace_rules_item]),
            "ExternNamespace extern_rules item must be",
        ),
    ]

    for ast, message in invalid_cases:
        with pytest.raises(SerializationError, match=message):
            serializer.serialize(ast)

    invalid_reference = ExternRuleReference(invalid_text)
    with pytest.raises(SerializationError, match="ExternRuleReference rule_name must be a string"):
        serializer.visit(invalid_reference)

    empty_reference = ExternRuleReference("")
    with pytest.raises(SerializationError, match="ExternRuleReference rule_name must not be empty"):
        serializer.visit(empty_reference)

    invalid_namespace = ExternRuleReference("external_rule", namespace=invalid_text)
    with pytest.raises(SerializationError, match="ExternRuleReference namespace must be a string"):
        serializer.visit(invalid_namespace)

    empty_namespace = ExternRuleReference("external_rule", namespace="")
    with pytest.raises(SerializationError, match="ExternRuleReference namespace must not be empty"):
        serializer.visit(empty_namespace)


def test_json_serializer_rejects_invalid_pragma_meta_comment_fields() -> None:
    serializer = JsonSerializer(include_metadata=False)
    invalid_text: Any = 123
    invalid_bool: Any = "true"
    invalid_float: Any = 1.2
    invalid_arguments: Any = ["a", 123]
    invalid_parameters: Any = [("key", "value")]
    invalid_parameter_key: Any = {1: "value"}
    invalid_parameter_value: Any = {"nested": "value"}
    nonfinite_parameter_value = float("nan")

    pragma_with_bad_type = Pragma(PragmaType.CUSTOM, "custom")
    cast(Any, pragma_with_bad_type).pragma_type = invalid_text
    pragma_with_empty_type = Pragma(PragmaType.CUSTOM, "custom")
    cast(Any, pragma_with_empty_type).pragma_type = ""
    pragma_with_bad_scope = Pragma(PragmaType.CUSTOM, "custom")
    cast(Any, pragma_with_bad_scope).scope = invalid_text
    pragma_with_unknown_scope = Pragma(PragmaType.CUSTOM, "custom")
    cast(Any, pragma_with_unknown_scope).scope = "secret"
    define_with_bad_macro_name = DefineDirective("GOOD")
    define_with_bad_macro_name.macro_name = invalid_text
    define_with_bad_macro_value = DefineDirective("GOOD", "1")
    define_with_bad_macro_value.macro_value = invalid_text
    conditional_with_bad_condition = ConditionalDirective(PragmaType.IFDEF, "GOOD")
    conditional_with_bad_condition.condition = invalid_text

    invalid_cases: list[tuple[YaraFile, str]] = [
        (
            YaraFile(pragmas=[Pragma(PragmaType.CUSTOM, invalid_text)]),
            "Pragma name must be a string",
        ),
        (
            YaraFile(pragmas=[Pragma(PragmaType.CUSTOM, "")]),
            "Pragma name must not be empty",
        ),
        (
            YaraFile(pragmas=[pragma_with_bad_type]),
            "Pragma pragma_type must be a string",
        ),
        (
            YaraFile(pragmas=[pragma_with_empty_type]),
            "Pragma pragma_type must not be empty",
        ),
        (
            YaraFile(pragmas=[pragma_with_bad_scope]),
            "Pragma scope must be a string",
        ),
        (
            YaraFile(pragmas=[pragma_with_unknown_scope]),
            "Pragma scope must be a valid pragma scope",
        ),
        (
            YaraFile(pragmas=[Pragma(PragmaType.CUSTOM, "custom", invalid_arguments)]),
            "Pragma arguments must be a list of strings",
        ),
        (
            YaraFile(pragmas=[CustomPragma("custom", parameters=invalid_parameters)]),
            "Pragma parameters must be a dictionary",
        ),
        (
            YaraFile(pragmas=[CustomPragma("custom", parameters=invalid_parameter_key)]),
            "Pragma parameters keys must be strings",
        ),
        (
            YaraFile(
                pragmas=[CustomPragma("custom", parameters={"config": invalid_parameter_value})]
            ),
            "Pragma parameter value must be a string, integer, boolean, or finite float",
        ),
        (
            YaraFile(
                pragmas=[CustomPragma("custom", parameters={"score": nonfinite_parameter_value})]
            ),
            "Pragma parameter value must be a string, integer, boolean, or finite float",
        ),
        (
            YaraFile(pragmas=[define_with_bad_macro_name]),
            "Pragma macro_name must be a string",
        ),
        (
            YaraFile(pragmas=[DefineDirective("")]),
            "Pragma macro_name must not be empty",
        ),
        (
            YaraFile(pragmas=[UndefDirective("")]),
            "Pragma macro_name must not be empty",
        ),
        (
            YaraFile(pragmas=[define_with_bad_macro_value]),
            "Pragma macro_value must be a string",
        ),
        (
            YaraFile(pragmas=[conditional_with_bad_condition]),
            "Pragma condition must be a string",
        ),
        (
            YaraFile(pragmas=[ConditionalDirective(PragmaType.IFDEF, "")]),
            "Pragma condition must not be empty",
        ),
        (
            YaraFile(pragmas=[ConditionalDirective(PragmaType.IFDEF)]),
            "Pragma condition must be a string",
        ),
        (
            YaraFile(
                rules=[
                    Rule(
                        "invalid_in_rule_pragma",
                        pragmas=[
                            InRulePragma(
                                Pragma(PragmaType.CUSTOM, "custom"),
                                invalid_text,
                            )
                        ],
                        condition=BooleanLiteral(True),
                    )
                ]
            ),
            "InRulePragma position must be a string",
        ),
        (
            YaraFile(
                rules=[
                    Rule(
                        "empty_in_rule_pragma",
                        pragmas=[InRulePragma(Pragma(PragmaType.CUSTOM, "custom"), "")],
                        condition=BooleanLiteral(True),
                    )
                ]
            ),
            "InRulePragma position must not be empty",
        ),
        (
            YaraFile(
                rules=[
                    Rule(
                        "invalid_meta_key",
                        meta=[MetaEntry(invalid_text, "value")],
                        condition=BooleanLiteral(True),
                    )
                ]
            ),
            "Meta key must be a string",
        ),
        (
            YaraFile(
                rules=[
                    Rule(
                        "invalid_meta_value",
                        meta=[Meta("key", invalid_float)],
                        condition=BooleanLiteral(True),
                    )
                ]
            ),
            "Meta value must be a string, integer, or boolean",
        ),
    ]

    rule_with_bad_comment_text = Rule("invalid_comment_text", condition=BooleanLiteral(True))
    rule_with_bad_comment_text.leading_comments.append(Comment(invalid_text))
    invalid_cases.append(
        (
            YaraFile(rules=[rule_with_bad_comment_text]),
            "Comment text must be a string",
        )
    )

    rule_with_bad_comment_flag = Rule("invalid_comment_flag", condition=BooleanLiteral(True))
    rule_with_bad_comment_flag.leading_comments.append(
        Comment("comment", is_multiline=invalid_bool)
    )
    invalid_cases.append(
        (
            YaraFile(rules=[rule_with_bad_comment_flag]),
            "Comment is_multiline must be a boolean",
        )
    )

    for ast, message in invalid_cases:
        with pytest.raises(SerializationError, match=message):
            serializer.serialize(ast)

    block_with_bad_pragmas = PragmaBlock([Pragma(PragmaType.CUSTOM, "custom")])
    cast(Any, block_with_bad_pragmas).pragmas = False
    with pytest.raises(SerializationError, match="PragmaBlock pragmas must be a list"):
        serializer.visit(block_with_bad_pragmas)

    block_with_bad_pragma_item = PragmaBlock([Pragma(PragmaType.CUSTOM, "custom")])
    cast(Any, block_with_bad_pragma_item).pragmas = [object()]
    with pytest.raises(SerializationError, match="PragmaBlock pragmas item must be"):
        serializer.visit(block_with_bad_pragma_item)

    block_with_bad_scope = PragmaBlock([Pragma(PragmaType.CUSTOM, "custom")])
    cast(Any, block_with_bad_scope).scope = invalid_text
    with pytest.raises(SerializationError, match="PragmaBlock scope must be a string"):
        serializer.visit(block_with_bad_scope)

    block_with_unknown_scope = PragmaBlock([Pragma(PragmaType.CUSTOM, "custom")])
    cast(Any, block_with_unknown_scope).scope = "secret"
    with pytest.raises(SerializationError, match="PragmaBlock scope must be a valid pragma scope"):
        serializer.visit(block_with_unknown_scope)

    group_with_bad_comments = CommentGroup([Comment("comment")])
    cast(Any, group_with_bad_comments).comments = False
    with pytest.raises(SerializationError, match="CommentGroup comments must be a list"):
        serializer.visit(group_with_bad_comments)

    group_with_bad_comment_item = CommentGroup([Comment("comment")])
    cast(Any, group_with_bad_comment_item).comments = [object()]
    with pytest.raises(SerializationError, match="CommentGroup comments item must be"):
        serializer.visit(group_with_bad_comment_item)

    rule_with_bad_leading_comments = Rule(
        "invalid_leading_comments",
        condition=BooleanLiteral(True),
    )
    cast(Any, rule_with_bad_leading_comments).leading_comments = True
    with pytest.raises(SerializationError, match="leading_comments must be a list"):
        serializer.serialize(YaraFile(rules=[rule_with_bad_leading_comments]))

    rule_with_bad_leading_comment_item = Rule(
        "invalid_leading_comment_item",
        condition=BooleanLiteral(True),
    )
    cast(Any, rule_with_bad_leading_comment_item).leading_comments = [object()]
    with pytest.raises(SerializationError, match="leading_comments item must be"):
        serializer.serialize(YaraFile(rules=[rule_with_bad_leading_comment_item]))

    rule_with_bad_trailing_comment = Rule(
        "invalid_trailing_comment",
        condition=BooleanLiteral(True),
    )
    cast(Any, rule_with_bad_trailing_comment).trailing_comment = object()
    with pytest.raises(SerializationError, match="trailing_comment must be"):
        serializer.serialize(YaraFile(rules=[rule_with_bad_trailing_comment]))

    meta_entry_with_bad_scope = MetaEntry("key", "value")
    cast(Any, meta_entry_with_bad_scope).scope = invalid_text
    with pytest.raises(SerializationError, match="Meta scope must be a string"):
        serializer.serialize(
            YaraFile(
                rules=[
                    Rule(
                        "invalid_meta_scope",
                        meta=[meta_entry_with_bad_scope],
                        condition=BooleanLiteral(True),
                    )
                ]
            )
        )

    meta_entry_with_unknown_scope = MetaEntry("key", "value")
    cast(Any, meta_entry_with_unknown_scope).scope = "secret"
    with pytest.raises(
        SerializationError, match="Meta scope must be public, private, or protected"
    ):
        serializer.serialize(
            YaraFile(
                rules=[
                    Rule(
                        "unknown_meta_scope",
                        meta=[meta_entry_with_unknown_scope],
                        condition=BooleanLiteral(True),
                    )
                ]
            )
        )

    meta_with_bad_scope = Meta("key", "value")
    cast(Any, meta_with_bad_scope).scope = invalid_text
    with pytest.raises(SerializationError, match="Meta scope must be a string"):
        serializer.visit(meta_with_bad_scope)


def test_json_serializer_rejects_invalid_hex_and_modifier_fields() -> None:
    serializer = JsonSerializer(include_metadata=False)
    invalid_text: Any = 123
    invalid_bool: Any = "true"
    invalid_byte: Any = 999
    invalid_nibble: Any = 99
    invalid_jump: Any = -1

    invalid_modifier = StringModifier.from_name_value("ascii")
    invalid_modifier.modifier_type = invalid_text
    invalid_modifier_value = StringModifier.from_name_value("base64", "alphabet")
    cast(Any, invalid_modifier_value).value = object()
    invalid_modifier_tuple = StringModifier.from_name_value("xor", (1, 3))
    cast(Any, invalid_modifier_tuple).value = (1, object())
    invalid_modifier_float = StringModifier.from_name_value("xor", 1)
    cast(Any, invalid_modifier_float).value = float("nan")
    invalid_hex_alternatives = HexAlternative([[HexByte(0x90)]])
    cast(Any, invalid_hex_alternatives).alternatives = False
    empty_hex_alternatives = HexAlternative([])
    empty_hex_alternative_branch = HexAlternative([[]])
    invalid_hex_alternative_token = HexAlternative([[object()]])

    invalid_cases: list[tuple[YaraFile, str]] = [
        (
            YaraFile(
                rules=[
                    Rule(
                        "invalid_modifier",
                        strings=[
                            PlainString(
                                identifier="$a",
                                value="x",
                                modifiers=[invalid_modifier],
                            )
                        ],
                        condition=BooleanLiteral(True),
                    )
                ]
            ),
            "StringModifier name must be a string",
        ),
        (
            YaraFile(
                rules=[
                    Rule(
                        "invalid_modifier_value",
                        strings=[
                            PlainString(
                                identifier="$a",
                                value="x",
                                modifiers=[invalid_modifier_value],
                            )
                        ],
                        condition=BooleanLiteral(True),
                    )
                ]
            ),
            "StringModifier value must be a string, number, tuple, or null",
        ),
        (
            YaraFile(
                rules=[
                    Rule(
                        "invalid_modifier_tuple",
                        strings=[
                            PlainString(
                                identifier="$a",
                                value="x",
                                modifiers=[invalid_modifier_tuple],
                            )
                        ],
                        condition=BooleanLiteral(True),
                    )
                ]
            ),
            "StringModifier tuple value must contain two integers",
        ),
        (
            YaraFile(
                rules=[
                    Rule(
                        "invalid_modifier_float",
                        strings=[
                            PlainString(
                                identifier="$a",
                                value="x",
                                modifiers=[invalid_modifier_float],
                            )
                        ],
                        condition=BooleanLiteral(True),
                    )
                ]
            ),
            "StringModifier value must be finite",
        ),
        (
            YaraFile(
                rules=[
                    Rule(
                        "invalid_hex_byte",
                        strings=[HexString(identifier="$h", tokens=[HexByte(invalid_byte)])],
                        condition=BooleanLiteral(True),
                    )
                ]
            ),
            "HexByte value must be a byte",
        ),
        (
            YaraFile(
                rules=[
                    Rule(
                        "invalid_hex_negated_byte",
                        strings=[
                            HexString(
                                identifier="$h",
                                tokens=[HexNegatedByte(invalid_byte)],
                            )
                        ],
                        condition=BooleanLiteral(True),
                    )
                ]
            ),
            "HexNegatedByte value must be a byte",
        ),
        (
            YaraFile(
                rules=[
                    Rule(
                        "invalid_hex_min_jump",
                        strings=[
                            HexString(identifier="$h", tokens=[HexJump(min_jump=invalid_jump)])
                        ],
                        condition=BooleanLiteral(True),
                    )
                ]
            ),
            "HexJump min_jump must be a non-negative integer",
        ),
        (
            YaraFile(
                rules=[
                    Rule(
                        "invalid_hex_max_jump",
                        strings=[
                            HexString(identifier="$h", tokens=[HexJump(max_jump=invalid_jump)])
                        ],
                        condition=BooleanLiteral(True),
                    )
                ]
            ),
            "HexJump max_jump must be a non-negative integer",
        ),
        (
            YaraFile(
                rules=[
                    Rule(
                        "invalid_hex_jump_bounds",
                        strings=[HexString(identifier="$h", tokens=[HexJump(5, 1)])],
                        condition=BooleanLiteral(True),
                    )
                ]
            ),
            "HexJump min_jump cannot exceed max_jump",
        ),
        (
            YaraFile(
                rules=[
                    Rule(
                        "hex_jump_at_start",
                        strings=[HexString(identifier="$h", tokens=[HexJump(1, 2), HexByte(0x41)])],
                        condition=BooleanLiteral(True),
                    )
                ]
            ),
            "HexJump cannot appear at the beginning or end of hex string",
        ),
        (
            YaraFile(
                rules=[
                    Rule(
                        "hex_jump_at_end",
                        strings=[HexString(identifier="$h", tokens=[HexByte(0x41), HexJump(1, 2)])],
                        condition=BooleanLiteral(True),
                    )
                ]
            ),
            "HexJump cannot appear at the beginning or end of hex string",
        ),
        (
            YaraFile(
                rules=[
                    Rule(
                        "invalid_hex_nibble_high",
                        strings=[
                            HexString(
                                identifier="$h",
                                tokens=[HexNibble(high=invalid_bool, value=1)],
                            )
                        ],
                        condition=BooleanLiteral(True),
                    )
                ]
            ),
            "HexNibble high must be a boolean",
        ),
        (
            YaraFile(
                rules=[
                    Rule(
                        "invalid_hex_nibble_value",
                        strings=[
                            HexString(
                                identifier="$h",
                                tokens=[HexNibble(high=True, value=invalid_nibble)],
                            )
                        ],
                        condition=BooleanLiteral(True),
                    )
                ]
            ),
            "HexNibble value must be a nibble",
        ),
        (
            YaraFile(
                rules=[
                    Rule(
                        "invalid_hex_alternatives",
                        strings=[HexString(identifier="$h", tokens=[invalid_hex_alternatives])],
                        condition=BooleanLiteral(True),
                    )
                ]
            ),
            "HexAlternative alternatives must be a list",
        ),
        (
            YaraFile(
                rules=[
                    Rule(
                        "empty_hex_alternatives",
                        strings=[HexString(identifier="$h", tokens=[empty_hex_alternatives])],
                        condition=BooleanLiteral(True),
                    )
                ]
            ),
            "HexAlternative must contain at least one branch",
        ),
        (
            YaraFile(
                rules=[
                    Rule(
                        "empty_hex_alternative_branch",
                        strings=[HexString(identifier="$h", tokens=[empty_hex_alternative_branch])],
                        condition=BooleanLiteral(True),
                    )
                ]
            ),
            "HexAlternative branches must not be empty",
        ),
        (
            YaraFile(
                rules=[
                    Rule(
                        "unbounded_hex_jump_in_alternative",
                        strings=[
                            HexString(
                                identifier="$h",
                                tokens=[
                                    HexAlternative(
                                        [[HexByte(0x41), HexJump(1, None), HexByte(0x42)]]
                                    )
                                ],
                            )
                        ],
                        condition=BooleanLiteral(True),
                    )
                ]
            ),
            "Unbounded HexJump is not allowed inside hex alternatives",
        ),
        (
            YaraFile(
                rules=[
                    Rule(
                        "invalid_hex_alternative_token",
                        strings=[
                            HexString(
                                identifier="$h",
                                tokens=[invalid_hex_alternative_token],
                            )
                        ],
                        condition=BooleanLiteral(True),
                    )
                ]
            ),
            "HexByte value must be a byte",
        ),
    ]

    for ast, message in invalid_cases:
        with pytest.raises(SerializationError, match=message):
            serializer.serialize(ast)


def test_json_serializer_rejects_invalid_location_fields() -> None:
    serializer = JsonSerializer(include_metadata=False)
    invalid_bool: Any = True
    invalid_text: Any = "1"
    invalid_file: Any = 123

    invalid_locations = [
        (
            cast(Any, object()),
            "location must be a Location",
        ),
        (
            Location(invalid_bool, 1),
            "Location line must be an integer",
        ),
        (
            Location(1, invalid_text),
            "Location column must be an integer",
        ),
        (
            Location(1, 1, file=invalid_file),
            "Location file must be a string",
        ),
        (
            Location(1, 1, end_line=invalid_text),
            "Location end_line must be an integer",
        ),
        (
            Location(1, 1, end_column=invalid_bool),
            "Location end_column must be an integer",
        ),
        (
            Location(0, 1),
            "Location line must be at least 1",
        ),
    ]

    for location, message in invalid_locations:
        rule = Rule("invalid_location", condition=BooleanLiteral(True))
        rule.location = location
        ast = YaraFile(rules=[rule])
        with pytest.raises(SerializationError, match=message):
            serializer.serialize(ast)


def test_json_serializer_deserialize_rejects_non_positive_location_fields() -> None:
    serializer = JsonSerializer(include_metadata=False)
    payload = {
        "type": "YaraFile",
        "imports": [],
        "includes": [],
        "rules": [],
        "extern_rules": [],
        "extern_imports": [],
        "pragmas": [],
        "namespaces": [],
        "location": {"line": 0, "column": 1},
    }

    with pytest.raises(SerializationError, match="Location line must be at least 1"):
        serializer.deserialize(json.dumps(payload))


def test_json_serializer_rejects_invalid_anonymous_string_flags() -> None:
    serializer = JsonSerializer(include_metadata=False)
    invalid_flag: Any = "yes"

    invalid_cases: list[tuple[YaraFile, str]] = [
        (
            YaraFile(
                rules=[
                    Rule(
                        "invalid_plain_anonymous",
                        strings=[
                            PlainString(
                                identifier="$a",
                                value="x",
                                is_anonymous=invalid_flag,
                            )
                        ],
                        condition=BooleanLiteral(True),
                    )
                ]
            ),
            "PlainString is_anonymous must be a boolean",
        ),
        (
            YaraFile(
                rules=[
                    Rule(
                        "invalid_hex_anonymous",
                        strings=[
                            HexString(
                                identifier="$h",
                                tokens=[],
                                is_anonymous=invalid_flag,
                            )
                        ],
                        condition=BooleanLiteral(True),
                    )
                ]
            ),
            "HexString is_anonymous must be a boolean",
        ),
        (
            YaraFile(
                rules=[
                    Rule(
                        "invalid_regex_anonymous",
                        strings=[
                            RegexString(
                                identifier="$r",
                                regex="x",
                                is_anonymous=invalid_flag,
                            )
                        ],
                        condition=BooleanLiteral(True),
                    )
                ]
            ),
            "RegexString is_anonymous must be a boolean",
        ),
    ]

    for ast, message in invalid_cases:
        with pytest.raises(SerializationError, match=message):
            serializer.serialize(ast)


def test_json_serializer_rejects_invalid_raw_string_sets() -> None:
    serializer = JsonSerializer(include_metadata=False)
    invalid_string_sets: list[Any] = [
        True,
        123,
        None,
        {},
        "",
        "   ",
        [],
        object(),
        [False],
        [123],
        [""],
        ["   "],
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
            ArrayComprehension(expression=invalid_value, variable="x"),
            ArrayComprehension(iterable=invalid_value, variable="x"),
            ArrayComprehension(condition=invalid_value, variable="x"),
            DictComprehension(key_expression=invalid_value, key_variable="k"),
            DictComprehension(value_expression=invalid_value, key_variable="k"),
            DictComprehension(iterable=invalid_value, key_variable="k"),
            DictComprehension(condition=invalid_value, key_variable="k"),
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
        ArrayComprehension(expression=invalid_node, variable="x"),
        ArrayComprehension(iterable=invalid_node, variable="x"),
        ArrayComprehension(condition=invalid_node, variable="x"),
        DictComprehension(key_expression=invalid_node, key_variable="k"),
        DictComprehension(value_expression=invalid_node, key_variable="k"),
        DictComprehension(iterable=invalid_node, key_variable="k"),
        DictComprehension(condition=invalid_node, key_variable="k"),
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
                "pragmas": [],
            }
        ],
        "extern_rules": [],
        "extern_imports": [],
        "pragmas": [],
        "namespaces": [],
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


def test_json_roundtrip_preserves_string_modifier_metadata() -> None:
    serializer = JsonSerializer(include_metadata=True)
    modifier = StringModifier.from_name_value("xor", 5)
    modifier.location = Location(11, 12)
    ast = YaraFile(
        rules=[
            Rule(
                name="modifier_metadata",
                strings=[
                    PlainString(
                        identifier="$a",
                        value="a",
                        modifiers=[modifier],
                    ),
                ],
                condition=BooleanLiteral(True),
            )
        ]
    )

    restored = serializer.deserialize(serializer.serialize(ast))
    restored_modifier = restored.rules[0].strings[0].modifiers[0]

    assert isinstance(restored_modifier, StringModifier)
    assert restored_modifier.location == Location(11, 12)


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
                "imports": [],
                "includes": [],
                "rules": [
                    {
                        "type": "Rule",
                        "name": "legacy_aliases",
                        "modifiers": [],
                        "tags": [],
                        "meta": [],
                        "strings": [
                            {
                                "type": "RegexString",
                                "identifier": "$r",
                                "regex": "ab.*",
                                "modifiers": ["i", "s"],
                            }
                        ],
                        "condition": {"type": "StringIdentifier", "name": "$r"},
                        "pragmas": [],
                    }
                ],
                "extern_rules": [],
                "extern_imports": [],
                "pragmas": [],
                "namespaces": [],
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
                    MetaEntry.from_key_value("score", 1.5),
                ],
                condition=BooleanLiteral(True),
            )
        ]
    )

    serialized = json.loads(serializer.serialize(ast))
    restored = serializer.deserialize(json.dumps(serialized))

    assert serialized["ast"]["rules"][0]["meta"][0]["type"] == "MetaEntry"
    assert serialized["ast"]["rules"][0]["meta"][0]["scope"] == "private"
    assert serialized["ast"]["rules"][0]["meta"][1]["type"] == "MetaEntry"
    assert serialized["ast"]["rules"][0]["meta"][2]["type"] == "MetaEntry"
    assert [entry.scope for entry in restored.rules[0].meta] == [
        MetaScope.PRIVATE,
        MetaScope.PUBLIC,
        MetaScope.PUBLIC,
    ]
    assert serialized["ast"]["rules"][0]["meta"][2]["value"] == 1.5
    assert restored.rules[0].meta[2].value == 1.5
    assert [entry.key for entry in restored.rules[0].get_private_meta()] == ["secret"]

    restored.rules[0].meta[0].location = Location(3, 5)
    reserialized = json.loads(serializer.serialize(restored))
    assert reserialized["ast"]["rules"][0]["meta"][0]["location"] == {
        "line": 3,
        "column": 5,
    }


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


def test_json_roundtrip_preserves_empty_define_macro_value_argument() -> None:
    serializer = JsonSerializer(include_metadata=False)
    ast = YaraFile(pragmas=[DefineDirective("EMPTY", "")])

    restored = serializer.deserialize(serializer.serialize(ast))

    assert isinstance(restored.pragmas[0], DefineDirective)
    assert restored.pragmas[0].macro_value == ""
    assert restored.pragmas[0].arguments == ["EMPTY", ""]


def test_json_serializer_preserves_extern_rule_reference_conditions() -> None:
    serializer = JsonSerializer(include_metadata=False)
    reference = ExternRuleReference("ExternalRule", namespace="ns")
    ast = YaraFile(
        rules=[
            Rule(
                name="uses_external",
                condition=cast(Any, reference),
            )
        ]
    )

    restored = serializer.deserialize(serializer.serialize(ast))

    assert cast(Any, restored.rules[0].condition) == reference


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
