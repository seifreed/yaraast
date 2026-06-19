"""Extra tests for Protobuf serializer (no mocks)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, cast

import pytest

from yaraast.ast.base import Location, YaraFile
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
    Expression,
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
from yaraast.ast.modifiers import MetaEntry, MetaScope, StringModifier
from yaraast.ast.modules import DictionaryAccess, ModuleReference
from yaraast.ast.operators import DefinedExpression, StringOperatorExpression
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
)
from yaraast.codegen import CodeGenerator
from yaraast.errors import SerializationError
from yaraast.serialization import yara_ast_pb2
from yaraast.serialization.protobuf_conversion import (
    _protobuf_has_field,
    convert_expression_to_protobuf,
)
from yaraast.serialization.protobuf_serializer import ProtobufSerializer
from yaraast.yarax.ast_nodes import DictExpression, ListExpression, TupleExpression


def _sample_ast() -> YaraFile:
    strings = [
        PlainString(
            identifier="$a",
            value="alpha",
            modifiers=[StringModifier.from_name_value("ascii")],
        ),
        HexString(
            identifier="$b",
            tokens=[
                HexByte(value=0x90),
                HexWildcard(),
                HexJump(min_jump=1, max_jump=3),
                HexNibble(high=True, value=0xA),
            ],
            modifiers=[StringModifier.from_name_value("wide")],
        ),
        RegexString(identifier="$c", regex="abc.*", modifiers=[]),
    ]
    condition = BinaryExpression(
        left=UnaryExpression(operator="not", operand=BooleanLiteral(value=False)),
        operator="and",
        right=BinaryExpression(
            left=StringCount(string_id="$a"),
            operator=">",
            right=IntegerLiteral(value=0),
        ),
    )
    rule = Rule(
        name="rule_one",
        modifiers=["private"],
        tags=[Tag(name="tag1")],
        meta={"author": "me", "score": 3},
        strings=strings,
        condition=condition,
    )
    return YaraFile(
        imports=[Import(module="pe")],
        includes=[Include(path="inc.yar")],
        rules=[rule],
    )


def test_protobuf_has_field_propagates_missing_message_api() -> None:
    class NotAProtobufMessage:
        pass

    location = yara_ast_pb2.SourceLocation(line=1)
    assert _protobuf_has_field(location, "line") is False

    with pytest.raises(AttributeError):
        _protobuf_has_field(NotAProtobufMessage(), "line")


def test_protobuf_serializer_roundtrip_and_metadata() -> None:
    serializer = ProtobufSerializer(include_metadata=True)
    ast = _sample_ast()

    data = serializer.serialize(ast)
    assert isinstance(data, bytes) and data

    text = serializer.serialize_text(ast)
    assert "metadata" in text or "format" in text

    restored = serializer.deserialize(binary_data=data)
    assert restored.rules[0].name == "rule_one"
    assert restored.rules[0].condition is not None  # Condition is preserved (no longer placeholder)


def test_protobuf_serializer_preserves_hex_jump_zero_and_open_bounds() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    expected_jumps = [
        (0, 100),
        (None, None),
        (0, 0),
        (None, 8),
        (4, None),
    ]
    ast = YaraFile(
        rules=[
            Rule(
                name="jump_bounds",
                strings=[
                    HexString(
                        identifier=f"$h{index}",
                        tokens=[HexByte(0x90), HexJump(min_jump, max_jump), HexByte(0x91)],
                    )
                    for index, (min_jump, max_jump) in enumerate(expected_jumps)
                ],
                condition=BooleanLiteral(value=True),
            )
        ]
    )

    restored = serializer.deserialize(binary_data=serializer.serialize(ast))

    assert [
        (string_def.tokens[1].min_jump, string_def.tokens[1].max_jump)
        for string_def in restored.rules[0].strings
        if isinstance(string_def, HexString)
    ] == expected_jumps


def test_protobuf_serializer_preserves_hex_alternatives() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    alternative = HexAlternative(
        alternatives=[
            [HexByte(value=0xAA), HexWildcard()],
            [
                HexByte(value=0xBB),
                HexJump(min_jump=1, max_jump=3),
                HexNibble(high=False, value=0xF),
            ],
        ]
    )
    ast = YaraFile(
        rules=[
            Rule(
                name="hex_alternative",
                strings=[HexString(identifier="$h", tokens=[alternative])],
                condition=BooleanLiteral(value=True),
            )
        ]
    )

    restored = serializer.deserialize(binary_data=serializer.serialize(ast))
    string_def = restored.rules[0].strings[0]

    assert isinstance(string_def, HexString)
    assert string_def.tokens == [alternative]


def test_protobuf_serializer_rejects_empty_hex_alternative() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    alternative = HexAlternative(alternatives=[])
    ast = YaraFile(
        rules=[
            Rule(
                name="empty_hex_alternative",
                strings=[HexString(identifier="$h", tokens=[alternative])],
                condition=BooleanLiteral(value=True),
            )
        ]
    )

    with pytest.raises(SerializationError, match="HexAlternative must contain at least one branch"):
        serializer.serialize(ast)


def test_protobuf_deserializer_rejects_empty_hex_alternatives() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    pb_file = yara_ast_pb2.YaraFile()
    pb_rule = pb_file.rules.add()
    pb_rule.name = "empty_hex_alternative"
    pb_rule.condition.boolean_literal.value = True
    pb_string = pb_rule.strings.add()
    pb_string.identifier = "$h"
    pb_string.hex.tokens.add().alternative.SetInParent()

    with pytest.raises(SerializationError, match="HexAlternative must contain at least one branch"):
        serializer.deserialize(binary_data=pb_file.SerializeToString())

    pb_file = yara_ast_pb2.YaraFile()
    pb_rule = pb_file.rules.add()
    pb_rule.name = "empty_hex_alternative_branch"
    pb_rule.condition.boolean_literal.value = True
    pb_string = pb_rule.strings.add()
    pb_string.identifier = "$h"
    pb_string.hex.tokens.add().alternative.alternatives.add()

    with pytest.raises(SerializationError, match="HexAlternative branches must not be empty"):
        serializer.deserialize(binary_data=pb_file.SerializeToString())


@pytest.mark.parametrize(
    "condition",
    [
        TupleExpression([]),
        ListExpression([]),
        DictExpression([]),
    ],
)
def test_protobuf_serializer_preserves_empty_collection_expressions(
    condition: Expression,
) -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = YaraFile(rules=[Rule(name="empty_collection", condition=condition)])

    restored = serializer.deserialize(binary_data=serializer.serialize(ast))

    assert restored.rules[0].condition == condition


def test_protobuf_serializer_rejects_empty_set_expression() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = YaraFile(rules=[Rule(name="empty_set", condition=SetExpression([]))])

    with pytest.raises(
        SerializationError, match="Set expression must contain at least one element"
    ):
        serializer.serialize(ast)


def test_protobuf_serializer_normalizes_scalar_hex_alternatives() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = YaraFile(
        rules=[
            Rule(
                name="scalar_hex_alternative",
                strings=[
                    HexString(
                        identifier="$h",
                        tokens=[
                            HexAlternative([0x90, "91"]),
                            HexAlternative([HexByte(0x92), HexByte("93")]),
                        ],
                    )
                ],
                condition=BooleanLiteral(value=True),
            )
        ]
    )

    restored = serializer.deserialize(binary_data=serializer.serialize(ast))
    string_def = restored.rules[0].strings[0]

    assert isinstance(string_def, HexString)
    assert string_def.tokens == [
        HexAlternative([[HexByte(0x90)], [HexByte("91")]]),
        HexAlternative([[HexByte(0x92)], [HexByte("93")]]),
    ]


def test_protobuf_serializer_preserves_hex_negated_bytes() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    tokens = [HexNegatedByte(value=0x4D), HexNegatedByte(value="4D"), HexNegatedByte(value="?0")]
    ast = YaraFile(
        rules=[
            Rule(
                name="hex_negated_byte",
                strings=[HexString(identifier="$h", tokens=tokens)],
                condition=BooleanLiteral(value=True),
            )
        ]
    )

    restored = serializer.deserialize(binary_data=serializer.serialize(ast))
    string_def = restored.rules[0].strings[0]

    assert isinstance(string_def, HexString)
    assert string_def.tokens == tokens


def test_protobuf_serializer_preserves_string_hex_byte_values() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = YaraFile(
        rules=[
            Rule(
                name="string_hex_byte",
                strings=[
                    HexString(
                        identifier="$h",
                        tokens=[HexByte(value="af"), HexByte(value="41")],
                    )
                ],
                condition=BooleanLiteral(value=True),
            )
        ]
    )

    restored = serializer.deserialize(binary_data=serializer.serialize(ast))
    string_def = restored.rules[0].strings[0]

    assert isinstance(string_def, HexString)
    assert string_def.tokens == [HexByte(value="af"), HexByte(value="41")]


def test_protobuf_serializer_accepts_string_hex_nibble_values() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = YaraFile(
        rules=[
            Rule(
                name="string_hex_nibble",
                strings=[
                    HexString(
                        identifier="$h",
                        tokens=[HexNibble(high=False, value="B")],
                    )
                ],
                condition=BooleanLiteral(value=True),
            )
        ]
    )

    restored = serializer.deserialize(binary_data=serializer.serialize(ast))
    string_def = restored.rules[0].strings[0]

    assert isinstance(string_def, HexString)
    assert string_def.tokens == [HexNibble(high=False, value="B")]


def test_protobuf_serializer_preserves_module_dictionary_and_wildcard_expressions() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    condition = BinaryExpression(
        left=DictionaryAccess(
            object=ModuleReference(module="pe"),
            key=StringLiteral(value="CompanyName"),
        ),
        operator="or",
        right=OfExpression(
            quantifier="any",
            string_set=StringWildcard(pattern="$api*"),
        ),
    )
    ast = YaraFile(
        rules=[
            Rule(
                name="module_dictionary_wildcard",
                condition=condition,
            )
        ]
    )

    restored = serializer.deserialize(binary_data=serializer.serialize(ast))

    assert restored.rules[0].condition == condition


@pytest.mark.parametrize(
    "condition",
    [
        ForOfExpression(
            quantifier=2,
            string_set=["$a", "$b"],
            condition=BooleanLiteral(value=True),
        ),
        ForOfExpression(
            quantifier="any",
            string_set="$api*",
            condition=BooleanLiteral(value=True),
        ),
        OfExpression(
            quantifier=2,
            string_set=["$a", "$b"],
        ),
        OfExpression(
            quantifier=2,
            string_set=("$a", "$b"),
        ),
        OfExpression(
            quantifier=2,
            string_set=frozenset(("$a", "$b")),
        ),
    ],
)
def test_protobuf_serializer_preserves_condition_string_set_value_shapes(
    condition: Expression,
) -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = YaraFile(
        rules=[
            Rule(
                name="string_set_shapes",
                condition=condition,
            )
        ]
    )

    restored = serializer.deserialize(binary_data=serializer.serialize(ast))

    expected = condition
    if isinstance(condition, OfExpression) and isinstance(
        condition.string_set, tuple | set | frozenset
    ):
        expected = OfExpression(condition.quantifier, sorted(condition.string_set, key=str))

    assert restored.rules[0].condition == expected


def test_protobuf_serializer_canonicalizes_ast_string_set_list_items() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = YaraFile(
        rules=[
            Rule(
                name="ast_string_set_items",
                condition=OfExpression(
                    quantifier="any",
                    string_set=[StringIdentifier("$a"), StringWildcard("$b*")],
                ),
            )
        ]
    )

    protobuf_file = serializer._ast_to_protobuf(ast)
    restored = serializer.deserialize(binary_data=serializer.serialize(ast))

    assert list(protobuf_file.rules[0].condition.of_expression.string_set_items) == ["$a", "$b*"]
    assert restored.rules[0].condition == OfExpression("any", ["$a", "$b*"])


def test_protobuf_serializer_preserves_metadata_bearing_string_set_items() -> None:
    serializer = ProtobufSerializer(include_metadata=True)
    list_item = StringIdentifier("$a")
    list_item.location = Location(7, 8)
    expression_item = StringWildcard("$b*")
    expression_item.location = Location(9, 10)
    ast = YaraFile(
        rules=[
            Rule(
                name="metadata_string_set_items",
                condition=OfExpression(IntegerLiteral(1), [list_item, "$b"]),
            ),
            Rule(
                name="metadata_string_set_expression_items",
                condition=OfExpression(
                    "any",
                    ParenthesesExpression(SetExpression([expression_item])),
                ),
            ),
        ]
    )

    protobuf_file = serializer._ast_to_protobuf(ast)
    restored = serializer.deserialize(binary_data=serializer.serialize(ast))
    list_condition = restored.rules[0].condition
    expression_condition = restored.rules[1].condition

    assert _protobuf_has_field(protobuf_file.rules[0].condition.of_expression, "string_set")
    assert not protobuf_file.rules[0].condition.of_expression.string_set_items
    assert isinstance(list_condition, OfExpression)
    assert isinstance(list_condition.string_set, SetExpression)
    restored_list_item = list_condition.string_set.elements[0]
    assert isinstance(restored_list_item, StringIdentifier)
    assert restored_list_item.name == "$a"
    assert restored_list_item.location == Location(7, 8)
    assert isinstance(list_condition.string_set.elements[1], StringIdentifier)
    assert list_condition.string_set.elements[1].name == "$b"

    assert _protobuf_has_field(protobuf_file.rules[1].condition.of_expression, "string_set")
    assert not protobuf_file.rules[1].condition.of_expression.string_set_items
    assert isinstance(expression_condition, OfExpression)
    assert isinstance(expression_condition.string_set, ParenthesesExpression)
    assert isinstance(expression_condition.string_set.expression, SetExpression)
    restored_expression_item = expression_condition.string_set.expression.elements[0]
    assert isinstance(restored_expression_item, StringWildcard)
    assert restored_expression_item.pattern == "$b*"
    assert restored_expression_item.location == Location(9, 10)


def test_protobuf_serializer_canonicalizes_ast_string_set_expression_items() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = YaraFile(
        rules=[
            Rule(
                name="ast_string_set_expression_items",
                condition=OfExpression(
                    quantifier="any",
                    string_set=ParenthesesExpression(
                        SetExpression([StringLiteral("$a"), StringLiteral("$b*")])
                    ),
                ),
            )
        ]
    )

    protobuf_file = serializer._ast_to_protobuf(ast)
    restored = serializer.deserialize(binary_data=serializer.serialize(ast))

    assert list(protobuf_file.rules[0].condition.of_expression.string_set_items) == ["$a", "$b*"]
    assert restored.rules[0].condition == OfExpression("any", ["$a", "$b*"])


def test_protobuf_serializer_restores_compact_rule_wildcard_string_sets_for_codegen() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = YaraFile(
        rules=[
            Rule(
                name="rule_wildcard_string_set",
                condition=OfExpression("any", SetExpression([StringWildcard("helper*")])),
            )
        ]
    )

    protobuf_file = serializer._ast_to_protobuf(ast)
    restored = serializer.deserialize(binary_data=serializer.serialize(ast))
    condition = restored.rules[0].condition

    assert _protobuf_has_field(protobuf_file.rules[0].condition.of_expression, "string_set")
    assert not protobuf_file.rules[0].condition.of_expression.string_set_items
    assert isinstance(condition, OfExpression)
    assert isinstance(condition.string_set, SetExpression)
    restored_item = condition.string_set.elements[0]
    assert isinstance(restored_item, StringWildcard)
    assert restored_item.pattern == "helper*"
    assert "any of (helper*)" in CodeGenerator().generate(restored)


def test_protobuf_serializer_preserves_compact_bare_string_set_items_as_strings() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = YaraFile(
        rules=[
            Rule(
                name="bare_string_set_item",
                strings=[PlainString("$a", "needle")],
                condition=OfExpression("any", ["a"]),
            )
        ]
    )

    protobuf_file = serializer._ast_to_protobuf(ast)
    restored = serializer.deserialize(binary_data=serializer.serialize(ast))
    condition = restored.rules[0].condition

    assert list(protobuf_file.rules[0].condition.of_expression.string_set_items) == ["a"]
    assert isinstance(condition, OfExpression)
    assert condition.string_set == ["a"]
    assert "any of ($a)" in CodeGenerator().generate(restored)


def test_protobuf_serializer_preserves_non_text_string_set_expression_items() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    string_set_expression = BinaryExpression(
        BooleanLiteral(True),
        "and",
        BooleanLiteral(False),
    )
    expressions: list[Expression] = [
        OfExpression("any", [string_set_expression]),
        ForOfExpression("any", [string_set_expression], condition=None),
    ]

    for expression in expressions:
        ast = YaraFile(rules=[Rule(name="expression_string_set", condition=expression)])
        restored = serializer.deserialize(binary_data=serializer.serialize(ast))
        condition = restored.rules[0].condition

        assert isinstance(condition, OfExpression | ForOfExpression)
        assert condition.string_set == SetExpression([string_set_expression])


def test_protobuf_serializer_rejects_invalid_string_set_roots() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    invalid_string_sets: list[Any] = [True, False, 1, 1.5, object()]

    for string_set in invalid_string_sets:
        expressions: list[Expression] = [
            OfExpression("any", string_set),
            ForOfExpression("any", string_set, condition=None),
        ]
        for expression in expressions:
            ast = YaraFile(rules=[Rule(name="bad_string_set", condition=expression)])
            with pytest.raises(SerializationError, match="string_set must be a string"):
                serializer.serialize(ast)


def test_protobuf_serializer_rejects_invalid_string_set_list_items() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    invalid_string_sets: list[Any] = [[True], [False], [123], [1.5], [object()]]

    for string_set in invalid_string_sets:
        expressions: list[Expression] = [
            OfExpression("any", string_set),
            ForOfExpression("any", string_set, condition=None),
        ]
        for expression in expressions:
            ast = YaraFile(rules=[Rule(name="bad_string_set_item", condition=expression)])
            with pytest.raises(
                SerializationError,
                match="string_set must contain strings or expressions",
            ):
                serializer.serialize(ast)


def test_protobuf_serializer_rejects_invalid_string_set_expression_containers() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    string_set = SetExpression([StringIdentifier("$a")])
    cast(Any, string_set).elements = False
    expressions: list[Expression] = [
        OfExpression("any", string_set),
        ForOfExpression("any", string_set, condition=None),
    ]

    for expression in expressions:
        ast = YaraFile(rules=[Rule(name="bad_string_set_expression", condition=expression)])
        with pytest.raises(SerializationError, match="SetExpression elements must be a list"):
            serializer.serialize(ast)


def test_protobuf_serializer_rejects_unsupported_condition_values() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    invalid_conditions: list[Any] = [False, 0, object()]

    for condition in invalid_conditions:
        ast = YaraFile(rules=[Rule(name="unsupported_condition", condition=condition)])
        with pytest.raises(SerializationError, match="Unsupported protobuf expression type"):
            serializer.serialize(ast)


def test_protobuf_serializer_rejects_empty_in_expression_subject() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = YaraFile(
        rules=[
            Rule(
                name="empty_in_subject",
                condition=InExpression("", RangeExpression(IntegerLiteral(0), IntegerLiteral(1))),
            )
        ]
    )

    with pytest.raises(SerializationError, match="InExpression subject must not be empty"):
        serializer.serialize(ast)


def test_protobuf_serializer_rejects_empty_dictionary_access_key() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = YaraFile(
        rules=[
            Rule(
                name="empty_dictionary_key",
                condition=DictionaryAccess(Identifier("m"), ""),
            )
        ]
    )

    with pytest.raises(SerializationError, match="DictionaryAccess key must not be empty"):
        serializer.serialize(ast)


def test_protobuf_serializer_rejects_unsupported_string_definitions() -> None:
    class UnsupportedStringDefinition:
        identifier = "$x"

    serializer = ProtobufSerializer(include_metadata=False)
    unsupported_string: Any = UnsupportedStringDefinition()
    ast = YaraFile(
        rules=[
            Rule(
                name="unsupported_string",
                strings=[unsupported_string],
                condition=BooleanLiteral(True),
            )
        ]
    )

    with pytest.raises(SerializationError, match="Unsupported protobuf string definition type"):
        serializer.serialize(ast)


def test_protobuf_serializer_rejects_unsupported_hex_tokens() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    unsupported_token: Any = object()
    ast = YaraFile(
        rules=[
            Rule(
                name="unsupported_hex_token",
                strings=[HexString(identifier="$h", tokens=[unsupported_token])],
                condition=BooleanLiteral(True),
            )
        ]
    )

    with pytest.raises(SerializationError, match="Unsupported protobuf hex token type"):
        serializer.serialize(ast)


@pytest.mark.parametrize(
    ("token", "message"),
    [
        (HexByte(999), "HexByte value must be a byte"),
        (HexByte(-1), "HexByte value must be a byte"),
        (HexNegatedByte(999), "HexNegatedByte value must be a byte"),
        (HexJump(-1, 2), "HexJump min_jump must be a non-negative integer"),
        (HexJump(2**31, 2**31), "HexJump min_jump must fit in protobuf int32"),
        (HexJump(5, 3), "HexJump min_jump cannot exceed max_jump"),
        (HexJump(1, 2**31), "HexJump max_jump must fit in protobuf int32"),
        (HexNibble(True, 16), "HexNibble value must be a nibble"),
        (HexNibble(cast(Any, "yes"), 1), "HexNibble high must be a boolean"),
    ],
)
def test_protobuf_serializer_rejects_invalid_hex_token_fields(token: Any, message: str) -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    tokens = [HexByte(0x90), token, HexByte(0x91)] if isinstance(token, HexJump) else [token]
    ast = YaraFile(
        rules=[
            Rule(
                name="invalid_hex_token",
                strings=[HexString(identifier="$h", tokens=tokens)],
                condition=BooleanLiteral(True),
            )
        ]
    )

    with pytest.raises(SerializationError, match=message):
        serializer.serialize(ast)


def test_protobuf_serializer_preserves_typed_string_modifier_values() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
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
                condition=BooleanLiteral(value=True),
            )
        ]
    )

    restored = serializer.deserialize(binary_data=serializer.serialize(ast))
    restored_strings = restored.rules[0].strings

    assert [string.modifiers[0].value for string in restored_strings] == [
        5,
        (1, 3),
        "alphabet",
    ]


def test_protobuf_serializer_preserves_meta_entry_scope() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = YaraFile(
        rules=[
            Rule(
                name="meta_scope",
                meta=[
                    MetaEntry.from_key_value("secret", "token", "private"),
                    MetaEntry.from_key_value("owner", "team"),
                ],
                condition=BooleanLiteral(value=True),
            )
        ]
    )

    restored = serializer.deserialize(binary_data=serializer.serialize(ast))
    scopes_by_key = {entry.key: entry.scope for entry in restored.rules[0].meta}

    assert scopes_by_key == {"secret": MetaScope.PRIVATE, "owner": MetaScope.PUBLIC}
    assert [entry.key for entry in restored.rules[0].get_private_meta()] == ["secret"]


def test_protobuf_serializer_preserves_scoped_meta_metadata() -> None:
    serializer = ProtobufSerializer(include_metadata=True)
    scoped_meta = Meta("classification", "restricted")
    scoped_meta.location = Location(3, 5)
    cast(Any, scoped_meta).scope = MetaScope.PRIVATE
    ast = YaraFile(
        rules=[
            Rule(
                name="scoped_meta_metadata",
                meta=[scoped_meta],
                condition=BooleanLiteral(value=True),
            )
        ]
    )

    restored = serializer.deserialize(binary_data=serializer.serialize(ast))
    restored_meta = restored.rules[0].meta[0]

    assert isinstance(restored_meta, MetaEntry)
    assert restored_meta.scope == MetaScope.PRIVATE
    assert getattr(restored_meta, "location", None) == Location(3, 5)


def test_protobuf_deserialize_rejects_invalid_meta_entry_scope() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    pb_file: Any = yara_ast_pb2.YaraFile()
    pb_rule = pb_file.rules.add()
    pb_rule.name = "invalid_meta_scope"
    pb_meta = pb_rule.meta_entries.add()
    pb_meta.key = "owner"
    pb_meta.value.string_value = "team"
    pb_meta.scope = "secret"

    with pytest.raises(
        SerializationError, match="Meta scope must be public, private, or protected"
    ):
        serializer.deserialize(binary_data=pb_file.SerializeToString())


def test_protobuf_serialize_rejects_invalid_meta_entry_scope() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    invalid_meta = MetaEntry("owner", "team")
    cast(Any, invalid_meta).scope = "secret"
    ast = YaraFile(
        rules=[
            Rule(
                name="invalid_meta_scope",
                meta=[invalid_meta],
                condition=BooleanLiteral(value=True),
            )
        ]
    )

    with pytest.raises(
        SerializationError, match="Meta scope must be public, private, or protected"
    ):
        serializer.serialize(ast)


def test_protobuf_deserializes_legacy_xor_modifier_text_values() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    pb_file: Any = yara_ast_pb2.YaraFile()
    pb_rule = pb_file.rules.add()
    pb_rule.name = "legacy_modifiers"
    pb_string = pb_rule.strings.add()
    pb_string.identifier = "$a"
    pb_string.plain.value = "a"
    key_modifier = pb_string.plain.modifiers.add()
    key_modifier.name = "xor"
    key_modifier.value = "5"
    range_modifier = pb_string.plain.modifiers.add()
    range_modifier.name = "xor"
    range_modifier.value = "1-3"
    pb_rule.condition.boolean_literal.value = True

    restored = serializer.deserialize(binary_data=pb_file.SerializeToString())
    modifiers = restored.rules[0].strings[0].modifiers

    assert [modifier.value for modifier in modifiers] == [5, (1, 3)]


def test_protobuf_serializer_preserves_extended_expression_roundtrips() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    expressions: list[Expression] = [
        BinaryExpression(
            left=StringOffset("$a", IntegerLiteral(0)),
            operator="==",
            right=IntegerLiteral(0),
        ),
        BinaryExpression(
            left=StringLength("$a", IntegerLiteral(0)),
            operator=">",
            right=IntegerLiteral(1),
        ),
        RegexLiteral(pattern="evil.*", modifiers="i"),
        ParenthesesExpression(BooleanLiteral(True)),
        SetExpression([StringIdentifier("$a"), StringIdentifier("$b")]),
        RangeExpression(IntegerLiteral(0), IntegerLiteral(10)),
        FunctionCall("math.entropy", [IntegerLiteral(0), IntegerLiteral(1)]),
        ArrayAccess(Identifier("arr"), IntegerLiteral(0)),
        MemberAccess(Identifier("pe"), "number_of_sections"),
        ForExpression(
            quantifier="any",
            variable="i",
            iterable=RangeExpression(IntegerLiteral(0), IntegerLiteral(2)),
            body=BinaryExpression(Identifier("i"), ">", IntegerLiteral(0)),
        ),
        ForOfExpression(
            quantifier="all",
            string_set=Identifier("them"),
            condition=StringIdentifier("$a"),
        ),
        AtExpression("$a", IntegerLiteral(0)),
        AtExpression(OfExpression(IntegerLiteral(1), Identifier("them")), IntegerLiteral(0)),
        InExpression("$a", RangeExpression(IntegerLiteral(0), IntegerLiteral(10))),
        InExpression(
            OfExpression(IntegerLiteral(1), Identifier("them")),
            RangeExpression(IntegerLiteral(0), IntegerLiteral(10)),
        ),
        OfExpression(IntegerLiteral(1), Identifier("them")),
        DefinedExpression(Identifier("pe")),
        StringOperatorExpression(
            left=StringLiteral("Alpha"),
            operator="icontains",
            right=StringLiteral("alp"),
        ),
    ]

    for expression in expressions:
        ast = YaraFile(rules=[Rule(name="expr", condition=expression)])
        restored = serializer.deserialize(binary_data=serializer.serialize(ast))

        assert restored.rules[0].condition == expression


def test_protobuf_serializer_preserves_expression_quantifiers() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    expressions: list[Expression] = [
        ForExpression(
            quantifier=IntegerLiteral(2),
            variable="i",
            iterable=RangeExpression(IntegerLiteral(0), IntegerLiteral(3)),
            body=BooleanLiteral(True),
        ),
        ForOfExpression(
            quantifier=IntegerLiteral(2),
            string_set=Identifier("them"),
            condition=StringIdentifier("$a"),
        ),
    ]

    for expression in expressions:
        ast = YaraFile(rules=[Rule(name="expr", condition=expression)])
        restored = serializer.deserialize(binary_data=serializer.serialize(ast))

        assert restored.rules[0].condition == expression


def test_protobuf_serializer_rejects_boolean_quantifiers() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    expressions: list[Expression] = [
        ForExpression(
            quantifier=True,
            variable="i",
            iterable=RangeExpression(IntegerLiteral(0), IntegerLiteral(3)),
            body=BooleanLiteral(True),
        ),
        ForOfExpression(
            quantifier=False,
            string_set=Identifier("them"),
            condition=None,
        ),
        OfExpression(
            quantifier=True,
            string_set=Identifier("them"),
        ),
    ]

    for expression in expressions:
        ast = YaraFile(rules=[Rule(name="bad_quantifier", condition=expression)])
        with pytest.raises(SerializationError, match="quantifier must be"):
            serializer.serialize(ast)


def test_protobuf_serializer_rejects_boolean_literal_quantifiers() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    expressions: list[Expression] = [
        ForExpression(
            quantifier=BooleanLiteral(True),
            variable="i",
            iterable=RangeExpression(IntegerLiteral(0), IntegerLiteral(3)),
            body=BooleanLiteral(True),
        ),
        ForOfExpression(
            quantifier=BooleanLiteral(False),
            string_set=Identifier("them"),
            condition=None,
        ),
        OfExpression(
            quantifier=BooleanLiteral(True),
            string_set=Identifier("them"),
        ),
    ]

    for expression in expressions:
        ast = YaraFile(rules=[Rule(name="bad_literal_quantifier", condition=expression)])
        with pytest.raises(SerializationError, match="quantifier must be"):
            serializer.serialize(ast)


def test_protobuf_serializer_rejects_unsupported_quantifier_values() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    invalid_quantifiers: list[Any] = [None, [], {}, object()]

    for quantifier in invalid_quantifiers:
        expressions: list[Expression] = [
            ForExpression(
                quantifier=quantifier,
                variable="i",
                iterable=RangeExpression(IntegerLiteral(0), IntegerLiteral(3)),
                body=BooleanLiteral(True),
            ),
            ForOfExpression(
                quantifier=quantifier,
                string_set=Identifier("them"),
                condition=None,
            ),
            OfExpression(
                quantifier=quantifier,
                string_set=Identifier("them"),
            ),
        ]
        for expression in expressions:
            ast = YaraFile(rules=[Rule(name="bad_quantifier", condition=expression)])
            with pytest.raises(SerializationError, match="quantifier must be"):
                serializer.serialize(ast)


def test_protobuf_serializer_rejects_empty_quantifier_text() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    expressions: list[Expression] = [
        ForExpression(
            quantifier="",
            variable="i",
            iterable=RangeExpression(IntegerLiteral(0), IntegerLiteral(3)),
            body=BooleanLiteral(True),
        ),
        ForOfExpression(
            quantifier="",
            string_set=Identifier("them"),
            condition=None,
        ),
        OfExpression(
            quantifier="",
            string_set=Identifier("them"),
        ),
    ]

    for expression in expressions:
        ast = YaraFile(rules=[Rule(name="bad_quantifier", condition=expression)])
        with pytest.raises(SerializationError, match="quantifier must not be empty"):
            serializer.serialize(ast)


def test_protobuf_serializer_rejects_non_finite_numeric_quantifiers() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    expressions: list[Expression] = [
        ForExpression(
            quantifier=float("nan"),
            variable="i",
            iterable=RangeExpression(IntegerLiteral(0), IntegerLiteral(3)),
            body=BooleanLiteral(True),
        ),
        ForOfExpression(
            quantifier=float("inf"),
            string_set=Identifier("them"),
            condition=None,
        ),
        OfExpression(
            quantifier=float("-inf"),
            string_set=Identifier("them"),
        ),
    ]

    for expression in expressions:
        ast = YaraFile(rules=[Rule(name="bad_quantifier", condition=expression)])
        with pytest.raises(SerializationError, match="quantifier must be finite"):
            serializer.serialize(ast)


def test_protobuf_deserializes_legacy_numeric_quantifier_text() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    pb_file: Any = yara_ast_pb2.YaraFile()
    pb_rule = pb_file.rules.add()
    pb_rule.name = "legacy"
    pb_rule.condition.for_expression.quantifier = "2"
    pb_rule.condition.for_expression.variable = "i"
    pb_rule.condition.for_expression.iterable.range_expression.low.integer_literal.value = 0
    pb_rule.condition.for_expression.iterable.range_expression.high.integer_literal.value = 3
    pb_rule.condition.for_expression.body.boolean_literal.value = True

    restored = serializer.deserialize(binary_data=pb_file.SerializeToString())
    condition = restored.rules[0].condition

    assert isinstance(condition, ForExpression)
    assert condition.quantifier == 2


def test_protobuf_deserializes_legacy_signed_numeric_quantifier_text() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    pb_file: Any = yara_ast_pb2.YaraFile()
    pb_rule = pb_file.rules.add()
    pb_rule.name = "legacy_signed"
    pb_rule.condition.for_expression.quantifier = "+1"
    pb_rule.condition.for_expression.variable = "i"
    pb_rule.condition.for_expression.iterable.range_expression.low.integer_literal.value = 0
    pb_rule.condition.for_expression.iterable.range_expression.high.integer_literal.value = 3
    pb_rule.condition.for_expression.body.boolean_literal.value = True

    restored = serializer.deserialize(binary_data=pb_file.SerializeToString())
    condition = restored.rules[0].condition

    assert isinstance(condition, ForExpression)
    assert condition.quantifier == 1


def test_protobuf_deserialize_rejects_non_finite_legacy_quantifier_text() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    pb_file: Any = yara_ast_pb2.YaraFile()
    pb_rule = pb_file.rules.add()
    pb_rule.name = "bad_quantifier"
    pb_rule.condition.for_expression.quantifier = "1e999"
    pb_rule.condition.for_expression.variable = "i"
    pb_rule.condition.for_expression.iterable.range_expression.low.integer_literal.value = 0
    pb_rule.condition.for_expression.iterable.range_expression.high.integer_literal.value = 3
    pb_rule.condition.for_expression.body.boolean_literal.value = True

    with pytest.raises(SerializationError, match="quantifier must be finite"):
        serializer.deserialize(binary_data=pb_file.SerializeToString())


@pytest.mark.parametrize(
    "expression_kind", ["for_expression", "for_of_expression", "of_expression"]
)
def test_protobuf_deserialize_rejects_empty_quantifier_text(expression_kind: str) -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    pb_file: Any = yara_ast_pb2.YaraFile()
    pb_rule = pb_file.rules.add()
    pb_rule.name = "empty_quantifier"
    if expression_kind == "for_expression":
        pb_rule.condition.for_expression.variable = "i"
        pb_rule.condition.for_expression.iterable.range_expression.low.integer_literal.value = 0
        pb_rule.condition.for_expression.iterable.range_expression.high.integer_literal.value = 3
        pb_rule.condition.for_expression.body.boolean_literal.value = True
    elif expression_kind == "for_of_expression":
        pb_rule.condition.for_of_expression.string_set_text = "them"
    else:
        pb_rule.condition.of_expression.quantifier_text = ""
        pb_rule.condition.of_expression.string_set_text = "them"

    with pytest.raises(SerializationError, match="quantifier must not be empty"):
        serializer.deserialize(binary_data=pb_file.SerializeToString())


def test_protobuf_deserialize_rejects_legacy_boolean_quantifier_text() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    pb_file: Any = yara_ast_pb2.YaraFile()
    pb_rule = pb_file.rules.add()
    pb_rule.name = "legacy_bool_text"
    pb_rule.condition.of_expression.quantifier_text = "true"
    pb_rule.condition.of_expression.string_set_text = "them"

    with pytest.raises(SerializationError, match="Invalid OfExpression quantifier"):
        serializer.deserialize(binary_data=pb_file.SerializeToString())


def test_protobuf_deserialize_rejects_malformed_signed_legacy_quantifier_text() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    pb_file: Any = yara_ast_pb2.YaraFile()
    pb_rule = pb_file.rules.add()
    pb_rule.name = "legacy_malformed_signed_text"
    pb_rule.condition.of_expression.quantifier_text = "--1"
    pb_rule.condition.of_expression.string_set_text = "them"

    with pytest.raises(SerializationError, match="Invalid OfExpression quantifier"):
        serializer.deserialize(binary_data=pb_file.SerializeToString())


def test_protobuf_deserialize_rejects_empty_expression_payload() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    pb_file: Any = yara_ast_pb2.YaraFile()
    pb_rule = pb_file.rules.add()
    pb_rule.name = "empty_condition"
    pb_rule.condition.SetInParent()

    with pytest.raises(SerializationError, match="Protobuf expression is missing"):
        serializer.deserialize(binary_data=pb_file.SerializeToString())


def test_protobuf_deserialize_rejects_nested_empty_expression_payload() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    pb_file: Any = yara_ast_pb2.YaraFile()
    pb_rule = pb_file.rules.add()
    pb_rule.name = "empty_operand"
    pb_rule.condition.binary_expression.operator = "and"
    pb_rule.condition.binary_expression.left.SetInParent()
    pb_rule.condition.binary_expression.right.boolean_literal.value = True

    with pytest.raises(SerializationError, match="Protobuf expression is missing"):
        serializer.deserialize(binary_data=pb_file.SerializeToString())


def test_protobuf_deserialize_rejects_empty_in_expression_subject() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    pb_file: Any = yara_ast_pb2.YaraFile()
    pb_rule = pb_file.rules.add()
    pb_rule.name = "empty_in_subject"
    pb_rule.condition.in_expression.range.range_expression.low.integer_literal.value = 0
    pb_rule.condition.in_expression.range.range_expression.high.integer_literal.value = 1

    with pytest.raises(SerializationError, match="InExpression subject must not be empty"):
        serializer.deserialize(binary_data=pb_file.SerializeToString())


def test_protobuf_deserialize_rejects_empty_dictionary_access_key() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    pb_file: Any = yara_ast_pb2.YaraFile()
    pb_rule = pb_file.rules.add()
    pb_rule.name = "empty_dictionary_key"
    pb_rule.condition.dictionary_access.object.identifier.name = "m"

    with pytest.raises(SerializationError, match="DictionaryAccess key must not be empty"):
        serializer.deserialize(binary_data=pb_file.SerializeToString())


def test_protobuf_deserialize_rejects_empty_string_definition() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    pb_file: Any = yara_ast_pb2.YaraFile()
    pb_rule = pb_file.rules.add()
    pb_rule.name = "empty_string"
    pb_rule.strings.add().identifier = "$a"
    pb_rule.condition.boolean_literal.value = True

    with pytest.raises(SerializationError, match="Protobuf string definition is missing"):
        serializer.deserialize(binary_data=pb_file.SerializeToString())


def test_protobuf_deserialize_rejects_empty_hex_token() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    pb_file: Any = yara_ast_pb2.YaraFile()
    pb_rule = pb_file.rules.add()
    pb_rule.name = "empty_hex_token"
    pb_string = pb_rule.strings.add()
    pb_string.identifier = "$h"
    pb_string.hex.tokens.add()
    pb_rule.condition.boolean_literal.value = True

    with pytest.raises(SerializationError, match="Protobuf hex token is missing"):
        serializer.deserialize(binary_data=pb_file.SerializeToString())


def test_protobuf_serializer_without_metadata() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = _sample_ast()
    text = serializer.serialize_text(ast)
    assert "format" not in text


def test_protobuf_expression_conversion_paths() -> None:
    pytest.importorskip("yaraast.serialization.yara_ast_pb2")
    from yaraast.serialization import yara_ast_pb2

    expr_cases: list[tuple[Expression, Callable[[Any], bool]]] = [
        (Identifier(name="id"), lambda pb: pb.identifier.name == "id"),
        (StringIdentifier(name="$a"), lambda pb: pb.string_identifier.name == "$a"),
        (StringCount(string_id="$b"), lambda pb: pb.string_count.string_id == "$b"),
        (IntegerLiteral(value=7), lambda pb: pb.integer_literal.value == 7),
        (DoubleLiteral(value=1.5), lambda pb: pb.double_literal.value == 1.5),
        (StringLiteral(value="hi"), lambda pb: pb.string_literal.value == "hi"),
        (BooleanLiteral(value=True), lambda pb: pb.boolean_literal.value is True),
        (
            BinaryExpression(
                left=IntegerLiteral(value=1),
                operator="==",
                right=IntegerLiteral(value=2),
            ),
            lambda pb: pb.binary_expression.operator == "=="
            and pb.binary_expression.left.integer_literal.value == 1
            and pb.binary_expression.right.integer_literal.value == 2,
        ),
        (
            UnaryExpression(operator="not", operand=BooleanLiteral(value=False)),
            lambda pb: pb.unary_expression.operator == "not"
            and pb.unary_expression.operand.boolean_literal.value is False,
        ),
    ]

    for expr, predicate in expr_cases:
        pb_expr = yara_ast_pb2.Expression()
        convert_expression_to_protobuf(expr, pb_expr)
        assert predicate(pb_expr)
