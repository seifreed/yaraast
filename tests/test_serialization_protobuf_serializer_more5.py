"""Additional coverage for protobuf serializer modifier paths."""

from __future__ import annotations

from collections.abc import Callable
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
    BinaryExpression,
    BooleanLiteral,
    DoubleLiteral,
    FunctionCall,
    Identifier,
    IntegerLiteral,
    MemberAccess,
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
from yaraast.ast.operators import StringOperatorExpression
from yaraast.ast.pragmas import (
    ConditionalDirective,
    CustomPragma,
    DefineDirective,
    InRulePragma,
    PragmaScope,
    PragmaType,
    UndefDirective,
)
from yaraast.ast.rules import Import, Include, Rule, Tag
from yaraast.ast.strings import (
    HexAlternative,
    HexByte,
    HexJump,
    HexString,
    HexWildcard,
    PlainString,
    RegexString,
)
from yaraast.errors import SerializationError
from yaraast.serialization import yara_ast_pb2
from yaraast.serialization.protobuf_conversion import protobuf_to_ast, protobuf_to_string
from yaraast.serialization.protobuf_serializer import ProtobufSerializer


def test_protobuf_serializer_hex_modifier_with_value() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = YaraFile(
        rules=[
            Rule(
                name="hexmods",
                strings=[
                    HexString(
                        identifier="$h",
                        tokens=[HexByte(value=0x41)],
                        modifiers=[StringModifier.from_name_value("xor", "10-20")],
                    ),
                ],
                condition=BooleanLiteral(value=True),
            ),
        ],
    )

    text = serializer.serialize_text(ast)
    assert "10-20" in text


def test_protobuf_serializer_preserves_string_modifier_aliases() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
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
            ),
        ],
    )

    restored = serializer.deserialize(binary_data=serializer.serialize(ast))
    modifiers = restored.rules[0].strings[0].modifiers

    assert modifiers[:2] == ["i", "s"]
    assert isinstance(modifiers[2], StringModifier)
    assert modifiers[2].name == "fullword"


def test_protobuf_conversion_escapes_unknown_modifier_string_values() -> None:
    pb_string = yara_ast_pb2.StringDefinition()
    pb_string.identifier = "$a"
    pb_string.plain.value = "abc"
    pb_modifier = pb_string.plain.modifiers.add()
    pb_modifier.name = "vendor_modifier"
    pb_modifier.value = 'a"\\b\n'

    restored = protobuf_to_string(pb_string)

    assert isinstance(restored, PlainString)
    assert restored.modifiers == ['vendor_modifier("a\\"\\\\b\\n")']


def test_protobuf_serializer_rejects_non_finite_modifier_values() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = YaraFile(
        rules=[
            Rule(
                name="bad_modifier",
                strings=[
                    PlainString(
                        identifier="$a",
                        value="abc",
                        modifiers=[StringModifier.from_name_value("xor", cast(Any, float("nan")))],
                    )
                ],
                condition=BooleanLiteral(value=True),
            ),
        ],
    )

    with pytest.raises(SerializationError, match="String modifier value must be finite"):
        serializer.serialize(ast)

    pb_string = yara_ast_pb2.StringDefinition()
    pb_string.identifier = "$a"
    pb_string.plain.value = "abc"
    pb_modifier = pb_string.plain.modifiers.add()
    pb_modifier.name = "vendor_modifier"
    pb_modifier.typed_value.double_value = float("inf")

    with pytest.raises(SerializationError, match="String modifier value must be finite"):
        protobuf_to_string(pb_string)


def test_protobuf_serializer_rejects_boolean_modifier_values() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = YaraFile(
        rules=[
            Rule(
                name="bad_modifier",
                strings=[
                    PlainString(
                        identifier="$a",
                        value="abc",
                        modifiers=[
                            StringModifier.from_name_value("xor", cast(Any, True)),
                        ],
                    )
                ],
                condition=BooleanLiteral(value=True),
            ),
        ],
    )

    with pytest.raises(
        SerializationError,
        match="String modifier value must be a string, number, tuple, or null",
    ):
        serializer.serialize(ast)

    pb_string = yara_ast_pb2.StringDefinition()
    pb_string.identifier = "$a"
    pb_string.plain.value = "abc"
    pb_modifier = pb_string.plain.modifiers.add()
    pb_modifier.name = "xor"
    pb_modifier.typed_value.bool_value = True

    with pytest.raises(
        SerializationError,
        match="String modifier value must be a string, number, tuple, or null",
    ):
        protobuf_to_string(pb_string)


def test_protobuf_serializer_rejects_unknown_modifier_value_types() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    invalid_modifier = StringModifier.from_name_value("xor", 1)
    cast(Any, invalid_modifier).value = object()
    ast = YaraFile(
        rules=[
            Rule(
                name="bad_modifier",
                strings=[
                    PlainString(
                        identifier="$a",
                        value="abc",
                        modifiers=[invalid_modifier],
                    )
                ],
                condition=BooleanLiteral(value=True),
            ),
        ],
    )

    with pytest.raises(
        SerializationError,
        match="String modifier value must be a string, number, tuple, or null",
    ):
        serializer.serialize(ast)


def test_protobuf_serializer_rejects_unknown_modifier_tuple_items() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    invalid_modifier = StringModifier.from_name_value("xor", (1, 3))
    cast(Any, invalid_modifier).value = (1, object())
    ast = YaraFile(
        rules=[
            Rule(
                name="bad_modifier",
                strings=[
                    PlainString(
                        identifier="$a",
                        value="abc",
                        modifiers=[invalid_modifier],
                    )
                ],
                condition=BooleanLiteral(value=True),
            ),
        ],
    )

    with pytest.raises(
        SerializationError,
        match="String modifier tuple value must contain two integers",
    ):
        serializer.serialize(ast)


@pytest.mark.parametrize("tuple_values", [[1], [1, 2, 3]])
def test_protobuf_deserializer_rejects_malformed_modifier_tuple_values(
    tuple_values: list[int],
) -> None:
    pb_string = yara_ast_pb2.StringDefinition()
    pb_string.identifier = "$a"
    pb_string.plain.value = "abc"
    pb_modifier = pb_string.plain.modifiers.add()
    pb_modifier.name = "xor"
    pb_modifier.tuple_value.extend(tuple_values)

    with pytest.raises(
        SerializationError,
        match="String modifier tuple value must contain two integers",
    ):
        protobuf_to_string(pb_string)


def test_protobuf_deserializer_rejects_empty_typed_modifier_value() -> None:
    pb_string = yara_ast_pb2.StringDefinition()
    pb_string.identifier = "$a"
    pb_string.plain.value = "abc"
    pb_modifier = pb_string.plain.modifiers.add()
    pb_modifier.name = "xor"
    pb_modifier.typed_value.SetInParent()

    with pytest.raises(
        SerializationError,
        match="String modifier typed value is missing a value",
    ):
        protobuf_to_string(pb_string)


@pytest.mark.parametrize("modifier_value", [cast(Any, (True, 3)), cast(Any, (1.5, 3))])
def test_protobuf_serializer_rejects_invalid_xor_range_values(
    modifier_value: Any,
) -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = YaraFile(
        rules=[
            Rule(
                name="invalid_xor_ranges",
                strings=[
                    PlainString(
                        "$range",
                        value="a",
                        modifiers=[StringModifier.from_name_value("xor", modifier_value)],
                    ),
                ],
                condition=StringIdentifier("$range"),
            ),
        ],
    )

    with pytest.raises(
        SerializationError,
        match="String modifier tuple value must contain two integers",
    ):
        serializer.serialize(ast)


def test_protobuf_conversion_parses_legacy_hex_xor_modifier_values() -> None:
    pb_string = yara_ast_pb2.StringDefinition()
    pb_string.identifier = "$a"
    pb_string.plain.value = "abc"
    key_modifier = pb_string.plain.modifiers.add()
    key_modifier.name = "xor"
    key_modifier.value = "0xff"
    range_modifier = pb_string.plain.modifiers.add()
    range_modifier.name = "xor"
    range_modifier.value = "0x01-0xff"

    restored = protobuf_to_string(pb_string)

    assert isinstance(restored, PlainString)
    assert [modifier.value for modifier in restored.modifiers] == [255, (1, 255)]


@pytest.mark.parametrize(
    ("token_kind", "field_name", "value", "message"),
    [
        ("byte", "value", "-1", "HexByte value must be a byte"),
        ("byte", "value", "999", "HexByte value must be a byte"),
        ("byte", "value", "GG", "HexByte value must be a byte"),
        ("negated_byte", "value", "999", "HexNegatedByte value must be a byte"),
        ("nibble", "value", 16, "HexNibble value must be a nibble"),
        ("nibble", "value", -1, "HexNibble value must be a nibble"),
        ("nibble", "raw_value", "GG", "HexNibble value must be a nibble"),
        ("jump", "min_jump", -1, "HexJump min_jump must be a non-negative integer"),
    ],
)
def test_protobuf_deserialization_rejects_invalid_hex_token_scalars(
    token_kind: str,
    field_name: str,
    value: str | int,
    message: str,
) -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    pb_file = yara_ast_pb2.YaraFile()
    pb_rule = pb_file.rules.add()
    pb_rule.name = "bad_hex"
    pb_string = pb_rule.strings.add()
    pb_string.identifier = "$h"
    pb_token = pb_string.hex.tokens.add()
    setattr(getattr(pb_token, token_kind), field_name, value)
    pb_rule.condition.boolean_literal.value = True

    with pytest.raises(SerializationError, match=message):
        serializer.deserialize(binary_data=pb_file.SerializeToString())


def test_protobuf_deserialization_rejects_descending_hex_jump_bounds() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    pb_file = yara_ast_pb2.YaraFile()
    pb_rule = pb_file.rules.add()
    pb_rule.name = "bad_hex_jump"
    pb_string = pb_rule.strings.add()
    pb_string.identifier = "$h"
    pb_token = pb_string.hex.tokens.add()
    pb_token.jump.min_jump = 5
    pb_token.jump.max_jump = 3
    pb_rule.condition.boolean_literal.value = True

    with pytest.raises(SerializationError, match="HexJump min_jump cannot exceed max_jump"):
        serializer.deserialize(binary_data=pb_file.SerializeToString())


def test_protobuf_serializer_rejects_non_finite_double_literals() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = YaraFile(
        rules=[
            Rule(
                name="bad_double",
                condition=DoubleLiteral(float("nan")),
            ),
        ],
    )

    with pytest.raises(SerializationError, match="DoubleLiteral value must be finite"):
        serializer.serialize(ast)

    pb_file = yara_ast_pb2.YaraFile()
    pb_rule = pb_file.rules.add()
    pb_rule.name = "bad_double"
    pb_rule.condition.double_literal.value = float("inf")

    with pytest.raises(SerializationError, match="DoubleLiteral value must be finite"):
        serializer.deserialize(binary_data=pb_file.SerializeToString())


def test_protobuf_serializer_rejects_non_finite_meta_values() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    non_finite_meta_entry = MetaEntry.from_key_value("score", 1.0)
    cast(Any, non_finite_meta_entry).value = float("nan")
    ast = YaraFile(
        rules=[
            Rule(
                name="bad_meta",
                meta=[non_finite_meta_entry],
                condition=BooleanLiteral(value=True),
            ),
        ],
    )

    with pytest.raises(SerializationError, match="Meta value must be finite"):
        serializer.serialize(ast)

    pb_file = yara_ast_pb2.YaraFile()
    pb_rule = pb_file.rules.add()
    pb_rule.name = "bad_meta"
    pb_rule.condition.boolean_literal.value = True
    pb_meta = pb_rule.meta_entries.add()
    pb_meta.key = "score"
    pb_meta.value.double_value = float("inf")

    with pytest.raises(SerializationError, match="Meta value must be finite"):
        serializer.deserialize(binary_data=pb_file.SerializeToString())

    legacy_pb_file = yara_ast_pb2.YaraFile()
    legacy_pb_rule = legacy_pb_file.rules.add()
    legacy_pb_rule.name = "bad_legacy_meta"
    legacy_pb_rule.condition.boolean_literal.value = True
    legacy_pb_rule.meta["score"].double_value = float("-inf")

    with pytest.raises(SerializationError, match="Meta value must be finite"):
        serializer.deserialize(binary_data=legacy_pb_file.SerializeToString())


def test_protobuf_serializer_rejects_legacy_meta_float_values() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = YaraFile(
        rules=[
            Rule(
                name="bad_meta_float",
                meta=[Meta("score", cast(Any, 1.5))],
                condition=BooleanLiteral(value=True),
            ),
        ],
    )

    with pytest.raises(
        SerializationError,
        match="Meta value must be a string, integer, or boolean",
    ):
        serializer.serialize(ast)


def test_protobuf_serializer_preserves_meta_entry_float_values() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = YaraFile(
        rules=[
            Rule(
                name="meta_entry_float",
                meta=[MetaEntry.from_key_value("score", 1.5)],
                condition=BooleanLiteral(value=True),
            ),
        ],
    )

    restored = serializer.deserialize(binary_data=serializer.serialize(ast))

    assert restored.rules[0].meta[0].value == 1.5


def test_protobuf_serializer_preserves_scoped_meta_float_values() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    scoped_meta = Meta("score", cast(Any, 1.5))
    cast(Any, scoped_meta).scope = MetaScope.PRIVATE
    ast = YaraFile(
        rules=[
            Rule(
                name="scoped_meta_float",
                meta=[scoped_meta],
                condition=BooleanLiteral(value=True),
            ),
        ],
    )

    restored = serializer.deserialize(binary_data=serializer.serialize(ast))
    restored_meta = restored.rules[0].meta[0]

    assert isinstance(restored_meta, MetaEntry)
    assert restored_meta.scope == MetaScope.PRIVATE
    assert restored_meta.value == 1.5


def test_protobuf_deserializer_rejects_empty_meta_values() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    pb_file = yara_ast_pb2.YaraFile()
    pb_rule = pb_file.rules.add()
    pb_rule.name = "empty_meta"
    pb_rule.condition.boolean_literal.value = True
    pb_meta = pb_rule.meta_entries.add()
    pb_meta.key = "score"
    pb_meta.value.SetInParent()

    with pytest.raises(SerializationError, match="Meta value is missing a value"):
        serializer.deserialize(binary_data=pb_file.SerializeToString())

    legacy_pb_file = yara_ast_pb2.YaraFile()
    legacy_pb_rule = legacy_pb_file.rules.add()
    legacy_pb_rule.name = "empty_legacy_meta"
    legacy_pb_rule.condition.boolean_literal.value = True
    legacy_pb_rule.meta["score"].SetInParent()

    with pytest.raises(SerializationError, match="Meta value is missing a value"):
        serializer.deserialize(binary_data=legacy_pb_file.SerializeToString())


def test_protobuf_serializer_rejects_unsupported_meta_and_pragma_parameter_values() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    bad_meta_value = cast(Any, ["not", "a", "scalar"])
    ast = YaraFile(
        rules=[
            Rule(
                name="bad_meta_value",
                meta=[Meta("labels", bad_meta_value)],
                condition=BooleanLiteral(value=True),
            ),
        ],
    )

    with pytest.raises(
        SerializationError,
        match="Meta value must be a string, integer, or boolean",
    ):
        serializer.serialize(ast)

    bad_parameter_value = cast(Any, {"nested": "value"})
    pragma_ast = YaraFile(
        pragmas=[CustomPragma("vendor", parameters={"config": bad_parameter_value})],
    )

    with pytest.raises(
        SerializationError,
        match="Pragma parameter value must be a string, integer, boolean, or finite float",
    ):
        serializer.serialize(pragma_ast)


def test_protobuf_serializer_rejects_non_string_meta_and_pragma_parameter_keys() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = YaraFile(
        rules=[
            Rule(
                name="bad_meta_key",
                meta=[Meta(cast(Any, 123), "value")],
                condition=BooleanLiteral(value=True),
            ),
        ],
    )

    with pytest.raises(SerializationError, match="Meta key must be a string"):
        serializer.serialize(ast)

    ast_with_invalid_meta_key = YaraFile(
        rules=[
            Rule(
                name="invalid_meta_key",
                meta=[Meta("bad-name", "value")],
                condition=BooleanLiteral(value=True),
            ),
        ],
    )

    with pytest.raises(SerializationError, match="Invalid meta identifier"):
        serializer.serialize(ast_with_invalid_meta_key)

    bad_parameters = {cast(Any, 1): "value"}
    pragma_ast = YaraFile(pragmas=[CustomPragma("vendor", parameters=bad_parameters)])

    with pytest.raises(SerializationError, match="Pragma parameters keys must be strings"):
        serializer.serialize(pragma_ast)


@pytest.mark.parametrize(
    ("ast", "message"),
    [
        (YaraFile(imports=[Import(cast(Any, 123))]), "Import module must be a string"),
        (
            YaraFile(imports=[Import("pe", alias=cast(Any, 123))]),
            "Import alias must be a string",
        ),
        (YaraFile(includes=[Include(cast(Any, 123))]), "Include path must be a string"),
        (
            YaraFile(rules=[Rule(cast(Any, 123), condition=BooleanLiteral(True))]),
            "Rule name must be a string",
        ),
        (
            YaraFile(
                rules=[
                    Rule(
                        name="bad_tag",
                        tags=[Tag(cast(Any, 123))],
                        condition=BooleanLiteral(True),
                    ),
                ],
            ),
            "Tag name must be a string",
        ),
    ],
)
def test_protobuf_serializer_rejects_non_string_file_and_rule_fields(
    ast: YaraFile,
    message: str,
) -> None:
    serializer = ProtobufSerializer(include_metadata=False)

    with pytest.raises(SerializationError, match=message):
        serializer.serialize(ast)


@pytest.mark.parametrize(
    ("ast", "message"),
    [
        (
            YaraFile(rules=[Rule("\ud800", condition=BooleanLiteral(True))]),
            "Rule name must be UTF-8 encodable",
        ),
        (
            YaraFile(
                rules=[Rule("bad_meta", meta=[Meta("k", "\ud800")], condition=BooleanLiteral(True))]
            ),
            "Meta value must be UTF-8 encodable",
        ),
        (
            YaraFile(
                rules=[
                    Rule(
                        "bad_plain_string",
                        strings=[PlainString("$a", value="\ud800")],
                        condition=BooleanLiteral(True),
                    ),
                ],
            ),
            "PlainString value must be UTF-8 encodable",
        ),
        (
            YaraFile(rules=[Rule("bad_string_literal", condition=StringLiteral("\ud800"))]),
            "StringLiteral value must be UTF-8 encodable",
        ),
        (
            YaraFile(
                rules=[
                    Rule(
                        "bad_modifier_value",
                        strings=[
                            PlainString(
                                "$a",
                                value="abc",
                                modifiers=[StringModifier.from_name_value("xor", "\ud800")],
                            ),
                        ],
                        condition=BooleanLiteral(True),
                    ),
                ],
            ),
            "String modifier value text must be UTF-8 encodable",
        ),
        (
            YaraFile(
                rules=[
                    Rule(
                        "bad_string_set",
                        condition=OfExpression("any", "\ud800"),
                    ),
                ],
            ),
            "OfExpression string_set must be UTF-8 encodable",
        ),
    ],
)
def test_protobuf_serializer_rejects_non_utf8_encodable_strings(
    ast: YaraFile,
    message: str,
) -> None:
    serializer = ProtobufSerializer(include_metadata=False)

    with pytest.raises(SerializationError, match=message):
        serializer.serialize(ast)


@pytest.mark.parametrize(
    ("string_def", "message"),
    [
        (
            PlainString(identifier=cast(Any, 123), value="abc"),
            "PlainString identifier must be a string",
        ),
        (
            PlainString(identifier="$a", value=cast(Any, ["abc"])),
            "PlainString value must be a string or bytes",
        ),
        (
            PlainString(identifier="$a", value="abc", raw_bytes=cast(Any, "abc")),
            "PlainString raw_bytes must be bytes or None",
        ),
        (
            PlainString(identifier="$a", value=b"abc", raw_bytes=b"def"),
            "PlainString raw_bytes must match bytes value",
        ),
        (
            HexString(identifier=cast(Any, 123), tokens=[HexByte(0x90)]),
            "HexString identifier must be a string",
        ),
        (
            RegexString(identifier=cast(Any, 123), regex="abc"),
            "RegexString identifier must be a string",
        ),
        (
            RegexString(identifier="$r", regex=cast(Any, 123)),
            "RegexString regex must be a string",
        ),
        (
            RegexString(identifier="$r", regex=""),
            "RegexString regex must not be empty",
        ),
    ],
)
def test_protobuf_serializer_rejects_invalid_string_definition_fields(
    string_def: Any,
    message: str,
) -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = YaraFile(
        rules=[
            Rule(
                name="bad_string_fields",
                strings=[string_def],
                condition=BooleanLiteral(value=True),
            ),
        ],
    )

    with pytest.raises(SerializationError, match=message):
        serializer.serialize(ast)


@pytest.mark.parametrize("invalid_flag", [cast(Any, "yes"), cast(Any, 1)])
def test_protobuf_serializer_rejects_invalid_anonymous_string_flags(
    invalid_flag: Any,
) -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    invalid_cases: list[tuple[Any, str]] = [
        (
            PlainString(identifier="$a", value="abc", is_anonymous=invalid_flag),
            "PlainString is_anonymous must be a boolean",
        ),
        (
            HexString(
                identifier="$h",
                tokens=[HexByte(0x90)],
                is_anonymous=invalid_flag,
            ),
            "HexString is_anonymous must be a boolean",
        ),
        (
            RegexString(identifier="$r", regex="abc", is_anonymous=invalid_flag),
            "RegexString is_anonymous must be a boolean",
        ),
    ]

    for string_def, message in invalid_cases:
        ast = YaraFile(
            rules=[
                Rule(
                    name="bad_anonymous_flag",
                    strings=[string_def],
                    condition=BooleanLiteral(value=True),
                ),
            ],
        )

        with pytest.raises(SerializationError, match=message):
            serializer.serialize(ast)


def test_protobuf_serializer_rejects_empty_hex_string() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    empty_hex = HexString(identifier="$h", tokens=[])
    ast = YaraFile(
        rules=[
            Rule(
                name="empty_hex_string",
                strings=[empty_hex],
                condition=BooleanLiteral(True),
            )
        ]
    )

    with pytest.raises(SerializationError, match="HexString must contain at least one token"):
        serializer.serialize(ast)


def test_protobuf_deserializer_rejects_empty_hex_string() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    pb_file = yara_ast_pb2.YaraFile()
    pb_rule = pb_file.rules.add()
    pb_rule.name = "empty_hex_string"
    pb_rule.condition.boolean_literal.value = True
    pb_string = pb_rule.strings.add()
    pb_string.identifier = "$h"
    pb_string.hex.SetInParent()

    with pytest.raises(SerializationError, match="HexString must contain at least one token"):
        serializer.deserialize(binary_data=pb_file.SerializeToString())


@pytest.mark.parametrize("value", ["", b""])
def test_protobuf_serializer_rejects_empty_plain_string(value: str | bytes) -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = YaraFile(
        rules=[
            Rule(
                name="empty_plain_string",
                strings=[PlainString(identifier="$a", value=value)],
                condition=BooleanLiteral(True),
            )
        ],
    )

    with pytest.raises(SerializationError, match="PlainString must contain at least one byte"):
        serializer.serialize(ast)


@pytest.mark.parametrize("use_raw_value", [False, True])
def test_protobuf_deserializer_rejects_empty_plain_string(use_raw_value: bool) -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    pb_file = yara_ast_pb2.YaraFile()
    pb_rule = pb_file.rules.add()
    pb_rule.name = "empty_plain_string"
    pb_rule.condition.boolean_literal.value = True
    pb_string = pb_rule.strings.add()
    pb_string.identifier = "$a"
    if use_raw_value:
        pb_string.plain.raw_value = b""
    else:
        pb_string.plain.value = ""

    with pytest.raises(SerializationError, match="PlainString must contain at least one byte"):
        serializer.deserialize(binary_data=pb_file.SerializeToString())


def test_protobuf_deserializer_rejects_empty_regex_string() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    pb_file = yara_ast_pb2.YaraFile()
    pb_rule = pb_file.rules.add()
    pb_rule.name = "empty_regex_string"
    pb_rule.condition.boolean_literal.value = True
    pb_string = pb_rule.strings.add()
    pb_string.identifier = "$r"
    pb_string.regex.SetInParent()

    with pytest.raises(SerializationError, match="RegexString regex must not be empty"):
        serializer.deserialize(binary_data=pb_file.SerializeToString())


@pytest.mark.parametrize(
    ("tokens", "message"),
    [
        ([HexJump(1, 2), HexByte(0x90)], "HexJump cannot appear"),
        ([HexByte(0x90), HexJump(1, 2)], "HexJump cannot appear"),
        (
            [HexAlternative([[HexByte(0x90), HexJump(1, None), HexWildcard()]])],
            "Unbounded HexJump is not allowed inside hex alternatives",
        ),
    ],
)
def test_protobuf_serializer_rejects_unemittable_hex_token_sequences(
    tokens: list[Any],
    message: str,
) -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = YaraFile(
        rules=[
            Rule(
                name="bad_hex_sequence",
                strings=[HexString(identifier="$h", tokens=tokens)],
                condition=BooleanLiteral(True),
            )
        ],
    )

    with pytest.raises(SerializationError, match=message):
        serializer.serialize(ast)


def _add_leading_protobuf_hex_jump(pb_hex: Any) -> None:
    pb_hex.tokens.add().jump.min_jump = 1
    pb_hex.tokens.add().byte.value = "90"


def _add_trailing_protobuf_hex_jump(pb_hex: Any) -> None:
    pb_hex.tokens.add().byte.value = "90"
    pb_hex.tokens.add().jump.min_jump = 1


def _add_unbounded_protobuf_hex_jump_in_alternative(pb_hex: Any) -> None:
    pb_alternative = pb_hex.tokens.add().alternative.alternatives.add()
    pb_alternative.tokens.add().byte.value = "90"
    pb_alternative.tokens.add().jump.min_jump = 1
    pb_alternative.tokens.add().wildcard.SetInParent()


@pytest.mark.parametrize(
    ("hex_token_builder", "message"),
    [
        (
            _add_leading_protobuf_hex_jump,
            "HexJump cannot appear",
        ),
        (
            _add_trailing_protobuf_hex_jump,
            "HexJump cannot appear",
        ),
        (
            _add_unbounded_protobuf_hex_jump_in_alternative,
            "Unbounded HexJump is not allowed inside hex alternatives",
        ),
    ],
)
def test_protobuf_deserializer_rejects_unemittable_hex_token_sequences(
    hex_token_builder: Callable[[Any], Any],
    message: str,
) -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    pb_file = yara_ast_pb2.YaraFile()
    pb_rule = pb_file.rules.add()
    pb_rule.name = "bad_hex_sequence"
    pb_rule.condition.boolean_literal.value = True
    pb_string = pb_rule.strings.add()
    pb_string.identifier = "$h"
    hex_token_builder(pb_string.hex)

    with pytest.raises(SerializationError, match=message):
        serializer.deserialize(binary_data=pb_file.SerializeToString())


def _invalid_modifier_and_hex_container_cases() -> list[tuple[YaraFile, str]]:
    bad_rule_modifiers = Rule("bad_rule_modifiers", condition=BooleanLiteral(True))
    cast(Any, bad_rule_modifiers).modifiers = False

    bad_rule_modifier = Rule("bad_rule_modifier", condition=BooleanLiteral(True))
    cast(Any, bad_rule_modifier).modifiers = [object()]

    invalid_rule_modifier_name = Rule(
        "invalid_rule_modifier_name",
        modifiers=["bad modifier"],
        condition=BooleanLiteral(True),
    )

    bad_extern_rule_modifiers = ExternRule("ExternalRule")
    cast(Any, bad_extern_rule_modifiers).modifiers = False

    bad_extern_rule_modifier = ExternRule("ExternalRule")
    cast(Any, bad_extern_rule_modifier).modifiers = [object()]

    invalid_extern_rule_modifier_name = ExternRule("ExternalRule")
    cast(Any, invalid_extern_rule_modifier_name).modifiers = ["bad modifier"]

    bad_plain_modifiers = PlainString(identifier="$a", value="abc")
    cast(Any, bad_plain_modifiers).modifiers = False

    bad_plain_modifier = PlainString(identifier="$a", value="abc")
    cast(Any, bad_plain_modifier).modifiers = [object()]

    bad_hex_tokens = HexString(identifier="$h", tokens=[HexByte(0x90)])
    cast(Any, bad_hex_tokens).tokens = False

    bad_hex_modifiers = HexString(identifier="$h", tokens=[HexByte(0x90)])
    cast(Any, bad_hex_modifiers).modifiers = False

    bad_hex_modifier = HexString(identifier="$h", tokens=[HexByte(0x90)])
    cast(Any, bad_hex_modifier).modifiers = [object()]

    bad_regex_modifiers = RegexString(identifier="$r", regex="abc")
    cast(Any, bad_regex_modifiers).modifiers = False

    bad_regex_modifier = RegexString(identifier="$r", regex="abc")
    cast(Any, bad_regex_modifier).modifiers = [object()]

    bad_alternatives = HexAlternative(alternatives=[[HexByte(0x90)]])
    cast(Any, bad_alternatives).alternatives = False

    return [
        (
            YaraFile(rules=[bad_rule_modifiers]),
            "Rule modifiers must be a list",
        ),
        (
            YaraFile(rules=[bad_rule_modifier]),
            "Rule modifiers item must be RuleModifier or string",
        ),
        (
            YaraFile(rules=[invalid_rule_modifier_name]),
            "Invalid rule modifier identifier",
        ),
        (
            YaraFile(extern_rules=[bad_extern_rule_modifiers]),
            "ExternRule modifiers must be a list",
        ),
        (
            YaraFile(extern_rules=[bad_extern_rule_modifier]),
            "ExternRule modifiers item must be RuleModifier or string",
        ),
        (
            YaraFile(extern_rules=[invalid_extern_rule_modifier_name]),
            "Invalid ExternRule modifier identifier",
        ),
        (
            YaraFile(
                rules=[
                    Rule(
                        "bad_plain_modifiers",
                        strings=[bad_plain_modifiers],
                        condition=BooleanLiteral(True),
                    )
                ],
            ),
            "PlainString modifiers must be a list",
        ),
        (
            YaraFile(
                rules=[
                    Rule(
                        "bad_plain_modifier",
                        strings=[bad_plain_modifier],
                        condition=BooleanLiteral(True),
                    )
                ],
            ),
            "PlainString modifiers item must be StringModifier or string",
        ),
        (
            YaraFile(
                rules=[
                    Rule("bad_hex_tokens", strings=[bad_hex_tokens], condition=BooleanLiteral(True))
                ],
            ),
            "HexString tokens must be a list",
        ),
        (
            YaraFile(
                rules=[
                    Rule(
                        "bad_hex_modifiers",
                        strings=[bad_hex_modifiers],
                        condition=BooleanLiteral(True),
                    )
                ],
            ),
            "HexString modifiers must be a list",
        ),
        (
            YaraFile(
                rules=[
                    Rule(
                        "bad_hex_modifier",
                        strings=[bad_hex_modifier],
                        condition=BooleanLiteral(True),
                    )
                ],
            ),
            "HexString modifiers item must be StringModifier or string",
        ),
        (
            YaraFile(
                rules=[
                    Rule(
                        "bad_regex_modifiers",
                        strings=[bad_regex_modifiers],
                        condition=BooleanLiteral(True),
                    )
                ],
            ),
            "RegexString modifiers must be a list",
        ),
        (
            YaraFile(
                rules=[
                    Rule(
                        "bad_regex_modifier",
                        strings=[bad_regex_modifier],
                        condition=BooleanLiteral(True),
                    )
                ],
            ),
            "RegexString modifiers item must be StringModifier or string",
        ),
        (
            YaraFile(
                rules=[
                    Rule(
                        "bad_alternatives",
                        strings=[
                            HexString(identifier="$h", tokens=[bad_alternatives]),
                        ],
                        condition=BooleanLiteral(True),
                    )
                ],
            ),
            "HexAlternative alternatives must be a list",
        ),
    ]


@pytest.mark.parametrize(("ast", "message"), _invalid_modifier_and_hex_container_cases())
def test_protobuf_serializer_rejects_invalid_modifier_and_hex_container_fields(
    ast: YaraFile,
    message: str,
) -> None:
    serializer = ProtobufSerializer(include_metadata=False)

    with pytest.raises(SerializationError, match=message):
        serializer.serialize(ast)


def test_protobuf_serializer_rejects_malformed_modifier_names() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    bad_rule_modifier = Rule(
        "bad_rule_modifier_name",
        modifiers=[RuleModifier(cast(Any, object()))],
        condition=BooleanLiteral(True),
    )
    bad_extern_rule_modifier = ExternRule(
        "ExternalRule",
        modifiers=[RuleModifier(cast(Any, object()))],
    )
    bad_string_modifier = PlainString(
        identifier="$a",
        value="abc",
        modifiers=[StringModifier(cast(Any, object()))],
    )

    cases = [
        (YaraFile(rules=[bad_rule_modifier]), "Rule modifier name must be a string"),
        (
            YaraFile(extern_rules=[bad_extern_rule_modifier]),
            "ExternRule modifier name must be a string",
        ),
        (
            YaraFile(
                rules=[
                    Rule(
                        "bad_string_modifier_name",
                        strings=[bad_string_modifier],
                        condition=BooleanLiteral(True),
                    )
                ],
            ),
            "String modifier name must be a string",
        ),
    ]

    for ast, message in cases:
        with pytest.raises(SerializationError, match=message):
            serializer.serialize(ast)


@pytest.mark.parametrize(
    "string_def",
    [
        PlainString(identifier="$a", value="abc", modifiers=cast(Any, [""])),
        HexString(identifier="$h", tokens=[HexByte(0x41)], modifiers=cast(Any, [""])),
        RegexString(identifier="$r", regex="abc", modifiers=cast(Any, [""])),
    ],
)
def test_protobuf_serializer_rejects_empty_string_modifier_names(
    string_def: Any,
) -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = YaraFile(
        rules=[
            Rule(
                name="bad_string_modifier",
                strings=[string_def],
                condition=BooleanLiteral(value=True),
            ),
        ],
    )

    with pytest.raises(SerializationError, match="String modifier name must not be empty"):
        serializer.serialize(ast)


@pytest.mark.parametrize("string_kind", ["plain", "hex", "regex"])
def test_protobuf_deserializer_rejects_empty_string_modifier_names(
    string_kind: str,
) -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    pb_file = yara_ast_pb2.YaraFile()
    pb_rule = pb_file.rules.add()
    pb_rule.name = "bad_string_modifier"
    pb_rule.condition.boolean_literal.value = True
    pb_string = pb_rule.strings.add()
    pb_string.identifier = "$a"
    if string_kind == "plain":
        pb_string.plain.value = "abc"
        pb_string.plain.modifiers.add().name = ""
    elif string_kind == "hex":
        pb_string.hex.tokens.add().byte.value = "65"
        pb_string.hex.modifiers.add().name = ""
    elif string_kind == "regex":
        pb_string.regex.regex = "abc"
        pb_string.regex.modifiers.add().name = ""

    with pytest.raises(SerializationError, match="String modifier name must not be empty"):
        serializer.deserialize(binary_data=pb_file.SerializeToString())


@pytest.mark.parametrize(
    ("ast", "message"),
    [
        (
            YaraFile(extern_rules=[ExternRule(cast(Any, 123))]),
            "ExternRule name must be a string",
        ),
        (
            YaraFile(extern_rules=[ExternRule("ExternalRule", namespace=cast(Any, 123))]),
            "ExternRule namespace must be a string",
        ),
        (
            YaraFile(extern_imports=[ExternImport(cast(Any, 123))]),
            "ExternImport module_path must be a string",
        ),
        (
            YaraFile(extern_imports=[ExternImport("external_rules", alias=cast(Any, 123))]),
            "ExternImport alias must be a string",
        ),
        (
            YaraFile(
                extern_imports=[ExternImport("external_rules", rules=cast(Any, ["A", 123]))],
            ),
            "ExternImport rules must be a list of strings",
        ),
        (
            YaraFile(namespaces=[ExternNamespace(cast(Any, 123))]),
            "ExternNamespace name must be a string",
        ),
        (
            YaraFile(
                rules=[
                    Rule(
                        name="bad_pragma_position",
                        pragmas=[InRulePragma(CustomPragma("vendor"), position=cast(Any, 123))],
                        condition=BooleanLiteral(True),
                    ),
                ],
            ),
            "InRulePragma position must be a string",
        ),
    ],
)
def test_protobuf_serializer_rejects_invalid_extern_and_in_rule_pragma_fields(
    ast: YaraFile,
    message: str,
) -> None:
    serializer = ProtobufSerializer(include_metadata=False)

    with pytest.raises(SerializationError, match=message):
        serializer.serialize(ast)


def _invalid_file_container_cases() -> list[tuple[YaraFile, str]]:
    bad_imports = YaraFile(imports=[Import("pe")])
    cast(Any, bad_imports).imports = False

    bad_import = YaraFile(imports=[Import("pe")])
    cast(Any, bad_import).imports = [object()]

    bad_includes = YaraFile(includes=[Include("rules.yar")])
    cast(Any, bad_includes).includes = False

    bad_include = YaraFile(includes=[Include("rules.yar")])
    cast(Any, bad_include).includes = [object()]

    bad_extern_rules = YaraFile(extern_rules=[ExternRule("ExternalRule")])
    cast(Any, bad_extern_rules).extern_rules = False

    bad_extern_rule = YaraFile(extern_rules=[ExternRule("ExternalRule")])
    cast(Any, bad_extern_rule).extern_rules = [object()]

    bad_extern_imports = YaraFile(extern_imports=[ExternImport("external_rules")])
    cast(Any, bad_extern_imports).extern_imports = False

    bad_extern_import = YaraFile(extern_imports=[ExternImport("external_rules")])
    cast(Any, bad_extern_import).extern_imports = [object()]

    bad_pragmas = YaraFile(pragmas=[CustomPragma("vendor")])
    cast(Any, bad_pragmas).pragmas = False

    bad_pragma = YaraFile(pragmas=[CustomPragma("vendor")])
    cast(Any, bad_pragma).pragmas = [object()]

    bad_namespaces = YaraFile(namespaces=[ExternNamespace("corp")])
    cast(Any, bad_namespaces).namespaces = False

    bad_namespace = YaraFile(namespaces=[ExternNamespace("corp")])
    cast(Any, bad_namespace).namespaces = [object()]

    namespace_with_bad_rules = ExternNamespace("corp")
    cast(Any, namespace_with_bad_rules).extern_rules = False

    namespace_with_bad_rule = ExternNamespace("corp")
    cast(Any, namespace_with_bad_rule).extern_rules = [object()]

    bad_rules = YaraFile(rules=[Rule(name="ok")])
    cast(Any, bad_rules).rules = False

    bad_rule = YaraFile(rules=[Rule(name="ok")])
    cast(Any, bad_rule).rules = [object()]

    return [
        (bad_imports, "YaraFile imports must be a list"),
        (bad_import, "YaraFile imports item must be Import"),
        (bad_includes, "YaraFile includes must be a list"),
        (bad_include, "YaraFile includes item must be Include"),
        (bad_extern_rules, "YaraFile extern_rules must be a list"),
        (bad_extern_rule, "YaraFile extern_rules item must be ExternRule"),
        (bad_extern_imports, "YaraFile extern_imports must be a list"),
        (bad_extern_import, "YaraFile extern_imports item must be ExternImport"),
        (bad_pragmas, "YaraFile pragmas must be a list"),
        (bad_pragma, "YaraFile pragmas item must be Pragma"),
        (bad_namespaces, "YaraFile namespaces must be a list"),
        (bad_namespace, "YaraFile namespaces item must be ExternNamespace"),
        (
            YaraFile(namespaces=[namespace_with_bad_rules]),
            "ExternNamespace extern_rules must be a list",
        ),
        (
            YaraFile(namespaces=[namespace_with_bad_rule]),
            "ExternNamespace extern_rules item must be ExternRule",
        ),
        (bad_rules, "YaraFile rules must be a list"),
        (bad_rule, "YaraFile rules item must be Rule"),
    ]


@pytest.mark.parametrize(("ast", "message"), _invalid_file_container_cases())
def test_protobuf_serializer_rejects_invalid_file_container_fields(
    ast: YaraFile,
    message: str,
) -> None:
    serializer = ProtobufSerializer(include_metadata=False)

    with pytest.raises(SerializationError, match=message):
        serializer.serialize(ast)


def _invalid_rule_container_cases() -> list[tuple[Rule, str]]:
    bad_tags = Rule(name="bad_rule_container", condition=BooleanLiteral(True))
    cast(Any, bad_tags).tags = False

    bad_tag = Rule(name="bad_rule_container", condition=BooleanLiteral(True))
    cast(Any, bad_tag).tags = [object()]

    bad_meta = Rule(name="bad_rule_container", condition=BooleanLiteral(True))
    cast(Any, bad_meta).meta = False

    bad_meta_entry = Rule(name="bad_rule_container", condition=BooleanLiteral(True))
    cast(Any, bad_meta_entry).meta = [object()]

    bad_strings = Rule(name="bad_rule_container", condition=BooleanLiteral(True))
    cast(Any, bad_strings).strings = False

    bad_string = Rule(name="bad_rule_container", condition=BooleanLiteral(True))
    cast(Any, bad_string).strings = [object()]

    bad_pragmas = Rule(name="bad_rule_container", condition=BooleanLiteral(True))
    cast(Any, bad_pragmas).pragmas = False

    bad_pragma = Rule(name="bad_rule_container", condition=BooleanLiteral(True))
    cast(Any, bad_pragma).pragmas = [object()]

    return [
        (bad_tags, "Rule tags must be a list"),
        (bad_tag, "Rule tags item must be Tag"),
        (bad_meta, "Rule meta must be a list"),
        (bad_meta_entry, "Rule meta item must be Meta or MetaEntry"),
        (bad_strings, "Rule strings must be a list"),
        (bad_string, "Rule strings item must be StringDefinition"),
        (bad_pragmas, "Rule pragmas must be a list"),
        (bad_pragma, "Rule pragmas item must be InRulePragma"),
    ]


@pytest.mark.parametrize(("rule", "message"), _invalid_rule_container_cases())
def test_protobuf_serializer_rejects_invalid_rule_container_fields(
    rule: Rule,
    message: str,
) -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = YaraFile(rules=[rule])

    with pytest.raises(SerializationError, match=message):
        serializer.serialize(ast)


def _custom_pragma_with_parameters(parameters: Any) -> CustomPragma:
    pragma = CustomPragma("vendor")
    cast(Any, pragma).parameters = parameters
    return pragma


@pytest.mark.parametrize(
    ("pragma", "message"),
    [
        (CustomPragma(cast(Any, 123)), "Pragma name must be a string"),
        (
            CustomPragma("vendor", arguments=cast(Any, "on")),
            "Pragma arguments must be a list of strings",
        ),
        (
            CustomPragma("vendor", arguments=cast(Any, ["on", 1])),
            "Pragma arguments must be a list of strings",
        ),
        (
            _custom_pragma_with_parameters(False),
            "Pragma parameters must be a mapping",
        ),
        (
            _custom_pragma_with_parameters([("level", 1)]),
            "Pragma parameters must be a mapping",
        ),
        (DefineDirective(cast(Any, 123)), "Pragma macro_name must be a string"),
        (
            DefineDirective("FLAG", macro_value=cast(Any, 123)),
            "Pragma macro_value must be a string",
        ),
        (
            ConditionalDirective(PragmaType.IFDEF, condition=cast(Any, 123)),
            "Pragma condition must be a string",
        ),
        (CustomPragma("bad-name"), "Invalid pragma identifier"),
        (DefineDirective("bad-name"), "Invalid pragma macro identifier"),
        (UndefDirective("bad-name"), "Invalid pragma macro identifier"),
        (
            ConditionalDirective(PragmaType.IFDEF, "bad-name"),
            "Invalid pragma condition identifier",
        ),
    ],
)
def test_protobuf_serializer_rejects_invalid_pragma_fields(
    pragma: Any,
    message: str,
) -> None:
    serializer = ProtobufSerializer(include_metadata=False)

    with pytest.raises(SerializationError, match=message):
        serializer.serialize(YaraFile(pragmas=[pragma]))


@pytest.mark.parametrize(
    ("pragma_type", "field_name", "field_value", "message"),
    [
        ("custom", "name", "bad-name", "Invalid pragma identifier"),
        ("define", "macro_name", "bad-name", "Invalid pragma macro identifier"),
        ("undef", "macro_name", "bad-name", "Invalid pragma macro identifier"),
        ("ifdef", "condition", "bad-name", "Invalid pragma condition identifier"),
    ],
)
def test_protobuf_deserializer_rejects_invalid_pragma_identifiers(
    pragma_type: str,
    field_name: str,
    field_value: str,
    message: str,
) -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    pb_file = yara_ast_pb2.YaraFile()
    pb_pragma = pb_file.pragmas.add()
    pb_pragma.pragma_type = pragma_type
    pb_pragma.name = pragma_type
    pb_pragma.scope = "file"
    setattr(pb_pragma, field_name, field_value)
    if pragma_type == "define":
        pb_pragma.macro_value = "1"

    with pytest.raises(SerializationError, match=message):
        serializer.deserialize(binary_data=pb_file.SerializeToString())


def test_protobuf_serializer_rejects_invalid_pragma_type() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    pragma = CustomPragma("vendor")
    cast(Any, pragma).pragma_type = 123

    with pytest.raises(SerializationError, match="Pragma pragma_type must be a string"):
        serializer.serialize(YaraFile(pragmas=[pragma]))


def test_protobuf_serializer_rejects_empty_pragma_type() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    pragma = CustomPragma("vendor")
    cast(Any, pragma).pragma_type = ""

    with pytest.raises(SerializationError, match="Pragma pragma_type must not be empty"):
        serializer.serialize(YaraFile(pragmas=[pragma]))


def test_protobuf_serializer_rejects_unknown_pragma_type() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    pragma = CustomPragma("vendor")
    cast(Any, pragma).pragma_type = "vendor"

    with pytest.raises(SerializationError, match="Pragma pragma_type must be a valid pragma type"):
        serializer.serialize(YaraFile(pragmas=[pragma]))


@pytest.mark.parametrize(
    ("ast", "message"),
    [
        (YaraFile(imports=[Import("")]), "Import module must not be empty"),
        (YaraFile(imports=[Import("   ")]), "Import module must not be empty"),
        (YaraFile(includes=[Include("")]), "Include path must not be empty"),
        (YaraFile(includes=[Include("\t")]), "Include path must not be empty"),
        (YaraFile(rules=[Rule("", condition=BooleanLiteral(True))]), "Rule name must not be empty"),
        (
            YaraFile(rules=[Rule("   ", condition=BooleanLiteral(True))]),
            "Rule name must not be empty",
        ),
        (
            YaraFile(rules=[Rule("bad-name", condition=BooleanLiteral(True))]),
            "Invalid rule identifier",
        ),
        (
            YaraFile(
                rules=[
                    Rule("duplicate", condition=BooleanLiteral(True)),
                    Rule("duplicate", condition=BooleanLiteral(False)),
                ]
            ),
            "Duplicate rule identifier",
        ),
        (
            YaraFile(rules=[Rule("r", tags=[Tag("")], condition=BooleanLiteral(True))]),
            "Tag name must not be empty",
        ),
        (
            YaraFile(rules=[Rule("r", tags=[Tag("   ")], condition=BooleanLiteral(True))]),
            "Tag name must not be empty",
        ),
        (
            YaraFile(rules=[Rule("r", tags=[Tag("bad-name")], condition=BooleanLiteral(True))]),
            "Invalid tag identifier",
        ),
        (
            YaraFile(
                rules=[
                    Rule(
                        "duplicate_tag",
                        tags=[Tag("packed"), Tag("packed")],
                        condition=BooleanLiteral(True),
                    )
                ]
            ),
            "Duplicate tag identifier",
        ),
        (
            YaraFile(
                rules=[
                    Rule(
                        "r",
                        strings=[PlainString(identifier="", value="abc")],
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
                        "r",
                        strings=[PlainString(identifier="   ", value="abc")],
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
                        "r",
                        strings=[HexString(identifier="", tokens=[HexByte(0x41)])],
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
                        "r",
                        strings=[RegexString(identifier="", regex="abc")],
                        condition=BooleanLiteral(True),
                    )
                ]
            ),
            "RegexString identifier must not be empty",
        ),
        (YaraFile(extern_rules=[ExternRule("")]), "ExternRule name must not be empty"),
        (
            YaraFile(extern_rules=[ExternRule("ExternalRule", namespace="")]),
            "ExternRule namespace must not be empty",
        ),
        (
            YaraFile(extern_imports=[ExternImport("")]),
            "ExternImport module_path must not be empty",
        ),
        (
            YaraFile(extern_imports=[ExternImport("   ")]),
            "ExternImport module_path must not be empty",
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
            YaraFile(namespaces=[ExternNamespace("")]),
            "ExternNamespace name must not be empty",
        ),
        (YaraFile(extern_rules=[ExternRule("bad-name")]), "Invalid extern rule identifier"),
        (
            YaraFile(extern_rules=[ExternRule("ExternalRule", namespace="bad-name")]),
            "Invalid namespace identifier",
        ),
        (
            YaraFile(extern_imports=[ExternImport("external", rules=["bad-name"])]),
            "Invalid extern rule identifier",
        ),
        (YaraFile(namespaces=[ExternNamespace("bad-name")]), "Invalid namespace identifier"),
        (
            YaraFile(extern_rules=[ExternRule("ExternalRule"), ExternRule("ExternalRule")]),
            "Duplicate extern rule identifier",
        ),
        (
            YaraFile(
                namespaces=[
                    ExternNamespace(
                        "corp",
                        extern_rules=[ExternRule("ExternalRule"), ExternRule("ExternalRule")],
                    )
                ],
            ),
            "Duplicate extern rule identifier",
        ),
    ],
)
def test_protobuf_serializer_rejects_empty_top_level_identifier_fields(
    ast: YaraFile,
    message: str,
) -> None:
    serializer = ProtobufSerializer(include_metadata=False)

    with pytest.raises(SerializationError, match=message):
        serializer.serialize(ast)


@pytest.mark.parametrize(
    ("payload_kind", "message"),
    [
        ("import", "Import module must not be empty"),
        ("import_whitespace", "Import module must not be empty"),
        ("include", "Include path must not be empty"),
        ("include_whitespace", "Include path must not be empty"),
        ("rule", "Rule name must not be empty"),
        ("rule_whitespace", "Rule name must not be empty"),
        ("rule_invalid", "Invalid rule identifier"),
        ("rule_duplicate", "Duplicate rule identifier"),
        ("tag", "Tag name must not be empty"),
        ("tag_whitespace", "Tag name must not be empty"),
        ("tag_invalid", "Invalid tag identifier"),
        ("tag_duplicate", "Duplicate tag identifier"),
        ("string", "PlainString identifier must not be empty"),
        ("string_whitespace", "PlainString identifier must not be empty"),
        ("extern_rule", "ExternRule name must not be empty"),
        ("extern_rule_invalid", "Invalid extern rule identifier"),
        ("extern_rule_namespace_invalid", "Invalid namespace identifier"),
        ("extern_rule_duplicate", "Duplicate extern rule identifier"),
        ("extern_import", "ExternImport module_path must not be empty"),
        ("extern_import_whitespace", "ExternImport module_path must not be empty"),
        ("extern_import_rule_invalid", "Invalid extern rule identifier"),
        ("namespace", "ExternNamespace name must not be empty"),
        ("namespace_invalid", "Invalid namespace identifier"),
        ("namespace_extern_duplicate", "Duplicate extern rule identifier"),
    ],
)
def test_protobuf_deserializer_rejects_empty_top_level_identifier_fields(
    payload_kind: str,
    message: str,
) -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    pb_file = yara_ast_pb2.YaraFile()
    if payload_kind == "import":
        pb_file.imports.add()
    elif payload_kind == "import_whitespace":
        pb_file.imports.add().module = "   "
    elif payload_kind == "include":
        pb_file.includes.add()
    elif payload_kind == "include_whitespace":
        pb_file.includes.add().path = "\t"
    elif payload_kind == "rule":
        pb_file.rules.add().condition.boolean_literal.value = True
    elif payload_kind == "rule_whitespace":
        pb_rule = pb_file.rules.add()
        pb_rule.name = "   "
        pb_rule.condition.boolean_literal.value = True
    elif payload_kind == "rule_invalid":
        pb_rule = pb_file.rules.add()
        pb_rule.name = "bad-name"
        pb_rule.condition.boolean_literal.value = True
    elif payload_kind == "rule_duplicate":
        first_rule = pb_file.rules.add()
        first_rule.name = "duplicate"
        first_rule.condition.boolean_literal.value = True
        second_rule = pb_file.rules.add()
        second_rule.name = "duplicate"
        second_rule.condition.boolean_literal.value = False
    elif payload_kind == "tag":
        pb_rule = pb_file.rules.add()
        pb_rule.name = "r"
        pb_rule.condition.boolean_literal.value = True
        pb_rule.tags.add()
    elif payload_kind == "tag_whitespace":
        pb_rule = pb_file.rules.add()
        pb_rule.name = "r"
        pb_rule.condition.boolean_literal.value = True
        pb_rule.tags.add().name = "   "
    elif payload_kind == "tag_invalid":
        pb_rule = pb_file.rules.add()
        pb_rule.name = "r"
        pb_rule.condition.boolean_literal.value = True
        pb_rule.tags.add().name = "bad-name"
    elif payload_kind == "tag_duplicate":
        pb_rule = pb_file.rules.add()
        pb_rule.name = "duplicate_tag"
        pb_rule.condition.boolean_literal.value = True
        pb_rule.tags.add().name = "packed"
        pb_rule.tags.add().name = "packed"
    elif payload_kind == "string":
        pb_rule = pb_file.rules.add()
        pb_rule.name = "r"
        pb_rule.condition.boolean_literal.value = True
        pb_rule.strings.add().plain.value = "abc"
    elif payload_kind == "string_whitespace":
        pb_rule = pb_file.rules.add()
        pb_rule.name = "r"
        pb_rule.condition.boolean_literal.value = True
        pb_string = pb_rule.strings.add()
        pb_string.identifier = "   "
        pb_string.plain.value = "abc"
    elif payload_kind == "extern_rule":
        pb_file.extern_rules.add()
    elif payload_kind == "extern_rule_invalid":
        pb_file.extern_rules.add().name = "bad-name"
    elif payload_kind == "extern_rule_namespace_invalid":
        pb_extern_rule = pb_file.extern_rules.add()
        pb_extern_rule.name = "ExternalRule"
        pb_extern_rule.namespace = "bad-name"
    elif payload_kind == "extern_rule_duplicate":
        pb_file.extern_rules.add().name = "ExternalRule"
        pb_file.extern_rules.add().name = "ExternalRule"
    elif payload_kind == "extern_import":
        pb_file.extern_imports.add()
    elif payload_kind == "extern_import_whitespace":
        pb_file.extern_imports.add().module_path = "   "
    elif payload_kind == "extern_import_rule_invalid":
        pb_import = pb_file.extern_imports.add()
        pb_import.module_path = "external"
        pb_import.rules.append("bad-name")
    elif payload_kind == "namespace":
        pb_file.namespaces.add()
    elif payload_kind == "namespace_invalid":
        pb_file.namespaces.add().name = "bad-name"
    elif payload_kind == "namespace_extern_duplicate":
        pb_namespace = pb_file.namespaces.add()
        pb_namespace.name = "corp"
        pb_namespace.extern_rules.add().name = "ExternalRule"
        pb_namespace.extern_rules.add().name = "ExternalRule"

    with pytest.raises(SerializationError, match=message):
        serializer.deserialize(binary_data=pb_file.SerializeToString())


def test_protobuf_serializer_rejects_empty_extern_import_rules() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    for rule_name in ("", "   ", "\t"):
        ast = YaraFile(extern_imports=[ExternImport("external", rules=[rule_name])])
        with pytest.raises(SerializationError, match="ExternImport rules item must not be empty"):
            serializer.serialize(ast)


def test_protobuf_serializer_accepts_qualified_extern_import_rules() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = YaraFile(extern_imports=[ExternImport("external", rules=["corp.RemoteRule"])])

    restored = serializer.deserialize(binary_data=serializer.serialize(ast))

    assert restored.extern_imports[0].rules == ["corp.RemoteRule"]


def test_protobuf_deserializer_rejects_empty_extern_import_rules() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    pb_file = yara_ast_pb2.YaraFile()
    pb_import = pb_file.extern_imports.add()
    pb_import.module_path = "external"
    for rule_name in ("", "   ", "\t"):
        del pb_import.rules[:]
        pb_import.rules.append(rule_name)
        with pytest.raises(SerializationError, match="ExternImport rules item must not be empty"):
            serializer.deserialize(binary_data=pb_file.SerializeToString())


def test_protobuf_deserializer_rejects_empty_extern_import_alias() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    pb_file = yara_ast_pb2.YaraFile()
    pb_import = pb_file.extern_imports.add()
    pb_import.module_path = "external"

    for alias in ("   ", "\t"):
        pb_import.alias = alias
        with pytest.raises(SerializationError, match="ExternImport alias must not be empty"):
            serializer.deserialize(binary_data=pb_file.SerializeToString())


@pytest.mark.parametrize(
    ("payload_kind", "message"),
    [
        ("import_alias", "Import alias must not be empty"),
        ("extern_rule_namespace", "ExternRule namespace must not be empty"),
        ("extern_rule_reference_namespace", "ExternRuleReference namespace must not be empty"),
    ],
)
def test_protobuf_deserializer_rejects_whitespace_optional_identifiers(
    payload_kind: str,
    message: str,
) -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    pb_file = yara_ast_pb2.YaraFile()

    if payload_kind == "import_alias":
        pb_import = pb_file.imports.add()
        pb_import.module = "pe"
        pb_import.alias = "   "
    elif payload_kind == "extern_rule_namespace":
        pb_extern_rule = pb_file.extern_rules.add()
        pb_extern_rule.name = "ExternalRule"
        pb_extern_rule.namespace = "   "
    else:
        pb_rule = pb_file.rules.add()
        pb_rule.name = "uses_external"
        pb_rule.condition.extern_rule_reference.rule_name = "ExternalRule"
        pb_rule.condition.extern_rule_reference.namespace = "   "

    with pytest.raises(SerializationError, match=message):
        serializer.deserialize(binary_data=pb_file.SerializeToString())


def test_protobuf_serializer_rejects_empty_meta_keys() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = YaraFile(
        rules=[
            Rule(
                name="bad_meta",
                meta=[Meta("", "value")],
                condition=BooleanLiteral(value=True),
            ),
        ],
    )

    with pytest.raises(SerializationError, match="Meta key must not be empty"):
        serializer.serialize(ast)


@pytest.mark.parametrize("legacy_map", [False, True])
def test_protobuf_deserializer_rejects_empty_meta_keys(legacy_map: bool) -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    pb_file = yara_ast_pb2.YaraFile()
    pb_rule = pb_file.rules.add()
    pb_rule.name = "bad_meta"
    pb_rule.condition.boolean_literal.value = True
    if legacy_map:
        pb_rule.meta[""].string_value = "value"
    else:
        pb_meta = pb_rule.meta_entries.add()
        pb_meta.key = ""
        pb_meta.value.string_value = "value"

    with pytest.raises(SerializationError, match="Meta key must not be empty"):
        serializer.deserialize(binary_data=pb_file.SerializeToString())


@pytest.mark.parametrize("legacy_map", [False, True])
def test_protobuf_deserializer_rejects_invalid_meta_keys(legacy_map: bool) -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    pb_file = yara_ast_pb2.YaraFile()
    pb_rule = pb_file.rules.add()
    pb_rule.name = "bad_meta"
    pb_rule.condition.boolean_literal.value = True
    if legacy_map:
        pb_rule.meta["bad-name"].string_value = "value"
    else:
        pb_meta = pb_rule.meta_entries.add()
        pb_meta.key = "bad-name"
        pb_meta.value.string_value = "value"

    with pytest.raises(SerializationError, match="Invalid meta identifier"):
        serializer.deserialize(binary_data=pb_file.SerializeToString())


def test_protobuf_serializer_rejects_empty_pragma_names() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = YaraFile(pragmas=[CustomPragma("")])

    with pytest.raises(SerializationError, match="Pragma name must not be empty"):
        serializer.serialize(ast)


@pytest.mark.parametrize("pragma_type", ["custom", "pragma"])
def test_protobuf_deserializer_rejects_empty_pragma_names(pragma_type: str) -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    pb_file = yara_ast_pb2.YaraFile()
    pb_pragma = pb_file.pragmas.add()
    pb_pragma.pragma_type = pragma_type
    pb_pragma.scope = "file"

    with pytest.raises(SerializationError, match="Pragma name must not be empty"):
        serializer.deserialize(binary_data=pb_file.SerializeToString())


def test_protobuf_deserializer_rejects_empty_pragma_type() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    pb_file = yara_ast_pb2.YaraFile()
    pb_pragma = pb_file.pragmas.add()
    pb_pragma.name = "vendor"
    pb_pragma.scope = "file"

    with pytest.raises(SerializationError, match="Pragma pragma_type must not be empty"):
        serializer.deserialize(binary_data=pb_file.SerializeToString())


def test_protobuf_deserializer_rejects_unknown_pragma_type() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    pb_file = yara_ast_pb2.YaraFile()
    pb_pragma = pb_file.pragmas.add()
    pb_pragma.pragma_type = "vendor"
    pb_pragma.name = "vendor"
    pb_pragma.scope = "file"

    with pytest.raises(SerializationError, match="Pragma pragma_type must be a valid pragma type"):
        serializer.deserialize(binary_data=pb_file.SerializeToString())


def test_protobuf_deserializer_rejects_empty_pragma_scope() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    pb_file = yara_ast_pb2.YaraFile()
    pb_pragma = pb_file.pragmas.add()
    pb_pragma.pragma_type = "custom"
    pb_pragma.name = "vendor"

    with pytest.raises(SerializationError, match="Pragma scope must not be empty"):
        serializer.deserialize(binary_data=pb_file.SerializeToString())


@pytest.mark.parametrize(
    ("pragma", "message"),
    [
        (DefineDirective(""), "Pragma macro_name must not be empty"),
        (UndefDirective(""), "Pragma macro_name must not be empty"),
        (
            ConditionalDirective(PragmaType.IFDEF, condition=""),
            "Pragma condition must not be empty",
        ),
        (
            ConditionalDirective(PragmaType.IFNDEF, condition=""),
            "Pragma condition must not be empty",
        ),
    ],
)
def test_protobuf_serializer_rejects_empty_required_pragma_operands(
    pragma: Any,
    message: str,
) -> None:
    serializer = ProtobufSerializer(include_metadata=False)

    with pytest.raises(SerializationError, match=message):
        serializer.serialize(YaraFile(pragmas=[pragma]))


@pytest.mark.parametrize(
    ("pragma_type", "field_name", "message"),
    [
        ("define", "macro_name", "Pragma macro_name must not be empty"),
        ("undef", "macro_name", "Pragma macro_name must not be empty"),
        ("ifdef", "condition", "Pragma condition must not be empty"),
        ("ifndef", "condition", "Pragma condition must not be empty"),
    ],
)
def test_protobuf_deserializer_rejects_empty_required_pragma_operands(
    pragma_type: str,
    field_name: str,
    message: str,
) -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    pb_file = yara_ast_pb2.YaraFile()
    pb_pragma = pb_file.pragmas.add()
    pb_pragma.pragma_type = pragma_type
    pb_pragma.name = pragma_type
    pb_pragma.scope = "file"
    setattr(pb_pragma, field_name, "")

    with pytest.raises(SerializationError, match=message):
        serializer.deserialize(binary_data=pb_file.SerializeToString())


def test_protobuf_serializer_rejects_empty_in_rule_pragma_positions() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = YaraFile(
        rules=[
            Rule(
                name="bad_pragma_position",
                pragmas=[InRulePragma(CustomPragma("vendor"), position="")],
                condition=BooleanLiteral(True),
            ),
        ],
    )

    with pytest.raises(SerializationError, match="InRulePragma position must not be empty"):
        serializer.serialize(ast)


def test_protobuf_deserializer_rejects_empty_in_rule_pragma_positions() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    pb_file = yara_ast_pb2.YaraFile()
    pb_rule = pb_file.rules.add()
    pb_rule.name = "bad_pragma_position"
    pb_rule.condition.boolean_literal.value = True
    pb_in_rule_pragma = pb_rule.pragmas.add()
    pb_in_rule_pragma.position = ""
    pb_in_rule_pragma.pragma.pragma_type = "custom"
    pb_in_rule_pragma.pragma.name = "vendor"
    pb_in_rule_pragma.pragma.scope = "file"

    with pytest.raises(SerializationError, match="InRulePragma position must not be empty"):
        serializer.deserialize(binary_data=pb_file.SerializeToString())


@pytest.mark.parametrize(
    ("ast", "message"),
    [
        (
            YaraFile(
                rules=[
                    Rule(
                        "bad_modifier",
                        modifiers=cast(Any, [""]),
                        condition=BooleanLiteral(True),
                    )
                ]
            ),
            "Rule modifier name must not be empty",
        ),
        (
            YaraFile(extern_rules=[ExternRule("ExternalRule", modifiers=cast(Any, [""]))]),
            "ExternRule modifier name must not be empty",
        ),
    ],
)
def test_protobuf_serializer_rejects_empty_rule_modifier_names(
    ast: YaraFile,
    message: str,
) -> None:
    serializer = ProtobufSerializer(include_metadata=False)

    with pytest.raises(SerializationError, match=message):
        serializer.serialize(ast)


@pytest.mark.parametrize(
    ("payload_kind", "message"),
    [
        ("rule", "Rule modifier name must not be empty"),
        ("extern_rule", "ExternRule modifier name must not be empty"),
    ],
)
def test_protobuf_deserializer_rejects_empty_rule_modifier_names(
    payload_kind: str,
    message: str,
) -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    pb_file = yara_ast_pb2.YaraFile()
    if payload_kind == "rule":
        pb_rule = pb_file.rules.add()
        pb_rule.name = "bad_modifier"
        pb_rule.modifiers.append("")
        pb_rule.condition.boolean_literal.value = True
    else:
        pb_extern_rule = pb_file.extern_rules.add()
        pb_extern_rule.name = "ExternalRule"
        pb_extern_rule.modifiers.append("")

    with pytest.raises(SerializationError, match=message):
        serializer.deserialize(binary_data=pb_file.SerializeToString())


@pytest.mark.parametrize(
    ("payload_kind", "message"),
    [
        ("rule", "Invalid rule modifier identifier"),
        ("extern_rule", "Invalid ExternRule modifier identifier"),
    ],
)
def test_protobuf_deserializer_rejects_invalid_rule_modifier_names(
    payload_kind: str,
    message: str,
) -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    pb_file = yara_ast_pb2.YaraFile()
    if payload_kind == "rule":
        pb_rule = pb_file.rules.add()
        pb_rule.name = "bad_modifier"
        pb_rule.modifiers.append("bad modifier")
        pb_rule.condition.boolean_literal.value = True
    else:
        pb_extern_rule = pb_file.extern_rules.add()
        pb_extern_rule.name = "ExternalRule"
        pb_extern_rule.modifiers.append("bad modifier")

    with pytest.raises(SerializationError, match=message):
        serializer.deserialize(binary_data=pb_file.SerializeToString())


@pytest.mark.parametrize(
    ("condition", "message"),
    [
        (
            BinaryExpression(BooleanLiteral(True), cast(Any, 123), BooleanLiteral(False)),
            "BinaryExpression operator must be a string",
        ),
        (
            BinaryExpression(BooleanLiteral(True), "", BooleanLiteral(False)),
            "BinaryExpression operator must not be empty",
        ),
        (
            BinaryExpression(BooleanLiteral(True), "???", BooleanLiteral(False)),
            "Invalid binary operator",
        ),
        (
            UnaryExpression(cast(Any, 123), BooleanLiteral(True)),
            "UnaryExpression operator must be a string",
        ),
        (
            UnaryExpression("", BooleanLiteral(True)),
            "UnaryExpression operator must not be empty",
        ),
        (
            UnaryExpression("???", BooleanLiteral(True)),
            "Invalid unary operator",
        ),
        (FunctionCall(cast(Any, 123), []), "FunctionCall function must be a string"),
        (FunctionCall("", []), "FunctionCall function must not be empty"),
        (FunctionCall("bad-name", []), "Invalid function identifier"),
        (
            MemberAccess(Identifier("pe"), cast(Any, 123)),
            "MemberAccess member must be a string",
        ),
        (
            MemberAccess(Identifier("pe"), ""),
            "MemberAccess member must not be empty",
        ),
        (
            MemberAccess(Identifier("pe"), "bad-name"),
            "Invalid member identifier",
        ),
        (
            ForExpression("any", cast(Any, 123), StringIdentifier("$a"), BooleanLiteral(True)),
            "ForExpression variable must be a string",
        ),
        (
            ForExpression("any", "", StringIdentifier("$a"), BooleanLiteral(True)),
            "ForExpression variable must not be empty",
        ),
        (
            ForExpression("any", "bad-name", StringIdentifier("$a"), BooleanLiteral(True)),
            "Invalid local variable identifier: bad-name",
        ),
        (
            ForExpression("50%", "i", SetExpression([IntegerLiteral(1)]), BooleanLiteral(True)),
            "Invalid ForExpression quantifier",
        ),
        (
            ForExpression("-1", "i", SetExpression([IntegerLiteral(1)]), BooleanLiteral(True)),
            "Invalid ForExpression quantifier",
        ),
        (
            OfExpression("0%", ["$a"]),
            "Invalid OfExpression quantifier",
        ),
        (
            OfExpression(101.0, ["$a"]),
            "Invalid OfExpression quantifier",
        ),
        (
            AtExpression(cast(Any, 123), IntegerLiteral(0)),
            "AtExpression string_id must be a string or expression",
        ),
        (
            AtExpression("", IntegerLiteral(0)),
            "AtExpression string_id must not be empty",
        ),
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
        (
            InExpression("$a", IntegerLiteral(0)),
            "InExpression range must be a range expression",
        ),
        (ModuleReference(cast(Any, ["pe"])), "ModuleReference module must be a string"),
        (ModuleReference(""), "ModuleReference module must not be empty"),
        (ModuleReference("bad-name"), "Invalid module identifier"),
        (
            DictionaryAccess(Identifier("items"), cast(Any, 123)),
            "DictionaryAccess key must be a string or expression",
        ),
        (
            DictionaryAccess(Identifier("items"), cast(Any, object())),
            "DictionaryAccess key must be a string or expression",
        ),
        (
            ExternRuleReference(cast(Any, 123)),
            "ExternRuleReference rule_name must be a string",
        ),
        (
            ExternRuleReference(""),
            "ExternRuleReference rule_name must not be empty",
        ),
        (
            ExternRuleReference("ExternalRule", namespace=cast(Any, False)),
            "ExternRuleReference namespace must be a string",
        ),
        (
            ExternRuleReference("ExternalRule", namespace=cast(Any, object())),
            "ExternRuleReference namespace must be a string",
        ),
        (
            ExternRuleReference("ExternalRule", namespace=""),
            "ExternRuleReference namespace must not be empty",
        ),
        (
            StringOperatorExpression(StringLiteral("a"), cast(Any, 123), StringLiteral("b")),
            "StringOperatorExpression operator must be a string",
        ),
        (
            StringOperatorExpression(StringLiteral("a"), "", StringLiteral("b")),
            "StringOperatorExpression operator must not be empty",
        ),
        (
            StringOperatorExpression(StringLiteral("a"), "???", StringLiteral("b")),
            "Invalid string operator",
        ),
    ],
)
def test_protobuf_serializer_rejects_invalid_expression_scalar_fields(
    condition: Any,
    message: str,
) -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = YaraFile(rules=[Rule(name="invalid_expression_scalar", condition=condition)])

    with pytest.raises(SerializationError, match=message):
        serializer.serialize(ast)


def test_protobuf_serializer_accepts_dotted_function_call_names() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = YaraFile(rules=[Rule("dotted_call", condition=FunctionCall("pe.imphash", []))])

    restored = serializer.deserialize(binary_data=serializer.serialize(ast))

    condition = restored.rules[0].condition
    assert isinstance(condition, FunctionCall)
    assert condition.function == "pe.imphash"


@pytest.mark.parametrize(
    ("condition", "message"),
    [
        (Identifier(cast(Any, ["id"])), "Identifier name must be a string"),
        (Identifier(""), "Identifier name must not be empty"),
        (StringIdentifier(cast(Any, 123)), "StringIdentifier name must be a string"),
        (StringIdentifier(""), "StringIdentifier name must not be empty"),
        (StringIdentifier("$bad-name"), "Invalid string reference"),
        (StringIdentifier("$a*"), "Invalid string reference"),
        (StringWildcard(cast(Any, 123)), "StringWildcard pattern must be a string"),
        (StringWildcard(""), "StringWildcard pattern must not be empty"),
        (StringWildcard("$bad-name*"), "Invalid string reference"),
        (StringCount(cast(Any, 123)), "StringCount string_id must be a string"),
        (StringCount(""), "StringCount string_id must not be empty"),
        (StringCount("#a"), "Invalid string reference"),
        (StringCount("$bad-name"), "Invalid string reference"),
        (StringOffset(cast(Any, 123)), "StringOffset string_id must be a string"),
        (StringOffset(""), "StringOffset string_id must not be empty"),
        (StringOffset("@a"), "Invalid string reference"),
        (StringOffset("$bad-name"), "Invalid string reference"),
        (StringLength(cast(Any, 123)), "StringLength string_id must be a string"),
        (StringLength(""), "StringLength string_id must not be empty"),
        (StringLength("!a"), "Invalid string reference"),
        (StringLength("$bad-name"), "Invalid string reference"),
        (IntegerLiteral(cast(Any, True)), "IntegerLiteral value must be an integer"),
        (IntegerLiteral(cast(Any, "1")), "IntegerLiteral value must be an integer"),
        (IntegerLiteral(2**63), "IntegerLiteral value must fit in protobuf int64"),
        (IntegerLiteral(-(2**63) - 1), "IntegerLiteral value must fit in protobuf int64"),
        (StringLiteral(cast(Any, True)), "StringLiteral value must be a string"),
        (RegexLiteral(cast(Any, 123)), "RegexLiteral pattern must be a string"),
        (RegexLiteral(""), "RegexLiteral pattern must not be empty"),
        (RegexLiteral("abc", cast(Any, ["i"])), "RegexLiteral modifiers must be a string"),
        (BooleanLiteral(cast(Any, "true")), "BooleanLiteral value must be a boolean"),
    ],
)
def test_protobuf_serializer_rejects_invalid_expression_leaf_fields(
    condition: Any,
    message: str,
) -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = YaraFile(rules=[Rule(name="invalid_expression_leaf", condition=condition)])

    with pytest.raises(SerializationError, match=message):
        serializer.serialize(ast)


def test_protobuf_serializer_rejects_blank_quantifiers() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    true_expr = BooleanLiteral(True)
    string_set = SetExpression([StringIdentifier("$a")])
    cases: tuple[tuple[Any, str], ...] = (
        (
            ForExpression("any", "i", string_set, true_expr),
            "ForExpression quantifier must not be empty",
        ),
        (
            ForOfExpression("any", ["$a"], true_expr),
            "ForOfExpression quantifier must not be empty",
        ),
        (
            OfExpression("any", ["$a"]),
            "OfExpression quantifier must not be empty",
        ),
    )

    for condition, message in cases:
        cast(Any, condition).quantifier = "   "
        ast = YaraFile(rules=[Rule(name="blank_quantifier", condition=condition)])
        with pytest.raises(SerializationError, match=message):
            serializer.serialize(ast)


def test_protobuf_deserializer_rejects_blank_quantifiers() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    cases: tuple[tuple[str, str], ...] = (
        ("for_expression", "ForExpression quantifier must not be empty"),
        ("for_of_expression", "ForOfExpression quantifier must not be empty"),
        ("of_expression", "OfExpression quantifier must not be empty"),
    )

    for expression_kind, message in cases:
        pb_file = yara_ast_pb2.YaraFile()
        pb_rule = pb_file.rules.add()
        pb_rule.name = "blank_quantifier"
        condition = pb_rule.condition
        if expression_kind == "for_expression":
            condition.for_expression.quantifier = "   "
            condition.for_expression.variable = "i"
            condition.for_expression.iterable.identifier.name = "items"
            condition.for_expression.body.boolean_literal.value = True
        elif expression_kind == "for_of_expression":
            condition.for_of_expression.quantifier = "   "
            condition.for_of_expression.string_set_text = "them"
        else:
            condition.of_expression.quantifier_text = "   "
            condition.of_expression.string_set_text = "them"

        with pytest.raises(SerializationError, match=message):
            serializer.deserialize(binary_data=pb_file.SerializeToString())


@pytest.mark.parametrize(
    ("ast", "message"),
    [
        (
            YaraFile(
                rules=[
                    Rule(
                        "oversized_meta_int",
                        meta=[Meta("score", 2**63)],
                        condition=BooleanLiteral(True),
                    )
                ]
            ),
            "Meta value must fit in protobuf int64",
        ),
        (
            YaraFile(
                rules=[
                    Rule(
                        "oversized_modifier_int",
                        strings=[
                            PlainString(
                                identifier="$a",
                                value="x",
                                modifiers=[StringModifier.from_name_value("xor", 2**63)],
                            )
                        ],
                        condition=StringIdentifier("$a"),
                    )
                ]
            ),
            "String modifier value must fit in protobuf int64",
        ),
        (
            YaraFile(
                rules=[
                    Rule(
                        "oversized_modifier_tuple_int",
                        strings=[
                            PlainString(
                                identifier="$a",
                                value="x",
                                modifiers=[StringModifier.from_name_value("xor", (1, 2**63))],
                            )
                        ],
                        condition=StringIdentifier("$a"),
                    )
                ]
            ),
            "String modifier tuple value must fit in protobuf int64",
        ),
    ],
)
def test_protobuf_serializer_rejects_out_of_range_int64_fields(
    ast: YaraFile,
    message: str,
) -> None:
    serializer = ProtobufSerializer(include_metadata=False)

    with pytest.raises(SerializationError, match=message):
        serializer.serialize(ast)


@pytest.mark.parametrize(
    ("string_set", "message"),
    [
        ([StringIdentifier(cast(Any, False))], "StringIdentifier name must be a string"),
        ([StringLiteral(cast(Any, False))], "StringLiteral value must be a string"),
        ([StringWildcard(cast(Any, False))], "StringWildcard pattern must be a string"),
    ],
)
def test_protobuf_serializer_rejects_invalid_string_set_reference_fields(
    string_set: Any,
    message: str,
) -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = YaraFile(
        rules=[Rule(name="invalid_string_set_reference", condition=OfExpression("any", string_set))]
    )

    with pytest.raises(SerializationError, match=message):
        serializer.serialize(ast)


def test_protobuf_serializer_rejects_empty_string_sets() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    true_expr = BooleanLiteral(True)
    cases: tuple[tuple[Any, str], ...] = (
        (
            ForOfExpression("any", "", true_expr),
            "ForOfExpression string_set must contain values",
        ),
        (
            ForOfExpression("any", "   ", true_expr),
            "ForOfExpression string_set must contain values",
        ),
        (
            ForOfExpression("any", [], true_expr),
            "ForOfExpression string_set must contain values",
        ),
        (
            ForOfExpression("any", [""], true_expr),
            "ForOfExpression string_set must contain values",
        ),
        (
            OfExpression("any", ""),
            "OfExpression string_set must contain values",
        ),
        (
            OfExpression("any", "   "),
            "OfExpression string_set must contain values",
        ),
        (
            OfExpression("any", []),
            "OfExpression string_set must contain values",
        ),
        (
            OfExpression("any", ["   "]),
            "OfExpression string_set must contain values",
        ),
    )

    for condition, message in cases:
        ast = YaraFile(rules=[Rule(name="empty_string_set", condition=condition)])
        with pytest.raises(SerializationError, match=message):
            serializer.serialize(ast)


def test_protobuf_deserializer_rejects_empty_string_sets() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    cases: tuple[tuple[str, str, str | None, list[str]], ...] = (
        ("for_of_expression", "ForOfExpression string_set must contain values", "", []),
        ("for_of_expression", "ForOfExpression string_set must contain values", "   ", []),
        ("for_of_expression", "ForOfExpression string_set must contain values", None, []),
        ("for_of_expression", "ForOfExpression string_set must contain values", None, [""]),
        ("of_expression", "OfExpression string_set must contain values", "", []),
        ("of_expression", "OfExpression string_set must contain values", "   ", []),
        ("of_expression", "OfExpression string_set must contain values", None, []),
        ("of_expression", "OfExpression string_set must contain values", None, ["   "]),
    )

    for expression_kind, message, string_set_text, string_set_items in cases:
        pb_file = yara_ast_pb2.YaraFile()
        pb_rule = pb_file.rules.add()
        pb_rule.name = "empty_string_set"
        condition = pb_rule.condition
        if expression_kind == "for_of_expression":
            condition.for_of_expression.quantifier = "any"
            if string_set_text is not None:
                condition.for_of_expression.string_set_text = string_set_text
            condition.for_of_expression.string_set_items.extend(string_set_items)
        else:
            condition.of_expression.quantifier_text = "any"
            if string_set_text is not None:
                condition.of_expression.string_set_text = string_set_text
            condition.of_expression.string_set_items.extend(string_set_items)

        with pytest.raises(SerializationError, match=message):
            serializer.deserialize(binary_data=pb_file.SerializeToString())


@pytest.mark.parametrize(
    ("expression_kind", "message"),
    [
        ("binary_expression", "Invalid binary operator"),
        ("unary_expression", "Invalid unary operator"),
        ("string_operator_expression", "Invalid string operator"),
    ],
)
def test_protobuf_deserializer_rejects_invalid_expression_operators(
    expression_kind: str,
    message: str,
) -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    pb_file = yara_ast_pb2.YaraFile()
    pb_rule = pb_file.rules.add()
    pb_rule.name = "invalid_expression_operator"
    condition = pb_rule.condition

    if expression_kind == "binary_expression":
        condition.binary_expression.left.boolean_literal.value = True
        condition.binary_expression.operator = "???"
        condition.binary_expression.right.boolean_literal.value = False
    elif expression_kind == "unary_expression":
        condition.unary_expression.operator = "???"
        condition.unary_expression.operand.boolean_literal.value = True
    elif expression_kind == "string_operator_expression":
        condition.string_operator_expression.left.string_literal.value = "a"
        condition.string_operator_expression.operator = "???"
        condition.string_operator_expression.right.string_literal.value = "b"

    with pytest.raises(SerializationError, match=message):
        serializer.deserialize(binary_data=pb_file.SerializeToString())


def test_protobuf_deserializer_rejects_invalid_in_expression_range() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    pb_file = yara_ast_pb2.YaraFile()
    pb_rule = pb_file.rules.add()
    pb_rule.name = "invalid_in_expression_range"
    condition = pb_rule.condition
    condition.in_expression.string_id = "$a"
    condition.in_expression.range.integer_literal.value = 0

    with pytest.raises(SerializationError, match="InExpression range must be a range expression"):
        serializer.deserialize(binary_data=pb_file.SerializeToString())


@pytest.mark.parametrize(
    ("expression_kind", "message"),
    [
        ("identifier", "Identifier name must not be empty"),
        ("string_identifier", "StringIdentifier name must not be empty"),
        ("string_wildcard", "StringWildcard pattern must not be empty"),
        ("string_count", "StringCount string_id must not be empty"),
        ("string_offset", "StringOffset string_id must not be empty"),
        ("string_length", "StringLength string_id must not be empty"),
        ("binary_expression", "BinaryExpression operator must not be empty"),
        ("unary_expression", "UnaryExpression operator must not be empty"),
        ("regex_literal", "RegexLiteral pattern must not be empty"),
        ("function_call", "FunctionCall function must not be empty"),
        ("member_access", "MemberAccess member must not be empty"),
        ("for_expression", "ForExpression variable must not be empty"),
        ("at_expression", "AtExpression string_id must not be empty"),
        ("module_reference", "ModuleReference module must not be empty"),
        ("extern_rule_reference", "ExternRuleReference rule_name must not be empty"),
        ("string_operator_expression", "StringOperatorExpression operator must not be empty"),
    ],
)
def test_protobuf_deserializer_rejects_empty_expression_identifier_fields(
    expression_kind: str,
    message: str,
) -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    pb_file = yara_ast_pb2.YaraFile()
    pb_rule = pb_file.rules.add()
    pb_rule.name = "empty_expression_identifier"
    condition = pb_rule.condition

    if expression_kind in {
        "identifier",
        "string_identifier",
        "string_wildcard",
        "string_count",
        "module_reference",
        "extern_rule_reference",
    }:
        getattr(condition, expression_kind).SetInParent()
    elif expression_kind in {"string_offset", "string_length"}:
        getattr(condition, expression_kind).index.integer_literal.value = 0
    elif expression_kind == "function_call":
        condition.function_call.SetInParent()
    elif expression_kind == "binary_expression":
        condition.binary_expression.left.boolean_literal.value = True
        condition.binary_expression.right.boolean_literal.value = False
    elif expression_kind == "unary_expression":
        condition.unary_expression.operand.boolean_literal.value = True
    elif expression_kind == "regex_literal":
        condition.regex_literal.SetInParent()
    elif expression_kind == "member_access":
        condition.member_access.object.identifier.name = "pe"
    elif expression_kind == "for_expression":
        condition.for_expression.quantifier = "any"
        condition.for_expression.iterable.range_expression.low.integer_literal.value = 0
        condition.for_expression.iterable.range_expression.high.integer_literal.value = 3
        condition.for_expression.body.boolean_literal.value = True
    elif expression_kind == "at_expression":
        condition.at_expression.offset.integer_literal.value = 0
    elif expression_kind == "string_operator_expression":
        condition.string_operator_expression.left.string_literal.value = "a"
        condition.string_operator_expression.right.string_literal.value = "b"

    with pytest.raises(SerializationError, match=message):
        serializer.deserialize(binary_data=pb_file.SerializeToString())


def test_protobuf_deserializer_rejects_invalid_function_call_names() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    pb_file = yara_ast_pb2.YaraFile()
    pb_rule = pb_file.rules.add()
    pb_rule.name = "invalid_function_call"
    pb_rule.condition.function_call.function = "bad-name"

    with pytest.raises(SerializationError, match="Invalid function identifier"):
        serializer.deserialize(binary_data=pb_file.SerializeToString())


def test_protobuf_deserializer_rejects_invalid_module_reference_names() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    pb_file = yara_ast_pb2.YaraFile()
    pb_rule = pb_file.rules.add()
    pb_rule.name = "invalid_module_reference"
    pb_rule.condition.module_reference.module = "bad-name"

    with pytest.raises(SerializationError, match="Invalid module identifier"):
        serializer.deserialize(binary_data=pb_file.SerializeToString())


@pytest.mark.parametrize(
    ("expression_kind", "quantifier", "message"),
    [
        ("for_expression", "50%", "Invalid ForExpression quantifier"),
        ("for_expression", "-1", "Invalid ForExpression quantifier"),
        ("of_expression", "0%", "Invalid OfExpression quantifier"),
        ("of_expression", "101%", "Invalid OfExpression quantifier"),
    ],
)
def test_protobuf_deserializer_rejects_invalid_quantifiers(
    expression_kind: str,
    quantifier: str,
    message: str,
) -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    pb_file = yara_ast_pb2.YaraFile()
    pb_rule = pb_file.rules.add()
    pb_rule.name = "invalid_quantifier"
    if expression_kind == "for_expression":
        pb_rule.condition.for_expression.quantifier = quantifier
        pb_rule.condition.for_expression.variable = "i"
        pb_rule.condition.for_expression.iterable.set_expression.elements.add().integer_literal.value = (
            1
        )
        pb_rule.condition.for_expression.body.boolean_literal.value = True
    else:
        pb_rule.condition.of_expression.quantifier_text = quantifier
        pb_rule.condition.of_expression.string_set_text = "them"

    with pytest.raises(SerializationError, match=message):
        serializer.deserialize(binary_data=pb_file.SerializeToString())


def test_protobuf_deserializer_rejects_invalid_member_access_names() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    pb_file = yara_ast_pb2.YaraFile()
    pb_rule = pb_file.rules.add()
    pb_rule.name = "invalid_member_access"
    pb_rule.condition.member_access.object.identifier.name = "pe"
    pb_rule.condition.member_access.member = "bad-name"

    with pytest.raises(SerializationError, match="Invalid member identifier"):
        serializer.deserialize(binary_data=pb_file.SerializeToString())


@pytest.mark.parametrize(
    ("expression_kind", "value"),
    [
        ("string_identifier", "$bad-name"),
        ("string_identifier", "$a*"),
        ("string_wildcard", "$bad-name*"),
        ("string_count", "#a"),
        ("string_count", "$bad-name"),
        ("string_offset", "@a"),
        ("string_offset", "$bad-name"),
        ("string_length", "!a"),
        ("string_length", "$bad-name"),
        ("at_expression", "@a"),
        ("at_expression", "$bad-name"),
        ("in_expression", "@a"),
        ("in_expression", "$bad-name"),
    ],
)
def test_protobuf_deserializer_rejects_invalid_string_reference_fields(
    expression_kind: str,
    value: str,
) -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    pb_file = yara_ast_pb2.YaraFile()
    pb_rule = pb_file.rules.add()
    pb_rule.name = "invalid_string_reference"
    condition = pb_rule.condition

    if expression_kind == "string_identifier":
        condition.string_identifier.name = value
    elif expression_kind == "string_wildcard":
        condition.string_wildcard.pattern = value
    elif expression_kind == "string_count":
        condition.string_count.string_id = value
    elif expression_kind == "string_offset":
        condition.string_offset.string_id = value
    elif expression_kind == "string_length":
        condition.string_length.string_id = value
    elif expression_kind == "at_expression":
        condition.at_expression.string_id = value
        condition.at_expression.offset.integer_literal.value = 0
    elif expression_kind == "in_expression":
        condition.in_expression.string_id = value
        condition.in_expression.range.range_expression.low.integer_literal.value = 0
        condition.in_expression.range.range_expression.high.integer_literal.value = 1

    with pytest.raises(SerializationError, match="Invalid string reference"):
        serializer.deserialize(binary_data=pb_file.SerializeToString())


def test_protobuf_accepts_placeholder_string_references() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = YaraFile(
        rules=[
            Rule(name="count_placeholder", condition=StringCount("$")),
            Rule(name="offset_placeholder", condition=StringOffset("$", IntegerLiteral(0))),
            Rule(name="length_placeholder", condition=StringLength("$", IntegerLiteral(0))),
        ]
    )

    restored = serializer.deserialize(binary_data=serializer.serialize(ast))

    conditions = [rule.condition for rule in restored.rules]
    assert conditions == [
        StringCount("$"),
        StringOffset("$", IntegerLiteral(0)),
        StringLength("$", IntegerLiteral(0)),
    ]


def test_protobuf_deserializer_rejects_invalid_for_expression_variable() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    pb_file = yara_ast_pb2.YaraFile()
    pb_rule = pb_file.rules.add()
    pb_rule.name = "invalid_for_variable"
    condition = pb_rule.condition
    condition.for_expression.quantifier = "any"
    condition.for_expression.variable = "bad-name"
    condition.for_expression.iterable.range_expression.low.integer_literal.value = 0
    condition.for_expression.iterable.range_expression.high.integer_literal.value = 3
    condition.for_expression.body.boolean_literal.value = True

    with pytest.raises(SerializationError, match="Invalid local variable identifier: bad-name"):
        serializer.deserialize(binary_data=pb_file.SerializeToString())


def _invalid_expression_container_cases() -> list[tuple[Any, str]]:
    set_bad_elements = SetExpression([IntegerLiteral(1)])
    cast(Any, set_bad_elements).elements = False

    set_bad_element = SetExpression([IntegerLiteral(1)])
    cast(Any, set_bad_element).elements = [object()]

    call_bad_arguments = FunctionCall("fn", [IntegerLiteral(1)])
    cast(Any, call_bad_arguments).arguments = False

    call_bad_argument = FunctionCall("fn", [IntegerLiteral(1)])
    cast(Any, call_bad_argument).arguments = [object()]

    return [
        (set_bad_elements, "SetExpression elements must be a list"),
        (set_bad_element, "SetExpression elements item must be Expression"),
        (call_bad_arguments, "FunctionCall arguments must be a list"),
        (call_bad_argument, "FunctionCall arguments item must be Expression"),
    ]


@pytest.mark.parametrize(("condition", "message"), _invalid_expression_container_cases())
def test_protobuf_serializer_rejects_invalid_expression_container_fields(
    condition: Any,
    message: str,
) -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = YaraFile(rules=[Rule(name="invalid_expression_container", condition=condition)])

    with pytest.raises(SerializationError, match=message):
        serializer.serialize(ast)


def test_protobuf_serializer_preserves_file_externs_and_pragmas() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = YaraFile(
        extern_rules=[
            ExternRule(
                name="ExternalRule",
                modifiers=[RuleModifier.from_string("private")],
                namespace="legacy",
            ),
        ],
        extern_imports=[
            ExternImport(
                module_path="external_rules",
                alias="ext",
                rules=["ExternalRule"],
            ),
        ],
        pragmas=[
            CustomPragma(
                name="optimize",
                arguments=["off"],
                parameters={"level": 2},
                scope=PragmaScope.FILE,
            ),
        ],
        namespaces=[
            ExternNamespace(
                name="corp",
                extern_rules=[ExternRule(name="NamespacedRule")],
            ),
        ],
        rules=[
            Rule(
                name="uses_pragmas",
                pragmas=[
                    InRulePragma(
                        pragma=CustomPragma(
                            name="rule_hint",
                            arguments=["fast"],
                            parameters={"enabled": True},
                            scope=PragmaScope.RULE,
                        ),
                        position="before_condition",
                    ),
                ],
                condition=BooleanLiteral(value=True),
            ),
        ],
    )

    restored = serializer.deserialize(binary_data=serializer.serialize(ast))

    assert restored.extern_rules[0].name == "ExternalRule"
    assert str(restored.extern_rules[0].modifiers[0]) == "private"
    assert restored.extern_rules[0].namespace == "legacy"
    assert restored.extern_imports[0].module_path == "external_rules"
    assert restored.extern_imports[0].alias == "ext"
    assert restored.extern_imports[0].rules == ["ExternalRule"]
    restored_file_pragma = restored.pragmas[0]
    assert isinstance(restored_file_pragma, CustomPragma)
    assert restored_file_pragma.name == "optimize"
    assert restored_file_pragma.parameters == {"level": 2}
    assert restored.namespaces[0].name == "corp"
    assert restored.namespaces[0].extern_rules[0].name == "NamespacedRule"
    assert restored.rules[0].pragmas[0].position == "before_condition"
    restored_rule_pragma = restored.rules[0].pragmas[0].pragma
    assert isinstance(restored_rule_pragma, CustomPragma)
    assert restored_rule_pragma.name == "rule_hint"
    assert restored_rule_pragma.scope == PragmaScope.RULE
    assert restored_rule_pragma.parameters == {"enabled": True}


def test_protobuf_roundtrip_preserves_empty_define_macro_value_argument() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = YaraFile(pragmas=[DefineDirective("EMPTY", "")])

    restored = serializer.deserialize(binary_data=serializer.serialize(ast))

    assert isinstance(restored.pragmas[0], DefineDirective)
    assert restored.pragmas[0].macro_value == ""
    assert restored.pragmas[0].arguments == ["EMPTY", ""]


def test_protobuf_serialize_rejects_invalid_pragma_scope() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    pragma = CustomPragma(name="custom", scope=PragmaScope.FILE)
    cast(Any, pragma).scope = "secret"

    with pytest.raises(SerializationError, match="Pragma scope must be a valid pragma scope"):
        serializer.serialize(YaraFile(pragmas=[pragma]))


def test_protobuf_deserialize_rejects_invalid_pragma_scope() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    pb_file: Any = yara_ast_pb2.YaraFile()
    pb_pragma = pb_file.pragmas.add()
    pb_pragma.pragma_type = "custom"
    pb_pragma.name = "custom"
    pb_pragma.scope = "secret"

    with pytest.raises(SerializationError, match="Pragma scope must be a valid pragma scope"):
        serializer.deserialize(binary_data=pb_file.SerializeToString())


def test_protobuf_deserializes_legacy_meta_map_in_stable_key_order() -> None:
    pb_file = yara_ast_pb2.YaraFile()
    pb_rule = pb_file.rules.add()
    pb_rule.name = "legacy_meta"
    for key in ("zeta", "alpha", "middle", "beta"):
        pb_rule.meta[key].string_value = key

    restored = protobuf_to_ast(pb_file)

    assert [entry.key for entry in restored.rules[0].meta] == [
        "alpha",
        "beta",
        "middle",
        "zeta",
    ]


def test_protobuf_deserializes_pragma_parameters_in_stable_key_order() -> None:
    pb_file = yara_ast_pb2.YaraFile()
    pb_pragma = pb_file.pragmas.add()
    pb_pragma.pragma_type = "custom"
    pb_pragma.name = "vendor"
    pb_pragma.scope = "file"
    for key in ("k9", "k1", "k5", "k2", "k8", "k3", "k7", "k4"):
        pb_pragma.parameters[key].string_value = key

    restored = protobuf_to_ast(pb_file)

    assert isinstance(restored.pragmas[0], CustomPragma)
    assert list(restored.pragmas[0].parameters) == [
        "k1",
        "k2",
        "k3",
        "k4",
        "k5",
        "k7",
        "k8",
        "k9",
    ]


def test_protobuf_serializer_uses_deterministic_map_encoding() -> None:
    keys = ("k9", "k1", "k5", "k2", "k8", "k3", "k7", "k4")
    serializer = ProtobufSerializer(include_metadata=False)
    first = YaraFile(
        pragmas=[CustomPragma("vendor", parameters={key: key for key in keys})],
    )
    second = YaraFile(
        pragmas=[CustomPragma("vendor", parameters={key: key for key in reversed(keys)})],
    )

    assert serializer.serialize(first) == serializer.serialize(second)


def test_protobuf_serializer_preserves_extern_rule_reference_condition() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = YaraFile(
        rules=[
            Rule(
                name="uses_external",
                condition=cast(
                    Any,
                    ExternRuleReference(rule_name="ExternalRule", namespace="legacy"),
                ),
            ),
        ],
    )

    restored = serializer.deserialize(binary_data=serializer.serialize(ast))
    condition = restored.rules[0].condition

    assert isinstance(condition, ExternRuleReference)
    assert condition.rule_name == "ExternalRule"
    assert condition.namespace == "legacy"


def test_protobuf_serializer_rejects_legacy_empty_string_sets() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    cases: tuple[tuple[Any, str], ...] = (
        (OfExpression(IntegerLiteral(0), []), "OfExpression string_set must contain values"),
        (
            ForOfExpression("any", [], None),
            "ForOfExpression string_set must contain values",
        ),
    )

    for condition, message in cases:
        ast = YaraFile(rules=[Rule(name="empty_string_set", condition=condition)])
        with pytest.raises(SerializationError, match=message):
            serializer.serialize(ast)


def _invalid_comment_metadata_cases() -> list[tuple[YaraFile, str]]:
    bad_leading_comments = Rule(name="bad_leading_comments", condition=BooleanLiteral(True))
    cast(Any, bad_leading_comments).leading_comments = False

    bad_leading_comment = Rule(name="bad_leading_comment", condition=BooleanLiteral(True))
    bad_leading_comment.leading_comments = cast(Any, [object()])

    bad_trailing_comment = Rule(name="bad_trailing_comment", condition=BooleanLiteral(True))
    bad_trailing_comment.trailing_comment = cast(Any, object())

    bad_comment_group = CommentGroup([Comment("ok")])
    cast(Any, bad_comment_group).comments = False
    group_rule = Rule(name="bad_comment_group", condition=BooleanLiteral(True))
    cast(Any, group_rule).trailing_comment = bad_comment_group

    bad_comment_group_item = CommentGroup([Comment("ok")])
    cast(Any, bad_comment_group_item).comments = [object()]
    group_item_rule = Rule(name="bad_comment_group_item", condition=BooleanLiteral(True))
    cast(Any, group_item_rule).trailing_comment = bad_comment_group_item

    bad_comment_text = Rule(name="bad_comment_text", condition=BooleanLiteral(True))
    bad_comment_text.trailing_comment = Comment(cast(Any, 123))

    bad_comment_multiline = Rule(name="bad_comment_multiline", condition=BooleanLiteral(True))
    bad_comment_multiline.trailing_comment = Comment("ok", is_multiline=cast(Any, "true"))

    return [
        (YaraFile(rules=[bad_leading_comments]), "leading_comments must be a list"),
        (
            YaraFile(rules=[bad_leading_comment]),
            "leading_comments item must be Comment or CommentGroup",
        ),
        (
            YaraFile(rules=[bad_trailing_comment]),
            "trailing_comment must be Comment or CommentGroup",
        ),
        (YaraFile(rules=[group_rule]), "CommentGroup comments must be a list"),
        (
            YaraFile(rules=[group_item_rule]),
            "CommentGroup comments item must be Comment",
        ),
        (YaraFile(rules=[bad_comment_text]), "Comment text must be a string"),
        (
            YaraFile(rules=[bad_comment_multiline]),
            "Comment is_multiline must be a boolean",
        ),
    ]


@pytest.mark.parametrize(("ast", "message"), _invalid_comment_metadata_cases())
def test_protobuf_serializer_rejects_invalid_comment_metadata(
    ast: YaraFile,
    message: str,
) -> None:
    serializer = ProtobufSerializer(include_metadata=False)

    with pytest.raises(SerializationError, match=message):
        serializer.serialize(ast)


@pytest.mark.parametrize("comment_position", ["leading", "trailing"])
def test_protobuf_deserializer_rejects_empty_comment_metadata(
    comment_position: str,
) -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    pb_file = yara_ast_pb2.YaraFile()
    if comment_position == "leading":
        pb_file.node_metadata.leading_comments.add()
    else:
        pb_file.node_metadata.trailing_comment.SetInParent()

    with pytest.raises(SerializationError, match="Protobuf comment metadata is missing"):
        serializer.deserialize(binary_data=pb_file.SerializeToString())


@pytest.mark.parametrize(
    ("location", "message"),
    [
        (cast(Any, object()), "location must be a Location"),
        (Location(cast(Any, True), 1), "Location line must be an integer"),
        (Location(2**31, 1), "Location line must fit in protobuf int32"),
        (Location(1, cast(Any, "2")), "Location column must be an integer"),
        (Location(1, -(2**31) - 1), "Location column must fit in protobuf int32"),
        (Location(1, 1, file=cast(Any, [])), "Location file must be a string"),
        (Location(1, 1, end_line=cast(Any, False)), "Location end_line must be an integer"),
        (Location(1, 1, end_line=2**31), "Location end_line must fit in protobuf int32"),
        (Location(1, 1, end_column=cast(Any, "3")), "Location end_column must be an integer"),
        (
            Location(1, 1, end_column=-(2**31) - 1),
            "Location end_column must fit in protobuf int32",
        ),
        (Location(0, 1), "Location line must be at least 1"),
    ],
)
def test_protobuf_serializer_rejects_invalid_location_metadata(
    location: Any,
    message: str,
) -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    rule = Rule(name="bad_location", condition=BooleanLiteral(True))
    rule.location = location

    with pytest.raises(SerializationError, match=message):
        serializer.serialize(YaraFile(rules=[rule]))


def test_protobuf_deserialize_rejects_non_positive_location_metadata() -> None:
    pb_file = yara_ast_pb2.YaraFile()
    pb_file.node_metadata.location.line = 0
    pb_file.node_metadata.location.column = 1

    with pytest.raises(SerializationError, match="Location line must be at least 1"):
        ProtobufSerializer().deserialize(binary_data=pb_file.SerializeToString())


def test_protobuf_serializer_preserves_node_comment_metadata() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    plain = PlainString(identifier="$a", value="abc")
    plain.leading_comments = [Comment("string lead", is_multiline=True)]
    condition = BooleanLiteral(True)
    condition.trailing_comment = Comment("condition tail")
    meta = Meta("author", "me")
    meta.leading_comments = [Comment("meta lead")]
    rule = Rule(name="commented", meta=[meta], strings=[plain], condition=condition)
    rule.leading_comments = [Comment("rule lead")]
    rule.trailing_comment = Comment("rule tail")
    ast = YaraFile(rules=[rule])
    ast.location = Location(1, 1, file="sample.yar", end_line=6, end_column=1)
    ast.trailing_comment = cast(Any, CommentGroup([Comment("file end"), Comment("final")]))

    restored = serializer.deserialize(binary_data=serializer.serialize(ast))

    assert restored.location == Location(1, 1, file="sample.yar", end_line=6, end_column=1)
    assert isinstance(restored.trailing_comment, CommentGroup)
    assert restored.trailing_comment.comments[1].text == "final"
    assert restored.rules[0].leading_comments[0].text == "rule lead"
    assert restored.rules[0].trailing_comment is not None
    assert restored.rules[0].trailing_comment.text == "rule tail"
    assert restored.rules[0].meta[0].leading_comments[0].text == "meta lead"
    restored_plain = restored.rules[0].strings[0]
    assert restored_plain.leading_comments[0].is_multiline is True
    restored_condition = restored.rules[0].condition
    assert restored_condition is not None
    assert restored_condition.trailing_comment is not None
    assert restored_condition.trailing_comment.text == "condition tail"


def test_protobuf_serializer_preserves_empty_comment_groups() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    rule = Rule(name="empty_comment_groups", condition=BooleanLiteral(True))
    rule.leading_comments = cast(Any, [CommentGroup([])])
    rule.trailing_comment = cast(Any, CommentGroup([]))
    ast = YaraFile(rules=[rule])

    restored = serializer.deserialize(binary_data=serializer.serialize(ast))

    assert len(restored.rules[0].leading_comments) == 1
    assert isinstance(restored.rules[0].leading_comments[0], CommentGroup)
    assert restored.rules[0].leading_comments[0].comments == []
    assert isinstance(restored.rules[0].trailing_comment, CommentGroup)
    assert restored.rules[0].trailing_comment.comments == []
