"""Additional coverage for protobuf serializer modifier paths."""

from __future__ import annotations

from typing import Any, cast

import pytest

from yaraast.ast.base import Location, YaraFile
from yaraast.ast.comments import Comment, CommentGroup
from yaraast.ast.conditions import ForOfExpression, OfExpression
from yaraast.ast.expressions import BooleanLiteral, DoubleLiteral, IntegerLiteral, StringIdentifier
from yaraast.ast.extern import ExternImport, ExternNamespace, ExternRule, ExternRuleReference
from yaraast.ast.meta import Meta
from yaraast.ast.modifiers import RuleModifier, StringModifier
from yaraast.ast.pragmas import CustomPragma, InRulePragma, PragmaScope
from yaraast.ast.rules import Rule
from yaraast.ast.strings import HexByte, HexString, PlainString, RegexString
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


def test_protobuf_serializer_does_not_coerce_invalid_xor_range_values_to_ints() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = YaraFile(
        rules=[
            Rule(
                name="invalid_xor_ranges",
                strings=[
                    PlainString(
                        "$bool_range",
                        value="a",
                        modifiers=[StringModifier.from_name_value("xor", cast(Any, (True, 3)))],
                    ),
                    PlainString(
                        "$float_range",
                        value="b",
                        modifiers=[StringModifier.from_name_value("xor", cast(Any, (1.5, 3)))],
                    ),
                ],
                condition=BooleanLiteral(value=True),
            ),
        ],
    )

    restored = serializer.deserialize(binary_data=serializer.serialize(ast))

    assert [string.modifiers[0].value for string in restored.rules[0].strings] == [
        "True-3",
        "1.5-3",
    ]


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
    ast = YaraFile(
        rules=[
            Rule(
                name="bad_meta",
                meta=[Meta("score", cast(Any, float("nan")))],
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


def test_protobuf_serializer_preserves_empty_string_sets() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = YaraFile(
        rules=[
            Rule(name="of_empty", condition=OfExpression(IntegerLiteral(0), [])),
            Rule(name="for_of_empty", condition=ForOfExpression("any", [], None)),
        ],
    )

    restored = serializer.deserialize(binary_data=serializer.serialize(ast))

    of_condition = restored.rules[0].condition
    for_of_condition = restored.rules[1].condition
    assert isinstance(of_condition, OfExpression)
    assert of_condition.string_set == []
    assert isinstance(for_of_condition, ForOfExpression)
    assert for_of_condition.string_set == []


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
