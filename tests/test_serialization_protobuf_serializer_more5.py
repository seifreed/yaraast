"""Additional coverage for protobuf serializer modifier paths."""

from __future__ import annotations

from typing import Any, cast

from yaraast.ast.base import Location, YaraFile
from yaraast.ast.comments import Comment, CommentGroup
from yaraast.ast.expressions import BooleanLiteral
from yaraast.ast.extern import ExternImport, ExternNamespace, ExternRule, ExternRuleReference
from yaraast.ast.meta import Meta
from yaraast.ast.modifiers import RuleModifier, StringModifier
from yaraast.ast.pragmas import CustomPragma, InRulePragma, PragmaScope
from yaraast.ast.rules import Rule
from yaraast.ast.strings import HexByte, HexString, PlainString
from yaraast.serialization import yara_ast_pb2
from yaraast.serialization.protobuf_conversion import protobuf_to_ast
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
