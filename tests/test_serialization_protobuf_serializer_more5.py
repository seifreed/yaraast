"""Additional coverage for protobuf serializer modifier paths."""

from __future__ import annotations

from typing import Any, cast

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import BooleanLiteral
from yaraast.ast.extern import ExternImport, ExternNamespace, ExternRule, ExternRuleReference
from yaraast.ast.modifiers import RuleModifier, StringModifier
from yaraast.ast.pragmas import CustomPragma, InRulePragma, PragmaScope
from yaraast.ast.rules import Rule
from yaraast.ast.strings import HexByte, HexString
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
