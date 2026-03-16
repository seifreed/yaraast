"""Additional tests for protobuf schema types (no mocks)."""

from __future__ import annotations

import pytest


def test_yara_ast_pb2_message_roundtrip() -> None:
    pb2 = pytest.importorskip("yaraast.serialization.yara_ast_pb2")

    file_msg = pb2.YaraFile()
    file_msg.imports.add(module="pe")
    file_msg.includes.add(path="inc.yar")

    rule = file_msg.rules.add()
    rule.name = "r1"
    rule.modifiers.extend(["private"])
    rule.tags.add().name = "t1"
    rule.meta["author"].string_value = "me"

    str_def = rule.strings.add()
    str_def.identifier = "$a"
    str_def.plain.value = "hello"
    str_def.plain.modifiers.add(name="ascii")

    expr = rule.condition
    expr.boolean_literal.value = True

    file_msg.metadata.format = "yaraast-protobuf"
    file_msg.metadata.rules_count = 1

    data = file_msg.SerializeToString()
    restored = pb2.YaraFile()
    restored.ParseFromString(data)

    assert restored.rules[0].name == "r1"
    assert restored.rules[0].meta["author"].string_value == "me"
    assert restored.rules[0].strings[0].plain.value == "hello"
    assert restored.rules[0].condition.WhichOneof("expression_type") == "boolean_literal"


def test_expression_oneof_variants() -> None:
    pb2 = pytest.importorskip("yaraast.serialization.yara_ast_pb2")

    expr = pb2.Expression()
    expr.integer_literal.value = 7
    assert expr.WhichOneof("expression_type") == "integer_literal"

    expr.string_literal.value = "x"
    assert expr.WhichOneof("expression_type") == "string_literal"

    expr.binary_expression.operator = "and"
    expr.binary_expression.left.boolean_literal.value = True
    expr.binary_expression.right.boolean_literal.value = False
    assert expr.WhichOneof("expression_type") == "binary_expression"
