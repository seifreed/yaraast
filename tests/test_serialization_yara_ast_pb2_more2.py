"""Extra tests for yara_ast_pb2 (no mocks)."""

from __future__ import annotations

from yaraast.serialization import yara_ast_pb2


def test_yara_ast_pb2_fields() -> None:
    pb = yara_ast_pb2.YaraFile()
    rule = pb.rules.add()
    rule.name = "r1"
    rule.modifiers.append("global")
    tag = rule.tags.add()
    tag.name = "t1"

    meta = rule.meta["author"]
    meta.string_value = "unit"

    s = rule.strings.add()
    s.identifier = "$a"
    s.regex.regex = "abc"
    mod = s.regex.modifiers.add()
    mod.name = "nocase"

    rule.condition.boolean_literal.value = True

    data = pb.SerializeToString()
    pb2 = yara_ast_pb2.YaraFile()
    pb2.ParseFromString(data)

    assert pb2.rules[0].name == "r1"
    assert pb2.rules[0].modifiers[0] == "global"
    assert pb2.rules[0].tags[0].name == "t1"
    assert pb2.rules[0].meta["author"].string_value == "unit"
    assert pb2.rules[0].strings[0].regex.regex == "abc"
    assert pb2.rules[0].condition.boolean_literal.value is True
