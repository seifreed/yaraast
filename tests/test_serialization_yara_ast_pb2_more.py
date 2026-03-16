"""Real tests for generated protobuf module (no mocks)."""

from __future__ import annotations

from yaraast.serialization import yara_ast_pb2


def test_yara_ast_pb2_roundtrip() -> None:
    pb = yara_ast_pb2.YaraFile()
    pb.metadata.format = "yaraast-protobuf"
    pb.metadata.version = "1.0"

    imp = pb.imports.add()
    imp.module = "pe"

    inc = pb.includes.add()
    inc.path = "base.yar"

    rule = pb.rules.add()
    rule.name = "pb_rule"
    rule.modifiers.append("private")

    s = pb.rules[0].strings.add()
    s.identifier = "$a"
    s.plain.value = "abc"

    data = pb.SerializeToString()
    pb2 = yara_ast_pb2.YaraFile()
    pb2.ParseFromString(data)

    assert pb2.metadata.format == "yaraast-protobuf"
    assert pb2.imports[0].module == "pe"
    assert pb2.includes[0].path == "base.yar"
    assert pb2.rules[0].name == "pb_rule"
    assert pb2.rules[0].strings[0].plain.value == "abc"
