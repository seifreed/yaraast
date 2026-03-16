"""Extra tests for Protobuf serializer (no mocks)."""

from __future__ import annotations

from textwrap import dedent

from yaraast.parser import Parser
from yaraast.serialization.protobuf_serializer import ProtobufSerializer


def test_protobuf_hex_regex_and_deserialize_file(tmp_path) -> None:
    code = dedent(
        """
        rule proto2 {
            strings:
                $a = { 4D 5A ?? [2-3] 00 }
                $b = /test.*/i
            condition:
                $a and $b
        }
        """,
    )
    ast = Parser().parse(code)
    serializer = ProtobufSerializer(include_metadata=True)

    out_path = tmp_path / "ast2.pb"
    serializer.serialize(ast, output_path=out_path)

    restored = serializer.deserialize(input_path=out_path)
    assert len(restored.rules) == 1
    assert restored.rules[0].name == "proto2"

    stats = serializer.get_serialization_stats(ast)
    assert stats["binary_size_bytes"] > 0
