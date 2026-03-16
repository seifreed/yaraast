"""Real tests for Protobuf serializer (no mocks)."""

from __future__ import annotations

import pytest

from yaraast.parser import Parser
from yaraast.serialization.protobuf_serializer import ProtobufSerializer


def _sample_ast():
    code = """
    import "pe"
    include "base.yar"

    rule proto_rule {
        strings:
            $a = "abc" ascii
            $b = /test/i
        condition:
            $a or $b
    }
    """
    return Parser().parse(code)


def test_protobuf_serialize_deserialize_roundtrip(tmp_path) -> None:
    ast = _sample_ast()
    serializer = ProtobufSerializer(include_metadata=True)

    out_path = tmp_path / "ast.pb"
    binary = serializer.serialize(ast, output_path=out_path)
    assert out_path.exists()
    assert binary

    text = serializer.serialize_text(ast)
    assert "rules" in text

    restored = serializer.deserialize(binary_data=binary)
    assert len(restored.rules) == 1
    assert restored.rules[0].name == "proto_rule"


def test_protobuf_stats_and_errors() -> None:
    ast = _sample_ast()
    serializer = ProtobufSerializer(include_metadata=False)
    stats = serializer.get_serialization_stats(ast)

    assert stats["binary_size_bytes"] > 0
    assert stats["rules_count"] == 1

    with pytest.raises(ValueError):
        serializer.deserialize(binary_data=None)
