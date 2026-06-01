"""Real tests for Protobuf serializer (no mocks)."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest

from yaraast.ast.base import YaraFile
from yaraast.errors import SerializationError
from yaraast.parser import Parser
from yaraast.serialization.protobuf_serializer import ProtobufSerializer


def _sample_ast() -> YaraFile:
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


def test_protobuf_serialize_deserialize_roundtrip(tmp_path: Path) -> None:
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

    with pytest.raises(SerializationError):
        serializer.deserialize(binary_data=None)


def test_protobuf_deserialize_rejects_malformed_binary() -> None:
    serializer = ProtobufSerializer()
    with pytest.raises(SerializationError, match="Invalid Protobuf input"):
        serializer.deserialize(binary_data=b"\xff\xff\xff")


@pytest.mark.parametrize("binary_data", [False, 0, "", [], object()])
def test_protobuf_deserialize_rejects_invalid_binary_data_types(binary_data: Any) -> None:
    serializer = ProtobufSerializer()

    with pytest.raises(TypeError, match="binary_data must be bytes"):
        serializer.deserialize(binary_data=cast(Any, binary_data))


@pytest.mark.parametrize("output_path", [False, 0, object()])
def test_protobuf_serialize_rejects_invalid_output_path_types(output_path: Any) -> None:
    ast = _sample_ast()
    serializer = ProtobufSerializer()

    with pytest.raises(TypeError, match="output_path must be a file path"):
        serializer.serialize(ast, output_path=cast(Any, output_path))

    with pytest.raises(TypeError, match="output_path must be a file path"):
        serializer.serialize_text(ast, output_path=cast(Any, output_path))


def test_protobuf_serialize_rejects_empty_output_path() -> None:
    ast = _sample_ast()
    serializer = ProtobufSerializer()

    with pytest.raises(ValueError, match="output_path must not be empty"):
        serializer.serialize(ast, output_path="")

    with pytest.raises(ValueError, match="output_path must not be empty"):
        serializer.serialize_text(ast, output_path="")


@pytest.mark.parametrize("input_path", [False, 0, object()])
def test_protobuf_deserialize_rejects_invalid_input_path_types(input_path: Any) -> None:
    serializer = ProtobufSerializer()

    with pytest.raises(TypeError, match="input_path must be a file path"):
        serializer.deserialize(input_path=cast(Any, input_path))


def test_protobuf_deserialize_rejects_empty_input_path() -> None:
    serializer = ProtobufSerializer()

    with pytest.raises(ValueError, match="input_path must not be empty"):
        serializer.deserialize(input_path="")
