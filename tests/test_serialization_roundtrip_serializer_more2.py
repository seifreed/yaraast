"""Additional tests for roundtrip serializer (no mocks)."""

from __future__ import annotations

import json
from typing import cast

import pytest
import yaml

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import BooleanLiteral
from yaraast.ast.rules import Rule
from yaraast.errors import SerializationError
from yaraast.serialization.json_serializer import JsonSerializer
from yaraast.serialization.roundtrip_serializer import RoundTripSerializer
from yaraast.yarax.ast_nodes import WithStatement
from yaraast.yarax.parser import YaraXParser


def test_roundtrip_parse_and_serialize_json() -> None:
    source = "rule r1 { condition: true }"
    serializer = RoundTripSerializer()

    formatting = serializer._detect_formatting(source)
    assert formatting.indent_size >= 1

    ast, serialized = serializer.parse_and_serialize(source, format="json")
    assert ast.rules[0].name == "r1"

    data = json.loads(serialized)
    assert "roundtrip_metadata" in data
    assert data["roundtrip_metadata"]["formatting"]["indent_size"] >= 1


def test_roundtrip_parse_and_serialize_yaml() -> None:
    source = "rule r1 { condition: true }"
    serializer = RoundTripSerializer()

    _, serialized = serializer.parse_and_serialize(source, format="yaml")
    data = yaml.safe_load(serialized)

    assert "roundtrip_metadata" in data
    assert data["roundtrip_metadata"]["serializer_version"] == "1.0.0"


def test_roundtrip_deserialize_and_generate() -> None:
    source = "rule r1 { condition: true }"
    serializer = RoundTripSerializer()
    _, serialized = serializer.parse_and_serialize(source, format="json")

    ast, generated = serializer.deserialize_and_generate(serialized, format="json")
    assert ast.rules[0].name == "r1"
    assert "rule r1" in generated


def _serialized_json_payload() -> dict[str, object]:
    ast = YaraFile(rules=[Rule(name="r1", condition=BooleanLiteral(value=True))])
    payload = json.loads(JsonSerializer(include_metadata=True).serialize(ast))
    if not isinstance(payload, dict):
        msg = "Expected serialized AST object"
        raise AssertionError(msg)
    return cast(dict[str, object], payload)


def test_roundtrip_deserialize_rejects_non_object_payload_as_serialization_error() -> None:
    serializer = RoundTripSerializer()

    with pytest.raises(SerializationError, match="YaraFile must be an object"):
        serializer.deserialize_and_generate("42", format="json")


@pytest.mark.parametrize(
    ("metadata", "message"),
    [
        ("metadata", "RoundTripMetadata must be an object"),
        ({"formatting": "compact"}, "FormattingInfo must be an object"),
        (
            {"formatting": {"indent_size": "wide"}},
            "FormattingInfo indent_size must be an integer",
        ),
        (
            {"comments_preserved": "yes"},
            "RoundTripMetadata comments_preserved must be a boolean",
        ),
    ],
)
def test_roundtrip_deserialize_rejects_invalid_roundtrip_metadata(
    metadata: object,
    message: str,
) -> None:
    payload = _serialized_json_payload()
    payload["roundtrip_metadata"] = metadata
    serializer = RoundTripSerializer()

    with pytest.raises(SerializationError, match=message):
        serializer.deserialize_and_generate(json.dumps(payload), format="json")


def test_roundtrip_serializer_handles_yarax_syntax() -> None:
    source = "rule rx { condition: with xs = [1]: match xs { _ => true } }"
    serializer = RoundTripSerializer()

    ast, serialized = serializer.parse_and_serialize(source, format="json")
    restored_ast, generated = serializer.deserialize_and_generate(serialized, format="json")

    assert isinstance(ast.rules[0].condition, WithStatement)
    assert isinstance(restored_ast.rules[0].condition, WithStatement)
    assert "with xs = [1]" in generated
    assert "match xs" in generated
    YaraXParser(generated).parse()


def test_roundtrip_test_result() -> None:
    source = "rule r1 { condition: true }"
    serializer = RoundTripSerializer()
    result = serializer.roundtrip_test(source, format="json")
    assert result["format"] == "json"
    assert "original_source" in result
