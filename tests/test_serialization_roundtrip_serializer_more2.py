"""Additional tests for roundtrip serializer (no mocks)."""

from __future__ import annotations

import json

import yaml

from yaraast.serialization.roundtrip_serializer import RoundTripSerializer


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


def test_roundtrip_test_result() -> None:
    source = "rule r1 { condition: true }"
    serializer = RoundTripSerializer()
    result = serializer.roundtrip_test(source, format="json")
    assert result["format"] == "json"
    assert "original_source" in result
