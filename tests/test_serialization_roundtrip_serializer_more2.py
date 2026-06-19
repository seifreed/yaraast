"""Additional tests for roundtrip serializer (no mocks)."""

from __future__ import annotations

import json
from typing import Any, cast

import pytest
import yaml

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import BooleanLiteral
from yaraast.ast.rules import Rule
from yaraast.errors import SerializationError
from yaraast.serialization.json_serializer import JsonSerializer
from yaraast.serialization.roundtrip_helpers import detect_formatting
from yaraast.serialization.roundtrip_serializer import (
    EnhancedYamlSerializer,
    RoundTripSerializer,
    create_rules_manifest,
    serialize_for_pipeline,
)
from yaraast.yarax.ast_nodes import WithStatement
from yaraast.yarax.parser import YaraXParser


def _sample_ast() -> YaraFile:
    return YaraFile(rules=[Rule(name="r1", condition=BooleanLiteral(value=True))])


def test_roundtrip_parse_and_serialize_json() -> None:
    source = "rule r1 { condition: true }"
    serializer = RoundTripSerializer()

    formatting = detect_formatting(source)
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


def test_roundtrip_parse_and_serialize_rejects_yaral_with_clear_error() -> None:
    source = """
    rule detect_login {
        events:
            $e.metadata.event_type = "USER_LOGIN"
        match:
            $e over 5m
        condition:
            #e > 5
    }
    """
    serializer = RoundTripSerializer()

    with pytest.raises(SerializationError, match=r"YARA-L.*round-trip serialization"):
        serializer.parse_and_serialize(source, format="json")


@pytest.mark.parametrize("preserve_comments", [None, 1, "yes", object()])
def test_roundtrip_serializer_rejects_invalid_preserve_comments_types(
    preserve_comments: Any,
) -> None:
    with pytest.raises(TypeError, match="preserve_comments must be a boolean"):
        RoundTripSerializer(preserve_comments=cast(bool, preserve_comments))


@pytest.mark.parametrize("preserve_formatting", [None, 1, "yes", object()])
def test_roundtrip_serializer_rejects_invalid_preserve_formatting_types(
    preserve_formatting: Any,
) -> None:
    with pytest.raises(TypeError, match="preserve_formatting must be a boolean"):
        RoundTripSerializer(preserve_formatting=cast(bool, preserve_formatting))


@pytest.mark.parametrize("source", [None, 123, object()])
def test_roundtrip_parse_and_serialize_rejects_invalid_source_types(source: Any) -> None:
    serializer = RoundTripSerializer()

    with pytest.raises(TypeError, match="yara_source must be a string"):
        serializer.parse_and_serialize(cast(str, source))


@pytest.mark.parametrize("source_file", [123, object()])
def test_roundtrip_parse_and_serialize_rejects_invalid_source_file_types(
    source_file: Any,
) -> None:
    serializer = RoundTripSerializer()

    with pytest.raises(TypeError, match="source_file must be a string"):
        serializer.parse_and_serialize(
            "rule r1 { condition: true }",
            source_file=cast(str, source_file),
        )


@pytest.mark.parametrize("format_name", [None, 123, object()])
def test_roundtrip_parse_and_serialize_rejects_invalid_format_types(
    format_name: Any,
) -> None:
    serializer = RoundTripSerializer()

    with pytest.raises(TypeError, match="format must be a string"):
        serializer.parse_and_serialize("rule r1 { condition: true }", format=cast(str, format_name))


@pytest.mark.parametrize("format_name", ["", "toml", "xml"])
def test_roundtrip_parse_and_serialize_rejects_unsupported_formats(format_name: str) -> None:
    serializer = RoundTripSerializer()

    with pytest.raises(ValueError, match="format must be 'json' or 'yaml'"):
        serializer.parse_and_serialize("rule r1 { condition: true }", format=format_name)


def test_roundtrip_deserialize_and_generate() -> None:
    source = "rule r1 { condition: true }"
    serializer = RoundTripSerializer()
    _, serialized = serializer.parse_and_serialize(source, format="json")

    ast, generated = serializer.deserialize_and_generate(serialized, format="json")
    assert ast.rules[0].name == "r1"
    assert "rule r1" in generated


@pytest.mark.parametrize("serialized_data", [None, 123, object()])
def test_roundtrip_deserialize_rejects_invalid_serialized_data_types(
    serialized_data: Any,
) -> None:
    serializer = RoundTripSerializer()

    with pytest.raises(TypeError, match="serialized_data must be a string"):
        serializer.deserialize_and_generate(cast(str, serialized_data))


@pytest.mark.parametrize("format_name", [None, 123, object()])
def test_roundtrip_deserialize_rejects_invalid_format_types(format_name: Any) -> None:
    serializer = RoundTripSerializer()

    with pytest.raises(TypeError, match="format must be a string"):
        serializer.deserialize_and_generate("{}", format=cast(str, format_name))


@pytest.mark.parametrize("format_name", ["", "toml", "xml"])
def test_roundtrip_deserialize_rejects_unsupported_formats(format_name: str) -> None:
    serializer = RoundTripSerializer()

    with pytest.raises(ValueError, match="format must be 'json' or 'yaml'"):
        serializer.deserialize_and_generate("{}", format=format_name)


@pytest.mark.parametrize("preserve_original_formatting", [None, 1, "yes", object()])
def test_roundtrip_deserialize_rejects_invalid_preserve_formatting_types(
    preserve_original_formatting: Any,
) -> None:
    serializer = RoundTripSerializer()

    with pytest.raises(TypeError, match="preserve_original_formatting must be a boolean"):
        serializer.deserialize_and_generate(
            "{}",
            preserve_original_formatting=cast(bool, preserve_original_formatting),
        )


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
    ("format_name", "payload", "message"),
    [
        ("json", "{bad", "Invalid JSON input"),
        ("yaml", "ast: [", "Invalid YAML input"),
    ],
)
def test_roundtrip_deserialize_rejects_malformed_serialized_input(
    format_name: str,
    payload: str,
    message: str,
) -> None:
    serializer = RoundTripSerializer()

    with pytest.raises(SerializationError, match=message):
        serializer.deserialize_and_generate(payload, format=format_name)


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
            {"formatting": {"indent_size": 0}},
            "FormattingInfo indent_size must be at least 1",
        ),
        (
            {"formatting": {"indent_size": -2}},
            "FormattingInfo indent_size must be at least 1",
        ),
        (
            {"formatting": {"blank_lines_before_rule": -1}},
            "FormattingInfo blank_lines_before_rule must be at least 0",
        ),
        (
            {"formatting": {"blank_lines_after_imports": -1}},
            "FormattingInfo blank_lines_after_imports must be at least 0",
        ),
        (
            {"formatting": {"blank_lines_after_includes": -1}},
            "FormattingInfo blank_lines_after_includes must be at least 0",
        ),
        (
            {"formatting": {"indent_style": "diagonal"}},
            "FormattingInfo indent_style must be one of:",
        ),
        (
            {"formatting": {"line_endings": "bad"}},
            "FormattingInfo line_endings must be one of:",
        ),
        (
            {"formatting": {"comment_style": "emoji"}},
            "FormattingInfo comment_style must be one of:",
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


@pytest.mark.parametrize("source", [None, 123, object()])
def test_roundtrip_test_rejects_invalid_source_types(source: Any) -> None:
    serializer = RoundTripSerializer()

    with pytest.raises(TypeError, match="yara_source must be a string"):
        serializer.roundtrip_test(cast(str, source))


@pytest.mark.parametrize("format_name", [None, 123, object()])
def test_roundtrip_test_rejects_invalid_format_types(format_name: Any) -> None:
    serializer = RoundTripSerializer()

    with pytest.raises(TypeError, match="format must be a string"):
        serializer.roundtrip_test("rule r1 { condition: true }", format=cast(str, format_name))


@pytest.mark.parametrize("format_name", ["", "toml", "xml"])
def test_roundtrip_test_rejects_unsupported_formats(format_name: str) -> None:
    serializer = RoundTripSerializer()

    with pytest.raises(ValueError, match="format must be 'json' or 'yaml'"):
        serializer.roundtrip_test("rule r1 { condition: true }", format=format_name)


def test_roundtrip_test_uses_structural_success_for_reformatted_source() -> None:
    source = 'rule r1 { strings: $a = "x" condition: $a }'
    serializer = RoundTripSerializer()

    result = serializer.roundtrip_test(source, format="json")

    assert result["round_trip_successful"] is True
    assert result["differences"] == []
    assert result["metadata"]["source_differences"]


@pytest.mark.parametrize("include_pipeline_metadata", [None, 1, "yes", object()])
def test_enhanced_yaml_rejects_invalid_pipeline_metadata_flag(
    include_pipeline_metadata: Any,
) -> None:
    with pytest.raises(TypeError, match="include_pipeline_metadata must be a boolean"):
        EnhancedYamlSerializer(
            include_pipeline_metadata=cast(bool, include_pipeline_metadata),
        )


@pytest.mark.parametrize("ast", [None, 123, object()])
def test_enhanced_yaml_pipeline_rejects_invalid_ast_types(ast: Any) -> None:
    with pytest.raises(TypeError, match="ast must be a YaraFile"):
        EnhancedYamlSerializer().serialize_for_pipeline(cast(YaraFile, ast))


@pytest.mark.parametrize("pipeline_info", [123, "ci", object()])
def test_enhanced_yaml_pipeline_rejects_invalid_pipeline_info_types(
    pipeline_info: Any,
) -> None:
    with pytest.raises(TypeError, match="pipeline_info must be a dictionary"):
        EnhancedYamlSerializer().serialize_for_pipeline(
            _sample_ast(),
            pipeline_info=cast(dict[str, Any], pipeline_info),
        )


@pytest.mark.parametrize("ast", [None, 123, object()])
def test_enhanced_yaml_manifest_rejects_invalid_ast_types(ast: Any) -> None:
    with pytest.raises(TypeError, match="ast must be a YaraFile"):
        EnhancedYamlSerializer().serialize_rules_manifest(cast(YaraFile, ast))


@pytest.mark.parametrize("ast", [None, 123, object()])
def test_pipeline_convenience_rejects_invalid_ast_types(ast: Any) -> None:
    with pytest.raises(TypeError, match="ast must be a YaraFile"):
        serialize_for_pipeline(cast(YaraFile, ast))


@pytest.mark.parametrize("pipeline_info", [123, "ci", object()])
def test_pipeline_convenience_rejects_invalid_pipeline_info_types(
    pipeline_info: Any,
) -> None:
    with pytest.raises(TypeError, match="pipeline_info must be a dictionary"):
        serialize_for_pipeline(
            _sample_ast(),
            pipeline_info=cast(dict[str, Any], pipeline_info),
        )


@pytest.mark.parametrize("ast", [None, 123, object()])
def test_manifest_convenience_rejects_invalid_ast_types(ast: Any) -> None:
    with pytest.raises(TypeError, match="ast must be a YaraFile"):
        create_rules_manifest(cast(YaraFile, ast))
