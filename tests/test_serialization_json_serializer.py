"""Real tests for JSON serializer (no mocks)."""

from __future__ import annotations

from collections.abc import Callable
import json
from typing import Any, cast

import pytest

from yaraast.ast.base import YaraFile
from yaraast.errors import SerializationError
from yaraast.parser import Parser
from yaraast.serialization.json_serializer import JsonSerializer
from yaraast.serialization.protobuf_serializer import ProtobufSerializer
from yaraast.serialization.yaml_serializer import YamlSerializer


def _parse_yara(code: str) -> YaraFile:
    parser = Parser()
    return parser.parse(code)


def test_json_serializer_roundtrip() -> None:
    code = """
    import "pe"

    rule alpha {
        strings:
            $a = "abc"
        condition:
            $a
    }
    """
    ast = _parse_yara(code)
    serializer = JsonSerializer(include_metadata=True)

    data = serializer.serialize(ast)
    parsed = json.loads(data)
    assert parsed["metadata"]["rules_count"] == 1

    reconstructed = serializer.deserialize(data)
    assert len(reconstructed.rules) == 1
    assert reconstructed.rules[0].name == "alpha"


def test_json_serializer_missing_input() -> None:
    serializer = JsonSerializer()
    with pytest.raises(SerializationError, match="No JSON input provided"):
        serializer.deserialize(None)


@pytest.mark.parametrize("json_str", [False, 0, [], 123, object()])
def test_json_serializer_rejects_non_string_input(json_str: Any) -> None:
    serializer = JsonSerializer()
    with pytest.raises(TypeError, match="JSON input must be a string"):
        serializer.deserialize(cast(str, json_str))


@pytest.mark.parametrize("input_path", [False, 0, object()])
def test_json_serializer_rejects_invalid_input_path_types(input_path: Any) -> None:
    serializer = JsonSerializer()
    with pytest.raises(TypeError, match="input_path must be a file path"):
        serializer.deserialize(input_path=cast(Any, input_path))


def test_json_serializer_rejects_empty_input_path() -> None:
    serializer = JsonSerializer()
    with pytest.raises(ValueError, match="input_path must not be empty"):
        serializer.deserialize(input_path="")


@pytest.mark.parametrize("output_path", [False, 0, object()])
def test_json_serializer_rejects_invalid_output_path_types(output_path: Any) -> None:
    serializer = JsonSerializer()
    ast = _parse_yara("rule sample { condition: true }")
    with pytest.raises(TypeError, match="output_path must be a file path"):
        serializer.serialize(ast, output_path=cast(Any, output_path))


def test_json_serializer_rejects_empty_output_path() -> None:
    serializer = JsonSerializer()
    ast = _parse_yara("rule sample { condition: true }")
    with pytest.raises(ValueError, match="output_path must not be empty"):
        serializer.serialize(ast, output_path="")


@pytest.mark.parametrize("ast", [None, False, 0, {}, object()])
def test_json_serializer_rejects_invalid_ast_types(ast: Any) -> None:
    serializer = JsonSerializer()

    with pytest.raises(TypeError, match="ast must be a YaraFile"):
        serializer.serialize(cast(Any, ast))


@pytest.mark.parametrize("yaml_str", [False, 0, [], 123, object()])
def test_yaml_serializer_rejects_non_string_input(yaml_str: Any) -> None:
    serializer = YamlSerializer()
    with pytest.raises(TypeError, match="YAML input must be a string"):
        serializer.deserialize(cast(str, yaml_str))


@pytest.mark.parametrize("input_path", [False, 0, object()])
def test_yaml_serializer_rejects_invalid_input_path_types(input_path: Any) -> None:
    serializer = YamlSerializer()
    with pytest.raises(TypeError, match="input_path must be a file path"):
        serializer.deserialize(input_path=cast(Any, input_path))


def test_yaml_serializer_rejects_empty_input_path() -> None:
    serializer = YamlSerializer()
    with pytest.raises(ValueError, match="input_path must not be empty"):
        serializer.deserialize(input_path="")


@pytest.mark.parametrize("output_path", [False, 0, object()])
def test_yaml_serializer_rejects_invalid_output_path_types(output_path: Any) -> None:
    serializer = YamlSerializer()
    ast = _parse_yara("rule sample { condition: true }")
    with pytest.raises(TypeError, match="output_path must be a file path"):
        serializer.serialize(ast, output_path=cast(Any, output_path))


def test_yaml_serializer_rejects_empty_output_path() -> None:
    serializer = YamlSerializer()
    ast = _parse_yara("rule sample { condition: true }")
    with pytest.raises(ValueError, match="output_path must not be empty"):
        serializer.serialize(ast, output_path="")


def test_json_serializer_rejects_malformed_json() -> None:
    serializer = JsonSerializer()
    with pytest.raises(SerializationError, match="Invalid JSON input"):
        serializer.deserialize("{bad")


def test_json_serializer_bad_ast_type() -> None:
    serializer = JsonSerializer()
    payload = json.dumps({"type": "NotYaraFile"})
    with pytest.raises(SerializationError, match="Expected YaraFile"):
        serializer.deserialize(payload)


@pytest.mark.parametrize(
    "constructor,args,match",
    [
        (JsonSerializer, {"include_metadata": cast(Any, "false")}, "include_metadata"),
        (YamlSerializer, {"include_metadata": cast(Any, 1)}, "include_metadata"),
        (YamlSerializer, {"flow_style": cast(Any, "true")}, "flow_style"),
        (ProtobufSerializer, {"include_metadata": cast(Any, [])}, "include_metadata"),
    ],
)
def test_serializers_reject_non_boolean_options(
    constructor: Callable[..., object],
    args: dict[str, Any],
    match: str,
) -> None:
    with pytest.raises(TypeError, match=match):
        constructor(**args)


def test_json_serializer_unknown_string_and_token_types() -> None:
    serializer = JsonSerializer()
    bad_string = {
        "ast": {
            "type": "YaraFile",
            "imports": [],
            "includes": [],
            "rules": [
                {
                    "type": "Rule",
                    "name": "alpha",
                    "modifiers": [],
                    "tags": [],
                    "meta": [],
                    "strings": [{"type": "UnknownString", "identifier": "$a"}],
                    "condition": None,
                }
            ],
        }
    }
    with pytest.raises(SerializationError, match="Unknown string type"):
        serializer.deserialize(json.dumps(bad_string))

    bad_token = {
        "ast": {
            "type": "YaraFile",
            "imports": [],
            "includes": [],
            "rules": [
                {
                    "type": "Rule",
                    "name": "alpha",
                    "modifiers": [],
                    "tags": [],
                    "meta": [],
                    "strings": [
                        {
                            "type": "HexString",
                            "identifier": "$a",
                            "tokens": [{"type": "HexUnknown"}],
                            "modifiers": [],
                        }
                    ],
                    "condition": None,
                }
            ],
        }
    }
    with pytest.raises(SerializationError, match="Unknown hex token type"):
        serializer.deserialize(json.dumps(bad_token))


def test_json_serializer_unknown_expression_type() -> None:
    serializer = JsonSerializer()
    bad_expr = {
        "ast": {
            "type": "YaraFile",
            "imports": [],
            "includes": [],
            "rules": [
                {
                    "type": "Rule",
                    "name": "alpha",
                    "modifiers": [],
                    "tags": [],
                    "meta": [],
                    "strings": [],
                    "condition": {"type": "UnknownExpr"},
                }
            ],
        }
    }
    with pytest.raises(SerializationError, match="Unknown expression type"):
        serializer.deserialize(json.dumps(bad_expr))
