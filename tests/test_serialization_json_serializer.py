"""Real tests for JSON serializer (no mocks)."""

from __future__ import annotations

import json

import pytest

from yaraast.parser import Parser
from yaraast.serialization.json_serializer import JsonSerializer


def _parse_yara(code: str):
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
    with pytest.raises(ValueError, match="No JSON input provided"):
        serializer.deserialize(None)


def test_json_serializer_bad_ast_type() -> None:
    serializer = JsonSerializer()
    payload = json.dumps({"type": "NotYaraFile"})
    with pytest.raises(ValueError, match="Expected YaraFile"):
        serializer.deserialize(payload)


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
    with pytest.raises(ValueError, match="Unknown string type"):
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
    with pytest.raises(ValueError, match="Unknown hex token type"):
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
    with pytest.raises(ValueError, match="Unknown expression type"):
        serializer.deserialize(json.dumps(bad_expr))
