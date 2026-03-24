"""Additional tests for JSON serializer (no mocks)."""

from __future__ import annotations

import json

import pytest

from yaraast.ast.base import YaraFile
from yaraast.ast.conditions import InExpression
from yaraast.ast.expressions import BinaryExpression, Identifier, IntegerLiteral, StringIdentifier
from yaraast.ast.modifiers import StringModifier
from yaraast.ast.modules import DictionaryAccess, ModuleReference
from yaraast.ast.rules import Import, Rule
from yaraast.ast.strings import HexJump, HexString, PlainString, RegexString
from yaraast.errors import SerializationError
from yaraast.serialization.json_serializer import JsonSerializer


def _sample_ast() -> YaraFile:
    rule = Rule(
        name="r1",
        tags=[],
        meta={"author": "me"},
        strings=[
            PlainString(
                identifier="$a",
                value="x",
                modifiers=[StringModifier.from_name_value("ascii")],
            ),
            RegexString(identifier="$b", regex="ab.*"),
            HexString(identifier="$c", tokens=[HexJump(min_jump=1, max_jump=2)]),
        ],
        condition=BinaryExpression(
            left=Identifier(name="true"),
            operator="and",
            right=InExpression(subject="a", range=IntegerLiteral(value=10)),
        ),
    )
    return YaraFile(imports=[Import(module="pe")], includes=[], rules=[rule])


def test_json_serialize_deserialize_roundtrip() -> None:
    serializer = JsonSerializer(include_metadata=True)
    ast = _sample_ast()

    json_str = serializer.serialize(ast)
    data = json.loads(json_str)
    assert data["metadata"]["rules_count"] == 1

    restored = serializer.deserialize(json_str)
    assert restored.rules[0].name == "r1"
    assert restored.rules[0].strings


def test_json_deserialize_expressions() -> None:
    serializer = JsonSerializer()

    expr_data = {
        "type": "DictionaryAccess",
        "object": {"type": "ModuleReference", "module": "pe"},
        "key": {"type": "StringLiteral", "value": "CompanyName"},
    }
    expr = serializer._deserialize_expression(expr_data)
    assert isinstance(expr, DictionaryAccess)
    assert isinstance(expr.object, ModuleReference)

    in_expr_data = {
        "type": "InExpression",
        "string_id": {"type": "StringIdentifier", "name": "$a"},
        "range": {"type": "IntegerLiteral", "value": 5},
    }
    in_expr = serializer._deserialize_expression(in_expr_data)
    assert isinstance(in_expr.subject, StringIdentifier)


def test_json_deserialize_errors() -> None:
    serializer = JsonSerializer()

    with pytest.raises(SerializationError):
        serializer._deserialize_string({"type": "UnknownString"})

    with pytest.raises(SerializationError):
        serializer._deserialize_expression({"type": "UnknownExpr"})
