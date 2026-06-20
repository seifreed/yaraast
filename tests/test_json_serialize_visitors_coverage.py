"""Coverage for JSON serialization visitors over diverse and YARA-X nodes."""

from __future__ import annotations

import json

import pytest

from yaraast.ast.base import YaraFile
from yaraast.ast.rules import Rule
from yaraast.errors import SerializationError
from yaraast.parser.source import parse_yara_source
from yaraast.serialization import json_serialize_visitors as visitors
from yaraast.serialization.json_serializer import JsonSerializer
from yaraast.yarax.parser import YaraXParser

RICH_RULE = (
    "rule r {\n"
    "    strings:\n"
    '        $a = "x"\n'
    "        $b = { 4D 5A ?? F? [2-4] ( 90 | 91 ) ~AA }\n"
    "        $c = /ab[0-9]+/ nocase\n"
    "    condition:\n"
    "        $a at 0 and any of them and $b in (0..10) and #a > 0\n"
    "}"
)


def test_serialize_rich_rule_produces_json() -> None:
    ast = parse_yara_source(RICH_RULE)
    serialized = JsonSerializer().serialize(ast)
    assert isinstance(json.loads(serialized), dict)


@pytest.mark.parametrize(
    "condition",
    [
        "[x for x in (1, 2, 3) if x > 0]",
        "{k: v for k, v in pairs}",
        "lambda x: x + 1",
        "(1, 2, 3)[0]",
        "[...a, b]",
        '{**a, "k": 1}',
        "arr[0:2:1]",
        "match v { 1 => true, _ => false }",
    ],
)
def test_serialize_yarax_expression_conditions(condition: str) -> None:
    expr = YaraXParser(condition).parse_expression()
    serialized = JsonSerializer().serialize(YaraFile(rules=[Rule(name="yx", condition=expr)]))
    assert isinstance(json.loads(serialized), dict)


@pytest.mark.parametrize(
    "serializer",
    [
        visitors._serialize_meta_value,
        visitors._serialize_meta_entry_value,
        visitors._serialize_pragma_parameter_value,
    ],
)
def test_meta_value_serializers_reject_unsupported(serializer) -> None:
    with pytest.raises(SerializationError):
        serializer(object())


def test_meta_value_serializers_accept_scalars() -> None:
    assert visitors._serialize_meta_value("text") == "text"
    assert visitors._serialize_meta_value(5) == 5
    assert visitors._serialize_meta_value(True) is True
    assert visitors._serialize_meta_entry_value(1.5) == 1.5
    assert visitors._serialize_pragma_parameter_value(2.5) == 2.5


def test_meta_entry_value_rejects_non_finite_float() -> None:
    with pytest.raises(SerializationError):
        visitors._serialize_meta_entry_value(float("inf"))
