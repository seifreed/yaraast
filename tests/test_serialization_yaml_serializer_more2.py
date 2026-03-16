"""Additional tests for YAML serializer (no mocks)."""

from __future__ import annotations

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import BooleanLiteral
from yaraast.ast.rules import Import, Include, Rule, Tag
from yaraast.ast.strings import PlainString
from yaraast.serialization.yaml_serializer import YamlSerializer


def _sample_ast() -> YaraFile:
    rule = Rule(
        name="r1",
        tags=[Tag(name="t1")],
        meta={"author": "me"},
        strings=[PlainString(identifier="$a", value="x")],
        condition=BooleanLiteral(value=True),
    )
    return YaraFile(
        imports=[Import(module="pe")],
        includes=[Include(path="inc.yar")],
        rules=[rule],
    )


def test_yaml_serialize_deserialize_with_metadata() -> None:
    serializer = YamlSerializer(include_metadata=True, flow_style=False)
    ast = _sample_ast()

    yaml_str = serializer.serialize(ast)
    assert "metadata" in yaml_str
    assert "yaraast-yaml" in yaml_str

    restored = serializer.deserialize(yaml_str)
    assert restored.rules[0].name == "r1"
    assert restored.imports[0].module == "pe"


def test_yaml_minimal_and_rules_only() -> None:
    serializer = YamlSerializer(include_metadata=True)
    ast = _sample_ast()

    minimal = serializer.serialize_minimal(ast)
    assert "metadata" not in minimal
    assert "rules" in minimal

    rules_only = serializer.serialize_rules_only(ast)
    assert "rule_count" in rules_only
