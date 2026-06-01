"""Additional tests for YAML serializer (no mocks)."""

from __future__ import annotations

from typing import Any, cast

import pytest

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import BooleanLiteral
from yaraast.ast.modifiers import StringModifier
from yaraast.ast.rules import Import, Include, Rule, Tag
from yaraast.ast.strings import PlainString
from yaraast.codegen.generator import CodeGenerator
from yaraast.errors import SerializationError
from yaraast.parser import Parser
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


def test_yaml_serializer_rejects_malformed_yaml() -> None:
    serializer = YamlSerializer()
    with pytest.raises(SerializationError, match="Invalid YAML input"):
        serializer.deserialize("ast: [")


def test_yaml_minimal_and_rules_only() -> None:
    serializer = YamlSerializer(include_metadata=True)
    ast = _sample_ast()

    minimal = serializer.serialize_minimal(ast)
    assert "metadata" not in minimal
    assert "rules" in minimal

    rules_only = serializer.serialize_rules_only(ast)
    assert "rule_count" in rules_only


@pytest.mark.parametrize("ast", [None, 123, object()])
def test_yaml_rules_only_rejects_invalid_ast_types(ast: object) -> None:
    serializer = YamlSerializer()

    with pytest.raises(TypeError, match="ast must be a YaraFile"):
        serializer.serialize_rules_only(cast(Any, ast))


@pytest.mark.parametrize("ast", [None, 123, object()])
def test_yaml_serializers_reject_invalid_ast_types(ast: object) -> None:
    serializer = YamlSerializer()

    with pytest.raises(TypeError, match="ast must be a YaraFile"):
        serializer.serialize(cast(Any, ast))

    with pytest.raises(TypeError, match="ast must be a YaraFile"):
        serializer.serialize_minimal(cast(Any, ast))


def test_yaml_roundtrip_preserves_xor_range_modifier() -> None:
    serializer = YamlSerializer(include_metadata=False)
    ast = YaraFile(
        rules=[
            Rule(
                name="xor_range",
                strings=[
                    PlainString(
                        identifier="$a",
                        value="a",
                        modifiers=[StringModifier.from_name_value("xor", (1, 3))],
                    )
                ],
                condition=BooleanLiteral(value=True),
            )
        ]
    )

    restored = serializer.deserialize(serializer.serialize(ast))

    assert restored.rules[0].strings[0].modifiers[0].value == (1, 3)


def test_yaml_roundtrip_preserves_anonymous_strings_for_codegen() -> None:
    serializer = YamlSerializer(include_metadata=False)
    ast = Parser(
        'rule r { strings: $ = "abc" $ = { 41 } $ = /def/ condition: any of them }'
    ).parse()

    restored = serializer.deserialize(serializer.serialize(ast))
    restored_strings = restored.rules[0].strings

    assert [string.is_anonymous for string in restored_strings] == [True, True, True]
    output = CodeGenerator().generate(restored)
    assert '$ = "abc"' in output
    assert "$ = { 41 }" in output
    assert "$ = /def/" in output
    assert "$anon_" not in output
