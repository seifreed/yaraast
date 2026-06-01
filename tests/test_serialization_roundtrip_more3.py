"""Additional real coverage for roundtrip and simple roundtrip serializers."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

import pytest
import yaml

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import BooleanLiteral
from yaraast.ast.rules import Rule
from yaraast.ast.strings import RegexString
from yaraast.errors import SerializationError
from yaraast.serialization import simple_roundtrip as simple_roundtrip_module
from yaraast.serialization.json_serializer import JsonSerializer
from yaraast.serialization.roundtrip_pipeline_helpers import (
    build_pipeline_statistics,
    build_rules_manifest,
)
from yaraast.serialization.roundtrip_serializer import EnhancedYamlSerializer
from yaraast.serialization.simple_roundtrip import SimpleRoundTrip


def _sample_ast() -> YaraFile:
    return YaraFile(rules=[Rule(name="r1", condition=BooleanLiteral(value=True))])


def test_enhanced_yaml_serializer_pipeline_without_pipeline_metadata(tmp_path: Path) -> None:
    serializer = EnhancedYamlSerializer(include_pipeline_metadata=False)
    output = tmp_path / "pipeline.yaml"

    yaml_str = serializer.serialize_for_pipeline(_sample_ast(), output_path=output)
    assert output.exists()

    data = yaml.safe_load(yaml_str)
    assert "pipeline_metadata" not in data
    assert data["statistics"]["total_rules"] == 1


def test_enhanced_yaml_serializer_counts_regex_strings() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="r2",
                strings=[RegexString(identifier="$r", regex="ab+")],
                condition=BooleanLiteral(value=True),
            ),
        ],
    )

    serializer = EnhancedYamlSerializer(include_pipeline_metadata=False)
    data = yaml.safe_load(serializer.serialize_for_pipeline(ast))
    assert data["statistics"]["string_patterns"]["regex"] == 1


_PIPELINE_HELPERS: dict[str, Callable[[YaraFile], dict[str, Any]]] = {
    "statistics": build_pipeline_statistics,
    "manifest": build_rules_manifest,
}


@pytest.mark.parametrize(
    ("helper_name", "field_name", "message"),
    [
        ("statistics", "imports", "YaraFile imports"),
        ("statistics", "rules", "YaraFile rules"),
        ("manifest", "imports", "YaraFile imports"),
        ("manifest", "includes", "YaraFile includes"),
        ("manifest", "rules", "YaraFile rules"),
    ],
)
def test_roundtrip_pipeline_helpers_reject_invalid_yara_file_collections(
    helper_name: str,
    field_name: str,
    message: str,
) -> None:
    ast = _sample_ast()
    setattr(ast, field_name, "")

    with pytest.raises(SerializationError, match=message):
        _PIPELINE_HELPERS[helper_name](ast)


@pytest.mark.parametrize(
    ("helper_name", "field_name", "message"),
    [
        ("statistics", "tags", "Rule tags"),
        ("statistics", "strings", "Rule strings"),
        ("manifest", "modifiers", "Rule modifiers"),
        ("manifest", "tags", "Rule tags"),
        ("manifest", "meta", "Rule meta"),
        ("manifest", "strings", "Rule strings"),
    ],
)
def test_roundtrip_pipeline_helpers_reject_invalid_rule_collections(
    helper_name: str,
    field_name: str,
    message: str,
) -> None:
    ast = _sample_ast()
    setattr(ast.rules[0], field_name, "")

    with pytest.raises(SerializationError, match=message):
        _PIPELINE_HELPERS[helper_name](ast)


def test_simple_roundtrip_test_handles_real_type_error() -> None:
    runner = SimpleRoundTrip()

    success, original_ast, regenerated_ast = runner.test(cast(Any, None))

    assert success is False
    assert original_ast is None
    assert regenerated_ast is None


def test_simple_roundtrip_test_propagates_internal_parser_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_parse_yara_source(content: str) -> YaraFile:
        raise AttributeError("broken parser internals")

    monkeypatch.setattr(simple_roundtrip_module, "parse_yara_source", fail_parse_yara_source)

    with pytest.raises(AttributeError, match="broken parser internals"):
        SimpleRoundTrip().test("rule r { condition: true }")


def test_roundtrip_deserialize_without_roundtrip_metadata_uses_plain_json() -> None:
    ast = _sample_ast()
    serializer = JsonSerializer(include_metadata=True)
    payload = serializer.serialize(ast)

    from yaraast.serialization.roundtrip_serializer import RoundTripSerializer

    restored_ast, generated = RoundTripSerializer().deserialize_and_generate(
        payload,
        format="json",
    )
    assert restored_ast.rules[0].name == "r1"
    assert "rule r1" in generated
