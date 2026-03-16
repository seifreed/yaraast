"""Additional real coverage for roundtrip and simple roundtrip serializers."""

from __future__ import annotations

from pathlib import Path

import yaml

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import BooleanLiteral
from yaraast.ast.rules import Rule
from yaraast.ast.strings import RegexString
from yaraast.serialization.json_serializer import JsonSerializer
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


def test_simple_roundtrip_test_handles_real_type_error() -> None:
    runner = SimpleRoundTrip()

    success, original_ast, regenerated_ast = runner.test(None)  # type: ignore[arg-type]

    assert success is False
    assert original_ast is None
    assert regenerated_ast is None


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
