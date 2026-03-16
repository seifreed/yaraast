"""Real tests for round-trip serialization (no mocks)."""

from __future__ import annotations

import json
from textwrap import dedent

import yaml

from yaraast.serialization.roundtrip_serializer import (
    EnhancedYamlSerializer,
    RoundTripSerializer,
    create_rules_manifest,
    roundtrip_yara,
    serialize_for_pipeline,
)


def _sample_rule() -> str:
    return dedent(
        """
        import "pe"

        rule alpha : tag1 {
            meta:
                author = "unit"
            strings:
                $a = "abc" ascii
                $b = { 01 02 03 }
            condition:
                $a and pe.number_of_sections > 0
        }
        """,
    )


def test_roundtrip_serializer_json_metadata() -> None:
    serializer = RoundTripSerializer()
    ast, serialized = serializer.parse_and_serialize(_sample_rule(), format="json")

    data = json.loads(serialized)
    assert "roundtrip_metadata" in data
    assert data["roundtrip_metadata"]["formatting"]["indent_size"] >= 2
    assert data["ast"]["type"] == "YaraFile"
    assert len(ast.rules) == 1


def test_roundtrip_serializer_yaml_reconstructs() -> None:
    serializer = RoundTripSerializer()
    _, serialized = serializer.parse_and_serialize(_sample_rule(), format="yaml")

    reconstructed_ast, reconstructed = serializer.deserialize_and_generate(
        serialized,
        format="yaml",
    )

    assert reconstructed_ast.rules
    assert "rule alpha" in reconstructed


def test_roundtrip_test_reports_metadata_and_differences() -> None:
    result = roundtrip_yara(_sample_rule(), format="json")

    assert result["format"] == "json"
    assert isinstance(result["differences"], list)
    assert result["metadata"]["original_rule_count"] == 1
    assert result["metadata"]["reconstructed_rule_count"] == 1


def test_enhanced_yaml_pipeline_and_manifest(tmp_path) -> None:
    serializer = RoundTripSerializer()
    ast, _ = serializer.parse_and_serialize(_sample_rule(), format="json")

    pipeline_yaml = serialize_for_pipeline(ast, pipeline_info={"ci": "true"})
    pipeline_data = yaml.safe_load(pipeline_yaml)
    assert pipeline_data["pipeline_metadata"]["ci"] == "true"
    assert pipeline_data["statistics"]["total_rules"] == 1

    manifest_yaml = create_rules_manifest(ast)
    manifest_data = yaml.safe_load(manifest_yaml)
    assert manifest_data["summary"]["total_rules"] == 1

    enhanced = EnhancedYamlSerializer()
    out_path = tmp_path / "manifest.yaml"
    _ = enhanced.serialize_rules_manifest(ast, output_path=out_path)
    assert out_path.exists()
