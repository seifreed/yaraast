"""Round-trip serialization preserving comments and formatting."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

from yaraast.parser.parser import Parser
from yaraast.serialization.json_serializer import JsonSerializer
from yaraast.serialization.roundtrip_helpers import (
    build_roundtrip_metadata,
    create_generator,
    detect_formatting,
    serialize_with_roundtrip_metadata,
)
from yaraast.serialization.roundtrip_models import RoundTripMetadata
from yaraast.serialization.roundtrip_pipeline_helpers import (
    build_pipeline_metadata,
    build_pipeline_statistics,
    build_rules_manifest,
)
from yaraast.serialization.roundtrip_pipeline_helpers import (
    collect_all_tags as helper_collect_all_tags,
)
from yaraast.serialization.roundtrip_pipeline_helpers import (
    count_string_types as helper_count_string_types,
)
from yaraast.serialization.roundtrip_pipeline_helpers import dump_pipeline_yaml
from yaraast.serialization.yaml_serializer import YamlSerializer

if TYPE_CHECKING:
    from yaraast.ast.base import YaraFile


class RoundTripSerializer:
    """Enhanced serializer for round-trip YARA ↔ AST conversion with preservation."""

    def __init__(
        self,
        preserve_comments: bool = True,
        preserve_formatting: bool = True,
    ) -> None:
        self.preserve_comments = preserve_comments
        self.preserve_formatting = preserve_formatting
        self.json_serializer = JsonSerializer(include_metadata=True)
        self.yaml_serializer = YamlSerializer(include_metadata=True)
        self.parser = Parser()

    def _detect_formatting(self, yara_source: str):
        """Backward-compatible wrapper used by tests."""
        return detect_formatting(yara_source)

    def parse_and_serialize(
        self,
        yara_source: str,
        source_file: str | None = None,
        format: str = "json",
    ) -> tuple[YaraFile, str]:
        """Parse YARA source and serialize with metadata."""
        # Detect formatting info from source
        detect_formatting(yara_source)

        # Parse with comment preservation
        ast = self.parser.parse(yara_source)

        # Create round-trip metadata
        metadata = build_roundtrip_metadata(
            yara_source,
            source_file,
            self.preserve_comments,
            self.preserve_formatting,
        )

        # Serialize with metadata
        if format.lower() == "yaml":
            serialized = serialize_with_roundtrip_metadata(
                self.yaml_serializer,
                ast,
                metadata,
                "yaml",
            )
        else:
            serialized = serialize_with_roundtrip_metadata(
                self.json_serializer,
                ast,
                metadata,
                "json",
            )

        return ast, serialized

    def deserialize_and_generate(
        self,
        serialized_data: str,
        format: str = "json",
        preserve_original_formatting: bool = True,
    ) -> tuple[YaraFile, str]:
        """Deserialize and generate YARA code with preserved formatting."""
        # Load serialized data
        if format.lower() == "yaml":
            data = yaml.safe_load(serialized_data)
        else:
            data = json.loads(serialized_data)

        # Extract metadata and AST
        roundtrip_metadata = None
        if "roundtrip_metadata" in data:
            roundtrip_metadata = RoundTripMetadata.from_dict(data["roundtrip_metadata"])

        # Deserialize AST
        if format.lower() == "yaml":
            ast = self.yaml_serializer.deserialize(serialized_data)
        else:
            ast = self.json_serializer.deserialize(serialized_data)

        # Generate YARA code with preserved formatting
        generator = create_generator(
            roundtrip_metadata,
            preserve_original_formatting,
            self.preserve_comments,
        )
        yara_code = generator.generate(ast)

        return ast, yara_code

    def roundtrip_test(self, yara_source: str, format: str = "json") -> dict[str, Any]:
        """Test round-trip conversion and report differences."""
        # Original → AST → Serialized
        original_ast, serialized = self.parse_and_serialize(yara_source, format=format)

        # Serialized → AST → YARA
        reconstructed_ast, reconstructed_yara = self.deserialize_and_generate(
            serialized,
            format=format,
        )

        # Compare results
        result = {
            "original_source": yara_source,
            "reconstructed_source": reconstructed_yara,
            "serialized_data": serialized,
            "format": format,
            "round_trip_successful": True,
            "differences": [],
            "metadata": {},
        }

        # Basic comparison (could be enhanced with AST structural comparison)
        original_lines = yara_source.strip().split("\n")
        reconstructed_lines = reconstructed_yara.strip().split("\n")

        if len(original_lines) != len(reconstructed_lines):
            result["differences"].append(
                f"Line count differs: {len(original_lines)} vs {len(reconstructed_lines)}",
            )

        # Line-by-line comparison (simplified)
        for i, (orig, recon) in enumerate(
            zip(original_lines, reconstructed_lines, strict=False),
        ):
            if orig.strip() != recon.strip():
                result["differences"].append(
                    f"Line {i + 1} differs: '{orig.strip()}' vs '{recon.strip()}'",
                )

        result["round_trip_successful"] = len(result["differences"]) == 0
        result["metadata"]["original_rule_count"] = len(original_ast.rules)
        result["metadata"]["reconstructed_rule_count"] = len(reconstructed_ast.rules)

        return result


class EnhancedYamlSerializer(YamlSerializer):
    """Enhanced YAML serializer with CI/CD pipeline features."""

    def __init__(
        self,
        include_metadata: bool = True,
        flow_style: bool = False,
        include_pipeline_metadata: bool = True,
    ) -> None:
        super().__init__(include_metadata, flow_style)
        self.include_pipeline_metadata = include_pipeline_metadata

    def serialize_for_pipeline(
        self,
        ast: YaraFile,
        pipeline_info: dict[str, Any] | None = None,
        output_path: str | Path | None = None,
    ) -> str:
        """Serialize for CI/CD pipeline with additional metadata."""
        serialized = self._serialize_with_metadata(ast)

        if self.include_pipeline_metadata:
            serialized["pipeline_metadata"] = build_pipeline_metadata(
                self.include_pipeline_metadata, pipeline_info
            )

        # Add rule statistics for pipeline
        serialized["statistics"] = build_pipeline_statistics(ast)
        return dump_pipeline_yaml(serialized, output_path, width=100, explicit_markers=True)

    def serialize_rules_manifest(
        self,
        ast: YaraFile,
        output_path: str | Path | None = None,
    ) -> str:
        """Create a rules manifest for pipeline automation."""
        manifest = build_rules_manifest(ast)
        return dump_pipeline_yaml(manifest, output_path)

    def _collect_all_tags(self, ast: YaraFile) -> list[str]:
        """Collect all unique tags from rules."""
        return helper_collect_all_tags(ast)

    def _count_string_types(self, ast: YaraFile) -> dict[str, int]:
        """Count different types of string patterns."""
        return helper_count_string_types(ast)


# Convenience functions
def roundtrip_yara(yara_source: str, format: str = "json") -> dict[str, Any]:
    """Perform round-trip conversion test on YARA source."""
    serializer = RoundTripSerializer()
    return serializer.roundtrip_test(yara_source, format)


def serialize_for_pipeline(
    ast: YaraFile,
    pipeline_info: dict[str, Any] | None = None,
) -> str:
    """Serialize AST for CI/CD pipeline."""
    serializer = EnhancedYamlSerializer(include_pipeline_metadata=True)
    return serializer.serialize_for_pipeline(ast, pipeline_info)


def create_rules_manifest(ast: YaraFile) -> str:
    """Create rules manifest for pipeline automation."""
    serializer = EnhancedYamlSerializer()
    return serializer.serialize_rules_manifest(ast)
