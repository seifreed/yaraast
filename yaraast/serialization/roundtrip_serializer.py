"""Round-trip serialization preserving comments and formatting."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

from yaraast.codegen.comment_aware_generator import CommentAwareCodeGenerator
from yaraast.parser import Parser
from yaraast.serialization.json_serializer import JsonSerializer
from yaraast.serialization.yaml_serializer import YamlSerializer

if TYPE_CHECKING:
    from yaraast.ast.base import YaraFile


@dataclass
class FormattingInfo:
    """Information about original formatting to preserve."""

    indent_size: int = 4
    indent_style: str = "spaces"  # "spaces" or "tabs"
    line_endings: str = "\n"  # "\n", "\r\n", or "\r"
    blank_lines_before_rule: int = 1
    blank_lines_after_imports: int = 1
    blank_lines_after_includes: int = 1
    comment_style: str = "line"  # "line" (//) or "block" (/* */)
    preserve_spacing: bool = True
    preserve_alignment: bool = True

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "indent_size": self.indent_size,
            "indent_style": self.indent_style,
            "line_endings": self.line_endings,
            "blank_lines_before_rule": self.blank_lines_before_rule,
            "blank_lines_after_imports": self.blank_lines_after_imports,
            "blank_lines_after_includes": self.blank_lines_after_includes,
            "comment_style": self.comment_style,
            "preserve_spacing": self.preserve_spacing,
            "preserve_alignment": self.preserve_alignment,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FormattingInfo:
        """Create from dictionary."""
        return cls(**data)


@dataclass
class RoundTripMetadata:
    """Metadata for round-trip serialization."""

    original_source: str | None = None
    source_file: str | None = None
    parsed_at: str | None = None
    serializer_version: str = "1.0.0"
    formatting: FormattingInfo = field(default_factory=FormattingInfo)
    comments_preserved: bool = True
    formatting_preserved: bool = True
    parser_version: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "original_source": self.original_source,
            "source_file": self.source_file,
            "parsed_at": self.parsed_at,
            "serializer_version": self.serializer_version,
            "formatting": self.formatting.to_dict(),
            "comments_preserved": self.comments_preserved,
            "formatting_preserved": self.formatting_preserved,
            "parser_version": self.parser_version,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RoundTripMetadata:
        """Create from dictionary."""
        formatting_data = data.get("formatting", {})
        formatting = FormattingInfo.from_dict(formatting_data)

        return cls(
            original_source=data.get("original_source"),
            source_file=data.get("source_file"),
            parsed_at=data.get("parsed_at"),
            serializer_version=data.get("serializer_version", "1.0.0"),
            formatting=formatting,
            comments_preserved=data.get("comments_preserved", True),
            formatting_preserved=data.get("formatting_preserved", True),
            parser_version=data.get("parser_version"),
        )


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

    def parse_and_serialize(
        self,
        yara_source: str,
        source_file: str | None = None,
        format: str = "json",
    ) -> tuple[YaraFile, str]:
        """Parse YARA source and serialize with metadata."""
        # Detect formatting info from source
        formatting = self._detect_formatting(yara_source)

        # Parse with comment preservation
        ast = self.parser.parse(yara_source)
        if not ast:
            msg = "Failed to parse YARA source"
            raise ValueError(msg)

        # Create round-trip metadata
        metadata = RoundTripMetadata(
            original_source=(
                yara_source if len(yara_source) < 10000 else None
            ),  # Store if not too large
            source_file=source_file,
            parsed_at=datetime.now().isoformat(),
            formatting=formatting,
            comments_preserved=self.preserve_comments,
            formatting_preserved=self.preserve_formatting,
        )

        # Serialize with metadata
        if format.lower() == "yaml":
            serialized = self._serialize_with_roundtrip_metadata(ast, metadata, "yaml")
        else:
            serialized = self._serialize_with_roundtrip_metadata(ast, metadata, "json")

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
        generator = self._create_generator(
            roundtrip_metadata,
            preserve_original_formatting,
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

    def _detect_formatting(self, source: str) -> FormattingInfo:
        """Detect formatting characteristics from source code."""
        formatting = FormattingInfo()

        lines = source.split("\n")

        # Detect line endings
        if "\r\n" in source:
            formatting.line_endings = "\r\n"
        elif "\r" in source:
            formatting.line_endings = "\r"
        else:
            formatting.line_endings = "\n"

        # Detect indentation
        indent_sizes = []
        for line in lines:
            if line.strip() and line.startswith(" "):
                # Count leading spaces
                leading_spaces = len(line) - len(line.lstrip(" "))
                if leading_spaces > 0:
                    indent_sizes.append(leading_spaces)
            elif line.strip() and line.startswith("\t"):
                formatting.indent_style = "tabs"

        if indent_sizes:
            # Find most common indent size
            from collections import Counter

            indent_counter = Counter(indent_sizes)
            formatting.indent_size = indent_counter.most_common(1)[0][0]

        # Detect comment style
        if "/*" in source and "*/" in source:
            formatting.comment_style = "block"
        elif "//" in source:
            formatting.comment_style = "line"

        return formatting

    def _serialize_with_roundtrip_metadata(
        self,
        ast: YaraFile,
        metadata: RoundTripMetadata,
        format: str,
    ) -> str:
        """Serialize AST with round-trip metadata."""
        if format == "yaml":
            # Get standard YAML serialization
            standard_data = yaml.safe_load(self.yaml_serializer.serialize(ast))
        else:
            # Get standard JSON serialization
            standard_data = json.loads(self.json_serializer.serialize(ast))

        # Add round-trip metadata
        standard_data["roundtrip_metadata"] = metadata.to_dict()

        # Serialize final result
        if format == "yaml":
            return yaml.dump(
                standard_data,
                default_flow_style=False,
                allow_unicode=True,
                sort_keys=False,
                indent=2,
            )
        return json.dumps(standard_data, indent=2, ensure_ascii=False)

    def _create_generator(
        self,
        metadata: RoundTripMetadata | None,
        preserve_original_formatting: bool,
    ) -> CommentAwareCodeGenerator:
        """Create code generator with appropriate formatting settings."""
        if metadata and preserve_original_formatting:
            # Use original formatting settings
            indent_size = metadata.formatting.indent_size
            preserve_comments = metadata.comments_preserved and self.preserve_comments
        else:
            # Use default settings
            indent_size = 4
            preserve_comments = self.preserve_comments

        return CommentAwareCodeGenerator(
            indent_size=indent_size,
            preserve_comments=preserve_comments,
        )


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
            pipeline_metadata = {
                "generated_at": datetime.now().isoformat(),
                "format": "yaraast-pipeline-yaml",
                "version": "1.0.0",
                "features": {
                    "rule_validation": True,
                    "dependency_tracking": True,
                    "change_detection": True,
                    "automated_testing": True,
                },
            }

            if pipeline_info:
                pipeline_metadata.update(pipeline_info)

            serialized["pipeline_metadata"] = pipeline_metadata

        # Add rule statistics for pipeline
        serialized["statistics"] = {
            "total_rules": len(ast.rules),
            "imports": [imp.module for imp in ast.imports],
            "rule_tags": self._collect_all_tags(ast),
            "string_patterns": self._count_string_types(ast),
        }

        # YAML output optimized for readability in CI/CD
        yaml_str = yaml.dump(
            serialized,
            default_flow_style=False,
            allow_unicode=True,
            sort_keys=False,
            indent=2,
            width=100,  # Narrower for CI logs
            explicit_start=True,  # Add --- at start
            explicit_end=True,  # Add ... at end
        )

        if output_path:
            with Path(output_path).open("w", encoding="utf-8") as f:
                f.write(yaml_str)

        return yaml_str

    def serialize_rules_manifest(
        self,
        ast: YaraFile,
        output_path: str | Path | None = None,
    ) -> str:
        """Create a rules manifest for pipeline automation."""
        manifest = {
            "manifest_version": "1.0",
            "generated_at": datetime.now().isoformat(),
            "rules": [],
        }

        for rule in ast.rules:
            rule_info = {
                "name": rule.name,
                "modifiers": rule.modifiers,
                "tags": [tag.name for tag in rule.tags],
                "meta": dict(rule.meta) if isinstance(rule.meta, dict) else {},
                "string_count": len(rule.strings),
                "has_condition": rule.condition is not None,
            }
            manifest["rules"].append(rule_info)

        # Summary statistics
        manifest["summary"] = {
            "total_rules": len(ast.rules),
            "private_rules": len([r for r in ast.rules if "private" in r.modifiers]),
            "global_rules": len([r for r in ast.rules if "global" in r.modifiers]),
            "tagged_rules": len([r for r in ast.rules if r.tags]),
            "imports": [imp.module for imp in ast.imports],
            "includes": [inc.path for inc in ast.includes],
        }

        yaml_str = yaml.dump(
            manifest,
            default_flow_style=False,
            allow_unicode=True,
            sort_keys=False,
            indent=2,
        )

        if output_path:
            with Path(output_path).open("w", encoding="utf-8") as f:
                f.write(yaml_str)

        return yaml_str

    def _collect_all_tags(self, ast: YaraFile) -> list[str]:
        """Collect all unique tags from rules."""
        tags = set()
        for rule in ast.rules:
            for tag in rule.tags:
                tags.add(tag.name)
        return sorted(tags)

    def _count_string_types(self, ast: YaraFile) -> dict[str, int]:
        """Count different types of string patterns."""
        counts = {"plain": 0, "hex": 0, "regex": 0}

        for rule in ast.rules:
            for string_def in rule.strings:
                if hasattr(string_def, "value"):  # PlainString
                    counts["plain"] += 1
                elif hasattr(string_def, "tokens"):  # HexString
                    counts["hex"] += 1
                elif hasattr(string_def, "regex"):  # RegexString
                    counts["regex"] += 1

        return counts


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
