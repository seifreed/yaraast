"""YAML serialization for YARA AST."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

from yaraast.serialization.json_serializer import JsonSerializer
from yaraast.serialization.serializer_helpers import read_text
from yaraast.serialization.yaml_serializer_helpers import enrich_yaml_metadata, serialize_yaml

if TYPE_CHECKING:
    from yaraast.ast.base import YaraFile


class YamlSerializer(JsonSerializer):
    """YAML serializer for YARA AST with human-readable output."""

    def __init__(self, include_metadata: bool = True, flow_style: bool = False) -> None:
        super().__init__(include_metadata)
        self.flow_style = flow_style

    def serialize(self, ast: YaraFile, output_path: str | Path | None = None) -> str:
        """Serialize AST to YAML format."""
        serialized = self._serialize_with_metadata(ast)
        return serialize_yaml(serialized, output_path, flow_style=self.flow_style)

    def deserialize(
        self,
        yaml_str: str | None = None,
        input_path: str | Path | None = None,
    ) -> YaraFile:
        """Deserialize YAML to AST."""
        if input_path:
            yaml_str = read_text(input_path)

        if not yaml_str:
            msg = "No YAML input provided"
            raise ValueError(msg)

        data = yaml.safe_load(yaml_str)
        return self._deserialize_ast(data)

    def _serialize_with_metadata(self, ast: YaraFile) -> dict[str, Any]:
        """Serialize with YAML-specific metadata."""
        result = super()._serialize_with_metadata(ast)
        return enrich_yaml_metadata(
            result, include_metadata=self.include_metadata, flow_style=self.flow_style
        )

    def serialize_minimal(
        self,
        ast: YaraFile,
        output_path: str | Path | None = None,
    ) -> str:
        """Serialize AST to minimal YAML format (AST only, no metadata)."""
        ast_data = self.visit(ast)
        return serialize_yaml(ast_data, output_path, flow_style=False)

    def serialize_rules_only(
        self,
        ast: YaraFile,
        output_path: str | Path | None = None,
    ) -> str:
        """Serialize only the rules section to YAML (useful for rule analysis)."""
        rules_data = {
            "rules": [self.visit(rule) for rule in ast.rules],
            "rule_count": len(ast.rules),
        }
        return serialize_yaml(rules_data, output_path, flow_style=False)
