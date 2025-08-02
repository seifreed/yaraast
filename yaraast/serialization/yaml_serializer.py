"""YAML serialization for YARA AST."""

from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import yaml

from yaraast.ast.base import YaraFile
from yaraast.serialization.json_serializer import JsonSerializer


class YamlSerializer(JsonSerializer):
    """YAML serializer for YARA AST with human-readable output."""

    def __init__(self, include_metadata: bool = True, flow_style: bool = False):
        super().__init__(include_metadata)
        self.flow_style = flow_style

    def serialize(self, ast: YaraFile, output_path: Optional[Union[str, Path]] = None) -> str:
        """Serialize AST to YAML format."""
        serialized = self._serialize_with_metadata(ast)

        # Configure YAML output for readability
        yaml_str = yaml.dump(
            serialized,
            default_flow_style=self.flow_style,
            allow_unicode=True,
            sort_keys=False,
            indent=2,
            width=120
        )

        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(yaml_str)

        return yaml_str

    def deserialize(self, yaml_str: Optional[str] = None,
                   input_path: Optional[Union[str, Path]] = None) -> YaraFile:
        """Deserialize YAML to AST."""
        if input_path:
            with open(input_path, 'r', encoding='utf-8') as f:
                yaml_str = f.read()

        if not yaml_str:
            raise ValueError("No YAML input provided")

        data = yaml.safe_load(yaml_str)
        return self._deserialize_ast(data)

    def _serialize_with_metadata(self, ast: YaraFile) -> Dict[str, Any]:
        """Serialize with YAML-specific metadata."""
        result = super()._serialize_with_metadata(ast)

        if self.include_metadata:
            result["metadata"]["format"] = "yaraast-yaml"
            result["metadata"]["serializer"] = "YamlSerializer"

            # Add YAML-specific metadata
            result["metadata"]["yaml_features"] = {
                "flow_style": self.flow_style,
                "human_readable": True,
                "preserves_order": True
            }

        return result

    def serialize_minimal(self, ast: YaraFile, output_path: Optional[Union[str, Path]] = None) -> str:
        """Serialize AST to minimal YAML format (AST only, no metadata)."""
        ast_data = self.visit(ast)

        yaml_str = yaml.dump(
            ast_data,
            default_flow_style=False,
            allow_unicode=True,
            sort_keys=False,
            indent=2
        )

        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(yaml_str)

        return yaml_str

    def serialize_rules_only(self, ast: YaraFile, output_path: Optional[Union[str, Path]] = None) -> str:
        """Serialize only the rules section to YAML (useful for rule analysis)."""
        rules_data = {
            "rules": [self.visit(rule) for rule in ast.rules],
            "rule_count": len(ast.rules)
        }

        yaml_str = yaml.dump(
            rules_data,
            default_flow_style=False,
            allow_unicode=True,
            sort_keys=False,
            indent=2
        )

        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(yaml_str)

        return yaml_str
