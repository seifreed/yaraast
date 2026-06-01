"""YAML serialization for YARA AST."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from yaraast.ast.base import YaraFile
from yaraast.ast.rules import Rule
from yaraast.errors import SerializationError
from yaraast.serialization.json_serializer import JsonSerializer
from yaraast.serialization.serializer_helpers import (
    read_text,
    require_bool_option,
    require_input_path,
)
from yaraast.serialization.yaml_serializer_helpers import enrich_yaml_metadata, serialize_yaml


class YamlSerializer(JsonSerializer):
    """YAML serializer for YARA AST with human-readable output."""

    def __init__(self, include_metadata: bool = True, flow_style: bool = False) -> None:
        super().__init__(include_metadata)
        self.flow_style = require_bool_option(flow_style, "flow_style")

    @staticmethod
    def _require_yara_file(ast: object) -> YaraFile:
        if not isinstance(ast, YaraFile):
            msg = "ast must be a YaraFile"
            raise TypeError(msg)
        return ast

    def serialize(self, ast: YaraFile, output_path: str | Path | None = None) -> str:
        """Serialize AST to YAML format."""
        ast = self._require_yara_file(ast)
        serialized = self._serialize_with_metadata(ast)
        return serialize_yaml(serialized, output_path, flow_style=self.flow_style)

    def deserialize(
        self,
        yaml_str: str | None = None,
        input_path: str | Path | None = None,
    ) -> YaraFile:
        """Deserialize YAML to AST."""
        if input_path is not None:
            yaml_str = read_text(require_input_path(input_path, "input_path"))

        if yaml_str is None or yaml_str == "":
            msg = "No YAML input provided"
            raise SerializationError(msg)
        if not isinstance(yaml_str, str):
            msg = "YAML input must be a string"
            raise TypeError(msg)

        try:
            data = yaml.safe_load(yaml_str)
        except yaml.YAMLError as exc:
            msg = "Invalid YAML input"
            raise SerializationError(msg) from exc
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
        ast = self._require_yara_file(ast)
        ast_data = self.visit(ast)
        return serialize_yaml(ast_data, output_path, flow_style=False)

    def serialize_rules_only(
        self,
        ast: YaraFile,
        output_path: str | Path | None = None,
    ) -> str:
        """Serialize only the rules section to YAML (useful for rule analysis)."""
        ast = self._require_yara_file(ast)
        if not isinstance(ast.rules, list | tuple):
            msg = "YaraFile rules must be a list of Rule nodes"
            raise SerializationError(msg)

        for rule in ast.rules:
            if not isinstance(rule, Rule):
                msg = "YaraFile rules item must be a Rule node"
                raise SerializationError(msg)

        rules_data = {
            "rules": [self.visit(rule) for rule in ast.rules],
            "rule_count": len(ast.rules),
        }
        return serialize_yaml(rules_data, output_path, flow_style=False)
