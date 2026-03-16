"""Protobuf serialization for YARA AST."""

from __future__ import annotations

import warnings
from pathlib import Path
from typing import TYPE_CHECKING, Any

from yaraast.serialization.protobuf_conversion import (
    ast_to_protobuf,
    convert_expression_to_protobuf,
    convert_hex_token_to_protobuf,
    convert_rule_to_protobuf,
    convert_string_to_protobuf,
    protobuf_to_ast,
)
from yaraast.visitor.defaults import DefaultASTVisitor

from . import yara_ast_pb2

if TYPE_CHECKING:
    from yaraast.ast.base import YaraFile

# Suppress protobuf version warning before import
warnings.filterwarnings(
    "ignore",
    category=UserWarning,
    message=".*Protobuf gencode version.*",
    module="google.protobuf.runtime_version",
)


class ProtobufSerializer(DefaultASTVisitor[Any]):
    """Protobuf serializer for YARA AST with efficient binary format."""

    def __init__(self, include_metadata: bool = True) -> None:
        super().__init__(default=None)
        self.include_metadata = include_metadata

    def serialize(self, ast: YaraFile, output_path: str | Path | None = None) -> bytes:
        """Serialize AST to Protobuf binary format."""
        pb_yara_file = self._ast_to_protobuf(ast)
        binary_data = pb_yara_file.SerializeToString()

        if output_path:
            with Path(output_path).open("wb") as f:
                f.write(binary_data)

        return binary_data

    def serialize_text(
        self,
        ast: YaraFile,
        output_path: str | Path | None = None,
    ) -> str:
        """Serialize AST to Protobuf text format (for debugging)."""
        pb_yara_file = self._ast_to_protobuf(ast)
        text_data = str(pb_yara_file)

        if output_path:
            with Path(output_path).open("w", encoding="utf-8") as f:
                f.write(text_data)

        return text_data

    def deserialize(
        self,
        binary_data: bytes | None = None,
        input_path: str | Path | None = None,
    ) -> YaraFile:
        """Deserialize Protobuf binary to AST."""
        if input_path:
            with Path(input_path).open("rb") as f:
                binary_data = f.read()

        if not binary_data:
            msg = "No binary data provided"
            raise ValueError(msg)

        pb_yara_file = yara_ast_pb2.YaraFile()
        pb_yara_file.ParseFromString(binary_data)

        return self._protobuf_to_ast(pb_yara_file)

    def _ast_to_protobuf(self, ast: YaraFile) -> yara_ast_pb2.YaraFile:
        """Convert AST to Protobuf message."""
        return ast_to_protobuf(ast, include_metadata=self.include_metadata)

    def _convert_rule_to_protobuf(self, rule, pb_rule) -> None:
        """Convert rule AST to Protobuf."""
        convert_rule_to_protobuf(rule, pb_rule)

    def _convert_string_to_protobuf(self, string_def, pb_string) -> None:
        """Convert string definition to Protobuf."""
        convert_string_to_protobuf(string_def, pb_string)

    def _convert_hex_token_to_protobuf(self, token, pb_token) -> None:
        """Convert hex token to Protobuf."""
        convert_hex_token_to_protobuf(token, pb_token)

    def _convert_expression_to_protobuf(self, expr, pb_expr) -> None:
        """Convert expression to Protobuf."""
        convert_expression_to_protobuf(expr, pb_expr)

    def _protobuf_to_ast(self, pb_file: yara_ast_pb2.YaraFile) -> YaraFile:
        """Convert Protobuf message to AST."""
        return protobuf_to_ast(pb_file)

    def get_serialization_stats(self, ast: YaraFile) -> dict[str, Any]:
        """Get statistics about the serialization."""
        pb_file = self._ast_to_protobuf(ast)
        binary_size = len(pb_file.SerializeToString())
        text_size = len(str(pb_file))

        return {
            "binary_size_bytes": binary_size,
            "text_size_bytes": text_size,
            "compression_ratio": text_size / binary_size if binary_size > 0 else 0,
            "rules_count": len(ast.rules),
            "imports_count": len(ast.imports),
            "includes_count": len(ast.includes),
        }
