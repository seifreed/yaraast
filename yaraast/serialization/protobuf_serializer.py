"""Protobuf serialization for YARA AST."""

from __future__ import annotations

from pathlib import Path
from typing import Any
import warnings

from google.protobuf.message import DecodeError

from yaraast.ast.base import YaraFile
from yaraast.errors import SerializationError
from yaraast.serialization.protobuf_conversion import (
    ast_to_protobuf,
    convert_expression_to_protobuf,
    convert_hex_token_to_protobuf,
    convert_rule_to_protobuf,
    convert_string_to_protobuf,
    protobuf_to_ast,
)
from yaraast.serialization.serializer_helpers import require_bool_option, require_input_path
from yaraast.visitor.defaults import DefaultASTVisitor

from . import yara_ast_pb2

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
        self.include_metadata = require_bool_option(include_metadata, "include_metadata")

    @staticmethod
    def _require_yara_file(ast: object) -> YaraFile:
        if not isinstance(ast, YaraFile):
            msg = "ast must be a YaraFile"
            raise TypeError(msg)
        return ast

    def serialize(self, ast: YaraFile, output_path: str | Path | None = None) -> bytes:
        """Serialize AST to Protobuf binary format."""
        ast = self._require_yara_file(ast)
        pb_yara_file = self._ast_to_protobuf(ast)
        binary_data = pb_yara_file.SerializeToString(deterministic=True)

        if output_path is not None:
            with require_input_path(output_path, "output_path").open("wb") as f:
                f.write(binary_data)

        return binary_data

    def serialize_text(
        self,
        ast: YaraFile,
        output_path: str | Path | None = None,
    ) -> str:
        """Serialize AST to Protobuf text format (for debugging)."""
        ast = self._require_yara_file(ast)
        pb_yara_file = self._ast_to_protobuf(ast)
        text_data = str(pb_yara_file)

        if output_path is not None:
            with require_input_path(output_path, "output_path").open("w", encoding="utf-8") as f:
                f.write(text_data)

        return text_data

    def deserialize(
        self,
        binary_data: bytes | None = None,
        input_path: str | Path | None = None,
    ) -> YaraFile:
        """Deserialize Protobuf binary to AST."""
        if input_path is not None:
            with require_input_path(input_path, "input_path").open("rb") as f:
                binary_data = f.read()

        if binary_data is None:
            msg = "No binary data provided"
            raise SerializationError(msg)
        if not isinstance(binary_data, bytes):
            msg = "binary_data must be bytes"
            raise TypeError(msg)

        pb_yara_file = yara_ast_pb2.YaraFile()
        try:
            pb_yara_file.ParseFromString(binary_data)
        except DecodeError as exc:
            msg = "Invalid Protobuf input"
            raise SerializationError(msg) from exc

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
        ast = self._require_yara_file(ast)
        pb_file = self._ast_to_protobuf(ast)
        binary_size = len(pb_file.SerializeToString(deterministic=True))
        text_size = len(str(pb_file))

        return {
            "binary_size_bytes": binary_size,
            "text_size_bytes": text_size,
            "compression_ratio": text_size / binary_size if binary_size > 0 else 0,
            "rules_count": len(ast.rules),
            "imports_count": len(ast.imports),
            "includes_count": len(ast.includes),
        }
