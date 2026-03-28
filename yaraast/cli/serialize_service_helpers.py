"""Helper functions for CLI serialization services."""

from __future__ import annotations

from yaraast.ast.base import YaraFile
from yaraast.errors import ValidationError
from yaraast.serialization.json_serializer import JsonSerializer
from yaraast.serialization.protobuf_serializer import ProtobufSerializer
from yaraast.serialization.yaml_serializer import YamlSerializer


def create_serializer(fmt: str, *, include_metadata: bool = True):
    if fmt == "json":
        return JsonSerializer(include_metadata=include_metadata)
    if fmt == "yaml":
        return YamlSerializer(include_metadata=include_metadata)
    if fmt == "protobuf":
        return ProtobufSerializer(include_metadata=include_metadata)
    raise ValidationError(f"Unknown format: {fmt}")


def export_with_serializer(
    ast: YaraFile, fmt: str, output: str | None, minimal: bool
) -> tuple[str | None, dict | None]:
    serializer = create_serializer(fmt, include_metadata=not minimal)
    if fmt == "json":
        return serializer.serialize(ast, output), None
    if fmt == "yaml":
        if minimal:
            return serializer.serialize_minimal(ast, output), None
        return serializer.serialize(ast, output), None
    if output and output.endswith(".txt"):
        return serializer.serialize_text(ast, output), None
    result = serializer.serialize(ast, output)
    return result, serializer.get_serialization_stats(ast)
