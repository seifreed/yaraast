"""Helper functions for CLI serialization services."""

from __future__ import annotations

from yaraast.ast.base import YaraFile
from yaraast.errors import ValidationError
from yaraast.serialization.json_serializer import JsonSerializer
from yaraast.serialization.protobuf_serializer import ProtobufSerializer
from yaraast.serialization.serializer_helpers import require_bool_option
from yaraast.serialization.yaml_serializer import YamlSerializer

_SERIALIZATION_FORMATS = frozenset({"json", "protobuf", "yaml"})


def _require_serialization_format(fmt: object) -> str:
    if not isinstance(fmt, str):
        msg = "serialization format must be a string"
        raise TypeError(msg)
    if fmt not in _SERIALIZATION_FORMATS:
        raise ValidationError(f"Unknown format: {fmt}")
    return fmt


def export_with_serializer(
    ast: YaraFile, fmt: object, output: str | None, minimal: object
) -> tuple[str | None, dict | None]:
    fmt = _require_serialization_format(fmt)
    minimal = require_bool_option(minimal, "minimal")
    if fmt == "json":
        serializer = JsonSerializer(include_metadata=not minimal)
    elif fmt == "yaml":
        serializer = YamlSerializer(include_metadata=not minimal)
    else:
        serializer = ProtobufSerializer(include_metadata=not minimal)
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
