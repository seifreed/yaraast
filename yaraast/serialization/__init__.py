"""Advanced serialization for YARA AST.

This module provides multiple serialization formats for AST persistence,
interchange, and versioning in CI/CD pipelines.
"""

from typing import Any

from yaraast.serialization.ast_diff import AstDiff, DiffResult, DiffType
from yaraast.serialization.json_serializer import JsonSerializer
from yaraast.serialization.roundtrip_serializer import (
    EnhancedYamlSerializer,
    RoundTripSerializer,
    create_rules_manifest,
    roundtrip_yara,
    serialize_for_pipeline,
)
from yaraast.serialization.yaml_serializer import YamlSerializer

ProtobufSerializer: Any
_OPTIONAL_PROTOBUF_DEPENDENCY_ROOTS = ("google.protobuf",)


def _is_optional_protobuf_dependency_error(exc: ImportError) -> bool:
    missing_name = exc.name or ""
    return any(
        missing_name == dependency or missing_name.startswith(f"{dependency}.")
        for dependency in _OPTIONAL_PROTOBUF_DEPENDENCY_ROOTS
    )


try:
    from yaraast.serialization.protobuf_serializer import ProtobufSerializer
except ImportError as exc:
    if not _is_optional_protobuf_dependency_error(exc):
        raise
    ProtobufSerializer = None

__all__ = [
    "AstDiff",
    "DiffResult",
    "DiffType",
    "EnhancedYamlSerializer",
    "JsonSerializer",
    "ProtobufSerializer",
    "RoundTripSerializer",
    "YamlSerializer",
    "create_rules_manifest",
    "roundtrip_yara",
    "serialize_for_pipeline",
]
