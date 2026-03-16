"""Advanced serialization for YARA AST.

This module provides multiple serialization formats for AST persistence,
interchange, and versioning in CI/CD pipelines.
"""

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

try:
    from yaraast.serialization.protobuf_serializer import ProtobufSerializer
except ImportError:
    ProtobufSerializer = None  # type: ignore[assignment,misc]

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
