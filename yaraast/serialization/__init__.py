"""Advanced serialization for YARA AST.

This module provides multiple serialization formats for AST persistence,
interchange, and versioning in CI/CD pipelines.
"""

from yaraast.serialization.ast_diff import AstDiff, DiffResult, DiffType
from yaraast.serialization.json_serializer import JsonSerializer
from yaraast.serialization.protobuf_serializer import ProtobufSerializer
from yaraast.serialization.roundtrip_serializer import (
    EnhancedYamlSerializer,
    FormattingInfo,
    RoundTripMetadata,
    RoundTripSerializer,
    create_rules_manifest,
    roundtrip_yara,
    serialize_for_pipeline,
)
from yaraast.serialization.yaml_serializer import YamlSerializer

__all__ = [
    "YamlSerializer",
    "ProtobufSerializer",
    "JsonSerializer",
    "AstDiff",
    "DiffType",
    "DiffResult",
    "RoundTripSerializer",
    "EnhancedYamlSerializer",
    "FormattingInfo",
    "RoundTripMetadata",
    "roundtrip_yara",
    "serialize_for_pipeline",
    "create_rules_manifest"
]
