"""Simple roundtrip serialization for YARA AST."""

from __future__ import annotations

from collections.abc import Sequence
from os import PathLike, fspath
from pathlib import Path
from typing import Any

from yaraast.ast.base import ASTNode
from yaraast.errors import YaraASTError
from yaraast.parser.parser import Parser
from yaraast.parser.source import parse_yara_source
from yaraast.serialization.simple_roundtrip_helpers import (
    deserialize_from_file,
    deserialize_node,
    serialize_node,
    serialize_to_file,
    simple_roundtrip_report,
    validate_roundtrip,
)
from yaraast.shared.file_patterns import iter_matching_files
from yaraast.yarax.generator import YaraXGenerator


class SimpleRoundtripSerializer:
    """Simple serializer for AST roundtrip testing."""

    def __init__(self) -> None:
        """Initialize the serializer."""
        self.parser = Parser()
        self.generator = YaraXGenerator()

    def serialize(self, node: ASTNode) -> dict[str, Any]:
        """Serialize an AST node to a dictionary."""
        return serialize_node(node)

    def deserialize(self, data: dict[str, Any]) -> ASTNode:
        """Deserialize a dictionary to an AST node."""
        return deserialize_node(data)

    def serialize_to_file(self, node: ASTNode, file_path: str | Path) -> None:
        """Serialize an AST node to a JSON file."""
        serialize_to_file(node, file_path)

    def deserialize_from_file(self, file_path: str | Path) -> ASTNode:
        """Deserialize an AST node from a JSON file."""
        return deserialize_from_file(file_path)

    def validate_roundtrip(self, node: ASTNode) -> tuple[bool, dict[str, Any]]:
        """Validate roundtrip serialization."""
        return validate_roundtrip(node)


class SimpleRoundTrip:
    """Simple roundtrip testing utility."""

    def __init__(self) -> None:
        self.parser = Parser()
        self.generator = YaraXGenerator()
        self.test_count = 0
        self.success_count = 0

    def test(self, yara_code: str) -> tuple[bool, Any, Any]:
        """Test roundtrip for a single YARA rule."""
        self.test_count += 1
        if not isinstance(yara_code, str):
            return False, None, None
        try:
            original_ast = parse_yara_source(yara_code)
            regenerated = self.generator.generate(original_ast)
            regenerated_ast = parse_yara_source(regenerated)

            success = original_ast is not None and regenerated_ast is not None
            if success:
                self.success_count += 1

            return success, original_ast, regenerated_ast
        except (ValueError, YaraASTError):
            return False, None, None

    def test_batch(self, yara_codes: list[str]) -> list[tuple[bool, Any, Any]]:
        """Test multiple YARA rules."""
        if isinstance(yara_codes, str) or not isinstance(yara_codes, Sequence):
            msg = "yara_codes must be a sequence of strings"
            raise TypeError(msg)
        if not all(isinstance(code, str) for code in yara_codes):
            msg = "yara_codes must contain only strings"
            raise TypeError(msg)
        return [self.test(code) for code in yara_codes]

    def test_file(self, file_path: str | PathLike[str]) -> tuple[bool, Any, Any]:
        """Test a YARA file."""
        if isinstance(file_path, bytes) or not isinstance(file_path, str | PathLike):
            msg = "file_path must be a string or path-like object"
            raise TypeError(msg)
        raw_path = fspath(file_path)
        if not raw_path:
            msg = "file_path must not be empty"
            raise ValueError(msg)
        path = Path(raw_path)
        yara_code = path.read_text(encoding="utf-8")
        return self.test(yara_code)

    def test_directory(self, dir_path: str | PathLike[str]) -> list[tuple[Path, bool, Any, Any]]:
        """Test all YARA files in a directory."""
        if isinstance(dir_path, bytes) or not isinstance(dir_path, str | PathLike):
            msg = "dir_path must be a string or path-like object"
            raise TypeError(msg)
        raw_path = fspath(dir_path)
        if not raw_path:
            msg = "dir_path must not be empty"
            raise ValueError(msg)
        dir_path = Path(raw_path)
        results = []
        for yar_file in iter_matching_files(dir_path):
            success, orig, regen = self.test_file(yar_file)
            results.append((yar_file, success, orig, regen))
        return results

    def get_statistics(self) -> dict[str, Any]:
        """Get test statistics."""
        return {
            "total_tests": self.test_count,
            "successful_tests": self.success_count,
            "failed_tests": self.test_count - self.success_count,
            "success_rate": self.success_count / max(1, self.test_count) * 100,
        }


def simple_roundtrip_test(yara_source: str) -> dict[str, Any]:
    """Perform a simple roundtrip test."""
    return simple_roundtrip_report(yara_source)
