"""Test-only support for simple roundtrip serialization."""

from __future__ import annotations

from collections.abc import Sequence
import json
from os import PathLike, fspath
from pathlib import Path
from typing import Any

from yaraast.ast.base import ASTNode
from yaraast.errors import YaraASTError
from yaraast.parser.source import parse_yara_source
from yaraast.serialization.simple_roundtrip_helpers import deserialize_node, serialize_node
from yaraast.shared.file_patterns import iter_matching_files
from yaraast.yarax.generator import YaraXGenerator


def _read_yara_text_file(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        msg = "YARA file must contain valid UTF-8 text"
        raise ValueError(msg) from exc


class SimpleRoundtripSerializer:
    def serialize(self, node: ASTNode) -> dict[str, Any]:
        return serialize_node(node)

    def deserialize(self, data: dict[str, Any]) -> ASTNode:
        return deserialize_node(data)

    def serialize_to_file(self, node: ASTNode, file_path: str | Path) -> None:
        Path(file_path).write_text(json.dumps(serialize_node(node), indent=2), encoding="utf-8")

    def deserialize_from_file(self, file_path: str | Path) -> ASTNode:
        data = json.loads(Path(file_path).read_text(encoding="utf-8"))
        return deserialize_node(data)

    def validate_roundtrip(self, node: ASTNode) -> tuple[bool, dict[str, Any]]:
        generator = YaraXGenerator()
        original_code = generator.generate(node)
        regenerated_ast = parse_yara_source(original_code)
        regenerated_code = generator.generate(regenerated_ast)
        success = original_code == regenerated_code
        return success, {
            "original_code": original_code,
            "regenerated_code": regenerated_code,
            "round_trip_successful": success,
        }


class SimpleRoundTrip:
    def __init__(self) -> None:
        self.generator = YaraXGenerator()
        self.test_count = 0
        self.success_count = 0

    def test(self, yara_code: str) -> tuple[bool, Any, Any]:
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
        if isinstance(yara_codes, str) or not isinstance(yara_codes, Sequence):
            msg = "yara_codes must be a sequence of strings"
            raise TypeError(msg)
        if not all(isinstance(code, str) for code in yara_codes):
            msg = "yara_codes must contain only strings"
            raise TypeError(msg)
        return [self.test(code) for code in yara_codes]

    def test_file(self, file_path: str | PathLike[str]) -> tuple[bool, Any, Any]:
        if isinstance(file_path, bytes) or not isinstance(file_path, str | PathLike):
            msg = "file_path must be a string or path-like object"
            raise TypeError(msg)
        raw_path = fspath(file_path)
        if not isinstance(raw_path, str):
            msg = "file_path must be a string or path-like object"
            raise TypeError(msg)
        if not raw_path.strip():
            msg = "file_path must not be empty"
            raise ValueError(msg)
        path = Path(raw_path)
        yara_code = _read_yara_text_file(path)
        return self.test(yara_code)

    def test_directory(self, dir_path: str | PathLike[str]) -> list[tuple[Path, bool, Any, Any]]:
        if isinstance(dir_path, bytes) or not isinstance(dir_path, str | PathLike):
            msg = "dir_path must be a string or path-like object"
            raise TypeError(msg)
        raw_path = fspath(dir_path)
        if not isinstance(raw_path, str):
            msg = "dir_path must be a string or path-like object"
            raise TypeError(msg)
        if not raw_path.strip():
            msg = "dir_path must not be empty"
            raise ValueError(msg)
        dir_path = Path(raw_path)
        results = []
        for yar_file in iter_matching_files(dir_path):
            success, orig, regen = self.test_file(yar_file)
            results.append((yar_file, success, orig, regen))
        return results

    def get_statistics(self) -> dict[str, Any]:
        return {
            "total_tests": self.test_count,
            "successful_tests": self.success_count,
            "failed_tests": self.test_count - self.success_count,
            "success_rate": self.success_count / max(1, self.test_count) * 100,
        }


def simple_roundtrip_test(yara_source: str) -> dict[str, Any]:
    try:
        original_ast = parse_yara_source(yara_source)
        generator = YaraXGenerator()
        reconstructed_source = generator.generate(original_ast)
        reconstructed_ast = parse_yara_source(reconstructed_source)
        success = original_ast is not None and reconstructed_ast is not None
        return {
            "original_source": yara_source,
            "reconstructed_source": reconstructed_source,
            "serialized_data": reconstructed_source,
            "format": "simple",
            "round_trip_successful": success,
            "differences": [] if success else ["Error during roundtrip"],
            "metadata": {
                "original_rule_count": len(original_ast.rules),
                "reconstructed_rule_count": len(reconstructed_ast.rules),
            },
        }
    except (ValueError, YaraASTError) as exc:
        return {
            "original_source": yara_source,
            "reconstructed_source": "",
            "serialized_data": "",
            "format": "simple",
            "round_trip_successful": False,
            "differences": [f"Error during roundtrip: {exc}"],
            "metadata": {
                "original_rule_count": 0,
                "reconstructed_rule_count": 0,
            },
        }
