"""Serialization services for CLI (logic without IO)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from yaraast.cli.serialize_service_helpers import create_serializer as helper_create_serializer
from yaraast.cli.serialize_service_helpers import (
    export_with_serializer as helper_export_with_serializer,
)
from yaraast.cli.utils import read_text
from yaraast.parser.parser import Parser
from yaraast.serialization.ast_diff import AstDiff, AstHasher


def export_ast(
    ast: Any, fmt: str, output: str | None, minimal: bool
) -> tuple[str | None, dict | None]:
    return helper_export_with_serializer(ast, fmt, output, minimal)


def import_ast(input_file: str, fmt: str):
    serializer = helper_create_serializer(fmt, include_metadata=True)
    return serializer.deserialize(input_path=input_file)


def parse_yara_file(input_file: str | Path) -> Any:
    parser = Parser()
    content = read_text(input_file)
    return parser.parse(content)


def compare_yara_files(old_file: str | Path, new_file: str | Path) -> tuple[AstDiff, Any]:
    parser = Parser()
    old_ast = parser.parse(read_text(old_file))
    new_ast = parser.parse(read_text(new_file))
    differ = AstDiff()
    diff_result = differ.compare(old_ast, new_ast)
    return differ, diff_result


def validate_serialized(input_file: str | Path, fmt: str) -> Any:
    return import_ast(str(input_file), fmt)


def build_ast_info(ast: Any) -> dict[str, Any]:
    rule_names = [rule.name for rule in ast.rules]
    rule_details = []
    for rule in ast.rules[:10]:
        rule_details.append(
            {
                "name": rule.name,
                "strings": len(rule.strings),
                "tags": len(rule.tags),
                "meta": len(rule.meta),
                "modifiers": ", ".join(rule.modifiers) if rule.modifiers else "none",
            },
        )
    hasher = AstHasher()
    return {
        "rule_count": len(ast.rules),
        "import_count": len(ast.imports),
        "include_count": len(ast.includes),
        "rule_samples": rule_names[:3],
        "rule_details": rule_details,
        "has_more_rules": len(ast.rules) > 10,
        "import_list": [imp.module for imp in ast.imports],
        "include_list": [inc.path for inc in ast.includes],
        "ast_hash": hasher.hash_ast(ast),
    }
