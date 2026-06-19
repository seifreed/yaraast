"""Serialization services for CLI (logic without IO)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from yaraast.ast.base import YaraFile, require_yara_file
from yaraast.cli.serialize_service_helpers import _require_serialization_format
from yaraast.cli.utils import parse_yara_file, write_text
from yaraast.codegen import CodeGenerator
from yaraast.serialization.ast_diff import AstDiff, AstHasher
from yaraast.serialization.json_serializer import JsonSerializer
from yaraast.serialization.protobuf_serializer import ProtobufSerializer
from yaraast.serialization.yaml_serializer import YamlSerializer


def import_ast(input_file: str, fmt: str):
    fmt = _require_serialization_format(fmt)
    if fmt == "json":
        serializer = JsonSerializer(include_metadata=True)
    elif fmt == "yaml":
        serializer = YamlSerializer(include_metadata=True)
    else:
        serializer = ProtobufSerializer(include_metadata=True)
    return serializer.deserialize(input_path=input_file)


def generate_yara_from_ast(ast: YaraFile, output: str) -> str:
    yara_code = CodeGenerator().generate(ast)
    write_text(output, yara_code)
    return yara_code


def compare_yara_files(old_file: str | Path, new_file: str | Path) -> tuple[AstDiff, Any]:
    old_ast = parse_yara_file(old_file)
    new_ast = parse_yara_file(new_file)
    differ = AstDiff()
    diff_result = differ.compare(old_ast, new_ast)
    return differ, diff_result


def build_ast_info(ast: YaraFile) -> dict[str, Any]:
    ast = require_yara_file(ast, "ast")
    rule_names = [rule.name for rule in ast.rules]
    rule_details = []
    for rule in ast.rules[:10]:
        rule_details.append(
            {
                "name": rule.name,
                "strings": len(rule.strings),
                "tags": len(rule.tags),
                "meta": len(rule.meta),
                "modifiers": (
                    ", ".join(str(m) for m in rule.modifiers) if rule.modifiers else "none"
                ),
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
