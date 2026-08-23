"""Formatting services for CLI (logic without IO)."""

from __future__ import annotations

from yaraast.ast.base import YaraFile
from yaraast.yarax.generator import YaraXGenerator


def format_ast(ast: YaraFile) -> str:
    generator = YaraXGenerator()
    return generator.generate(ast)


def build_format_stats(ast: YaraFile) -> dict[str, int]:
    return {
        "rules": len(ast.rules),
        "imports": len(ast.imports),
    }
