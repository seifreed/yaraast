"""Formatting services for CLI (logic without IO)."""

from __future__ import annotations

from yaraast import CodeGenerator


def format_ast(ast) -> str:
    generator = CodeGenerator()
    return generator.generate(ast)


def build_format_stats(ast) -> dict[str, int]:
    return {
        "rules": len(ast.rules),
        "imports": len(ast.imports),
    }
