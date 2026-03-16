"""Helpers for direct AST compilation."""

from __future__ import annotations

from typing import Any

from yaraast.codegen.generator import CodeGenerator
from yaraast.libyara.compiler import LibyaraCompiler
from yaraast.libyara.direct_models import DirectCompilationResult


def generate_source(ast) -> str:
    generator = CodeGenerator()
    return generator.generate(ast)


def compile_source(
    source: str,
    externals: dict[str, Any],
    includes: dict[str, str] | None,
    error_on_warning: bool,
) -> DirectCompilationResult:
    compiler = LibyaraCompiler(externals=externals)
    result = compiler.compile_source(source, includes, error_on_warning)

    return DirectCompilationResult(
        success=result.success,
        compiled_rules=result.compiled_rules,
        errors=result.errors,
        warnings=result.warnings,
    )


def count_ast_nodes(ast) -> int:
    count = 1

    def count_node(node) -> int:
        node_count = 1
        for child in node.children():
            node_count += count_node(child)
        return node_count

    for child in ast.children():
        count += count_node(child)

    return count
