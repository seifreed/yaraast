"""Helpers for direct AST compilation."""

from __future__ import annotations

import os
from os import PathLike, fspath
from pathlib import Path
import tempfile
from typing import Any

from yaraast.ast.base import ASTNode, YaraFile
from yaraast.codegen.generator import CodeGenerator
from yaraast.libyara.compatibility import ensure_libyara_compatible_ast
from yaraast.libyara.compiler import LibyaraCompiler
from yaraast.libyara.direct_models import DirectCompilationResult


def _require_source_path(source_path: object) -> Path:
    if isinstance(source_path, bool | bytes) or not isinstance(source_path, str | PathLike):
        msg = "source_path must be a string or path-like object"
        raise TypeError(msg)
    raw_path = fspath(source_path)
    if not isinstance(raw_path, str):
        msg = "source_path must be a string or path-like object"
        raise TypeError(msg)
    if not raw_path:
        msg = "source_path must not be empty"
        raise ValueError(msg)
    return Path(raw_path)


def generate_source(ast: YaraFile) -> str:
    ensure_libyara_compatible_ast(ast, action="compile")
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


def compile_source_with_file_context(
    source: str,
    externals: dict[str, Any],
    source_path: object,
    error_on_warning: bool,
    includes: dict[str, str] | None = None,
) -> DirectCompilationResult:
    """Compile generated source from the original file directory.

    libyara resolves relative includes from the compiled file's directory. Generated
    source compiled as an in-memory string has no directory context, so CLI/direct
    compilation must use a temporary file beside the original rules file.
    """
    source_dir = _require_source_path(source_path).resolve().parent
    temp_path = None
    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".yar",
        dir=source_dir,
        delete=False,
    ) as handle:
        handle.write(source)
        temp_path = Path(handle.name)

    try:
        compiler = LibyaraCompiler(externals=externals)
        result = compiler.compile_file(
            temp_path,
            error_on_warning=error_on_warning,
            includes=includes,
        )
    finally:
        if temp_path is not None:
            os.unlink(temp_path)

    return DirectCompilationResult(
        success=result.success,
        compiled_rules=result.compiled_rules,
        errors=result.errors,
        warnings=result.warnings,
    )


def count_ast_nodes(ast: ASTNode) -> int:
    count = 1

    def count_node(node: ASTNode) -> int:
        node_count = 1
        for child in node.children():
            node_count += count_node(child)
        return node_count

    for child in ast.children():
        count += count_node(child)

    return count
