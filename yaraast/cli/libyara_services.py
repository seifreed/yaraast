"""Services for LibYARA CLI commands."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from yaraast.ast.base import YaraFile
from yaraast.cli.utils import parse_yara_file
from yaraast.codegen.generator import CodeGenerator
from yaraast.libyara.compatibility import ensure_libyara_compatible_ast
from yaraast.shared.numeric_validation import validate_positive_int_setting


def _require_bool_option(value: object, name: str) -> bool:
    if not isinstance(value, bool):
        msg = f"{name} must be a boolean"
        raise TypeError(msg)
    return value


def ensure_yara_available() -> None:
    """Raise if yara-python is not installed."""
    from yaraast.libyara import YARA_AVAILABLE

    if not YARA_AVAILABLE:
        msg = "yara-python is not installed"
        raise RuntimeError(msg)


def ensure_yara_compatible_ast(ast: YaraFile) -> None:
    """Raise when an AST contains syntax libyara cannot compile."""
    ensure_libyara_compatible_ast(ast, action="use")


def compile_yara(
    input_file: str,
    optimize: object,
    debug: object,
) -> tuple[Any, Any, YaraFile]:
    """Parse and compile YARA rules."""
    optimize = _require_bool_option(optimize, "optimize")
    debug = _require_bool_option(debug, "debug")

    from yaraast.libyara import DirectASTCompiler

    ast = parse_yara_file(input_file)
    ensure_yara_compatible_ast(ast)
    compiler = DirectASTCompiler(enable_optimization=optimize, debug_mode=debug)
    result = compiler.compile_ast(ast, source_path=input_file)
    return result, compiler, ast


def scan_yara(
    rules_file: str,
    target: str,
    optimize: object,
    timeout: object,
    fast: object,
) -> tuple[Any | None, Any | None, Any]:
    """Compile and scan a target file."""
    optimize = _require_bool_option(optimize, "optimize")
    if timeout is not None:
        validate_positive_int_setting(timeout, "timeout")
    fast = _require_bool_option(fast, "fast")

    from yaraast.libyara import DirectASTCompiler, OptimizedMatcher

    ast = parse_yara_file(rules_file)
    ensure_yara_compatible_ast(ast)
    compiler = DirectASTCompiler(enable_optimization=optimize)
    compile_result = compiler.compile_ast(ast, source_path=rules_file)
    if not compile_result.success:
        return None, None, compile_result

    matcher = OptimizedMatcher(compile_result.compiled_rules, ast)
    scan_result = matcher.scan(
        Path(target),
        timeout=timeout,
        fast_mode=fast,
    )
    return scan_result, matcher, compile_result


def optimize_yara(input_file: str) -> tuple[Any, str]:
    """Optimize YARA rules and return optimizer + generated code."""
    from yaraast.libyara import ASTOptimizer

    ast = parse_yara_file(input_file)
    ensure_yara_compatible_ast(ast)
    optimizer = ASTOptimizer()
    optimized_ast = optimizer.optimize(ast)

    generator = CodeGenerator()
    optimized_code = generator.generate(optimized_ast)
    return optimizer, optimized_code
