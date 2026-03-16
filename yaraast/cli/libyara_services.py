"""Services for LibYARA CLI commands."""

from __future__ import annotations

from pathlib import Path

from yaraast import CodeGenerator
from yaraast.cli.utils import parse_yara_file


def ensure_yara_available() -> None:
    """Raise if yara-python is not installed."""
    from yaraast.libyara import YARA_AVAILABLE

    if not YARA_AVAILABLE:
        msg = "yara-python is not installed"
        raise RuntimeError(msg)


def compile_yara(
    input_file: str,
    optimize: bool,
    debug: bool,
):
    """Parse and compile YARA rules."""
    from yaraast.libyara import DirectASTCompiler

    ast = parse_yara_file(input_file)
    compiler = DirectASTCompiler(enable_optimization=optimize, debug_mode=debug)
    result = compiler.compile_ast(ast)
    return result, compiler, ast


def scan_yara(
    rules_file: str,
    target: str,
    optimize: bool,
    timeout: int | None,
    fast: bool,
):
    """Compile and scan a target file."""
    from yaraast.libyara import DirectASTCompiler, OptimizedMatcher

    ast = parse_yara_file(rules_file)
    compiler = DirectASTCompiler(enable_optimization=optimize)
    compile_result = compiler.compile_ast(ast)
    if not compile_result.success:
        return None, None, compile_result

    matcher = OptimizedMatcher(compile_result.compiled_rules, ast)
    scan_result = matcher.scan(
        Path(target),
        timeout=timeout,
        fast_mode=fast,
    )
    return scan_result, matcher, compile_result


def optimize_yara(input_file: str):
    """Optimize YARA rules and return optimizer + generated code."""
    from yaraast.libyara import ASTOptimizer

    ast = parse_yara_file(input_file)
    optimizer = ASTOptimizer()
    optimized_ast = optimizer.optimize(ast)

    generator = CodeGenerator()
    optimized_code = generator.generate(optimized_ast)
    return optimizer, optimized_code
