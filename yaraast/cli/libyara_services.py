"""Services for LibYARA CLI commands."""

from __future__ import annotations

from pathlib import Path

from yaraast import CodeGenerator
from yaraast.cli.utils import parse_yara_file
from yaraast.yarax.compatibility_checker import YaraXCompatibilityChecker
from yaraast.yarax.feature_flags import YaraXFeatures


def ensure_yara_available() -> None:
    """Raise if yara-python is not installed."""
    from yaraast.libyara import YARA_AVAILABLE

    if not YARA_AVAILABLE:
        msg = "yara-python is not installed"
        raise RuntimeError(msg)


def ensure_yara_compatible_ast(ast) -> None:
    """Raise when an AST contains syntax libyara cannot compile."""
    checker = YaraXCompatibilityChecker(YaraXFeatures.yara_compatible())
    blocking = [
        issue
        for issue in checker.check(ast)
        if issue.issue_type == "yarax_feature" and issue.severity == "error"
    ]
    if blocking:
        features = sorted(
            {
                issue.message.split(": ", 1)[1] if ": " in issue.message else issue.message
                for issue in blocking
            }
        )
        msg = "Cannot use YARA-X-only syntax with libyara: " + ", ".join(features)
        raise ValueError(msg)


def compile_yara(
    input_file: str,
    optimize: bool,
    debug: bool,
):
    """Parse and compile YARA rules."""
    from yaraast.libyara import DirectASTCompiler

    ast = parse_yara_file(input_file)
    ensure_yara_compatible_ast(ast)
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
    ensure_yara_compatible_ast(ast)
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
    ensure_yara_compatible_ast(ast)
    optimizer = ASTOptimizer()
    optimized_ast = optimizer.optimize(ast)

    generator = CodeGenerator()
    optimized_code = generator.generate(optimized_ast)
    return optimizer, optimized_code
