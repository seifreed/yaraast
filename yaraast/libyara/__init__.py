"""LibYARA integration for cross-validation and testing."""

from typing import Never

from yaraast.libyara._availability import is_missing_yara_import

try:
    import yara

    YARA_AVAILABLE = True
except ImportError as exc:
    if not is_missing_yara_import(exc):
        raise
    YARA_AVAILABLE = False

if YARA_AVAILABLE:
    from .ast_optimizer import ASTOptimizer, OptimizationStats
    from .compiler import CompilationResult, LibyaraCompiler
    from .direct_compiler import DirectASTCompiler, OptimizedMatcher
    from .direct_models import DirectCompilationResult
    from .equivalence import EquivalenceResult, EquivalenceTester
    from .scanner import LibyaraScanner, ScanResult

    __all__ = [
        "YARA_AVAILABLE",
        "ASTOptimizer",
        "CompilationResult",
        "DirectASTCompiler",
        "DirectCompilationResult",
        "EquivalenceResult",
        "EquivalenceTester",
        "LibyaraCompiler",
        "LibyaraScanner",
        "OptimizationStats",
        "OptimizedMatcher",
        "ScanResult",
    ]
else:
    # Provide stub message when yara-python is not installed
    __all__ = ["YARA_AVAILABLE"]

    def __getattr__(name: str) -> Never:
        msg = f"'{name}' requires yara-python. Install with: pip install yaraast[libyara]"
        raise ImportError(
            msg,
        )
