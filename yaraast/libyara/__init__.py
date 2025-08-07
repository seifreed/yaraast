"""LibYARA integration for cross-validation and testing."""

from typing import Never

try:
    import yara

    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

if YARA_AVAILABLE:
    from .ast_optimizer import ASTOptimizer, OptimizationStats
    from .compiler import CompilationResult, LibyaraCompiler
    from .direct_compiler import DirectASTCompiler, DirectCompilationResult, OptimizedMatcher
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

    def __getattr__(name) -> Never:
        msg = f"'{name}' requires yara-python. Install with: pip install yaraast[libyara]"
        raise ImportError(
            msg,
        )
