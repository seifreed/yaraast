"""LibYARA integration for cross-validation and testing."""

try:
    import yara  # noqa: F401

    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

if YARA_AVAILABLE:
    from .ast_optimizer import ASTOptimizer, OptimizationStats  # noqa: F401
    from .compiler import CompilationResult, LibyaraCompiler  # noqa: F401
    from .direct_compiler import (  # noqa: F401
        DirectASTCompiler,
        DirectCompilationResult,
        OptimizedMatcher,
    )
    from .equivalence import EquivalenceResult, EquivalenceTester  # noqa: F401
    from .scanner import LibyaraScanner, ScanResult  # noqa: F401

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

    def __getattr__(name):
        raise ImportError(
            f"'{name}' requires yara-python. Install with: pip install yaraast[libyara]"
        )
