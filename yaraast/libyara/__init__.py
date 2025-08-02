"""LibYARA integration for cross-validation and testing."""

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

if YARA_AVAILABLE:
    from .compiler import CompilationResult, LibyaraCompiler
    from .direct_compiler import (
        ASTOptimizer,
        DirectASTCompiler,
        DirectCompilationResult,
        OptimizationStats,
        OptimizedMatcher,
    )
    from .equivalence import EquivalenceResult, EquivalenceTester
    from .scanner import LibyaraScanner, ScanResult

    __all__ = [
        'YARA_AVAILABLE',
        'LibyaraCompiler',
        'CompilationResult',
        'LibyaraScanner',
        'ScanResult',
        'EquivalenceTester',
        'EquivalenceResult',
        'DirectASTCompiler',
        'OptimizedMatcher',
        'DirectCompilationResult',
        'ASTOptimizer',
        'OptimizationStats'
    ]
else:
    # Provide stub message when yara-python is not installed
    __all__ = ['YARA_AVAILABLE']

    def __getattr__(name):
        raise ImportError(
            f"'{name}' requires yara-python. "
            "Install with: pip install yaraast[libyara]"
        )
