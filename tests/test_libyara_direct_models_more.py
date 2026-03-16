from __future__ import annotations

from yaraast.libyara.direct_models import DirectCompilationResult, OptimizationStats


def test_direct_compilation_result_optimized_property_paths() -> None:
    plain = DirectCompilationResult(success=True)
    assert plain.optimized is False

    zero_stats = DirectCompilationResult(success=True, optimization_stats=OptimizationStats())
    assert zero_stats.optimized is False

    folded = DirectCompilationResult(
        success=True,
        optimization_stats=OptimizationStats(constant_folded=1),
    )
    assert folded.optimized is True
