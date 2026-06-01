"""Input validation tests for public analysis APIs."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, cast

import pytest

from yaraast.analysis.dependency_analyzer import DependencyAnalyzer
from yaraast.analysis.optimization import OptimizationAnalyzer
from yaraast.analysis.rule_analyzer import RuleAnalyzer
from yaraast.analysis.string_usage import StringUsageAnalyzer
from yaraast.metrics.complexity import ComplexityAnalyzer
from yaraast.performance.parallel_analyzer import ParallelAnalyzer
from yaraast.performance.string_analyzer import StringPatternAnalyzer


@pytest.mark.parametrize(
    "analyze",
    [
        DependencyAnalyzer().analyze,
        OptimizationAnalyzer().analyze,
        RuleAnalyzer().analyze,
        StringUsageAnalyzer().analyze,
        ComplexityAnalyzer().analyze,
        StringPatternAnalyzer().analyze_file,
        ParallelAnalyzer().analyze_file,
    ],
)
@pytest.mark.parametrize("value", [None, 123, object()])
def test_public_analysis_apis_reject_invalid_yara_file_inputs(
    analyze: Callable[[Any], object],
    value: object,
) -> None:
    with pytest.raises(TypeError, match="must be a YaraFile"):
        analyze(cast(Any, value))
