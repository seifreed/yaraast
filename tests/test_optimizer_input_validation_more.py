"""Input validation tests for public optimizer APIs."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, cast

import pytest

from yaraast.libyara.ast_optimizer import ASTOptimizer
from yaraast.optimization.rule_optimizer import RuleOptimizer
from yaraast.performance.optimizer import PerformanceOptimizer


@pytest.mark.parametrize(
    "optimize",
    [
        RuleOptimizer().optimize,
        PerformanceOptimizer().optimize_file,
        ASTOptimizer().optimize,
    ],
)
@pytest.mark.parametrize("value", [None, 123, object()])
def test_public_optimizer_apis_reject_invalid_yara_file_inputs(
    optimize: Callable[[Any], object],
    value: object,
) -> None:
    with pytest.raises(TypeError, match="must be a YaraFile"):
        optimize(cast(Any, value))
