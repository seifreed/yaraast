"""Models for direct libyara compilation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from yaraast.libyara.ast_optimizer import OptimizationStats

__all__ = ["DirectCompilationResult", "OptimizationStats"]


@dataclass
class DirectCompilationResult:
    """Result of direct AST compilation."""

    success: bool
    compiled_rules: Any | None = None
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    optimization_stats: OptimizationStats | None = None
    compilation_time: float = 0.0
    ast_node_count: int = 0
    generated_source: str | None = None

    @property
    def optimized(self) -> bool:
        if not self.optimization_stats:
            return False
        stats = self.optimization_stats
        return (
            stats.rules_optimized > 0
            or stats.strings_optimized > 0
            or stats.conditions_simplified > 0
            or stats.dead_code_removed > 0
            or stats.constant_folded > 0
        )
