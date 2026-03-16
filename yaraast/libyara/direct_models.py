"""Models for direct libyara compilation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class OptimizationStats:
    """Statistics about AST optimizations performed."""

    rules_optimized: int = 0
    strings_optimized: int = 0
    conditions_simplified: int = 0
    dead_code_removed: int = 0
    constant_folded: int = 0


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
