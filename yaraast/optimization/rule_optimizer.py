"""Main rule optimizer combining all optimization passes."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from yaraast.optimization.dead_code_eliminator import DeadCodeEliminator
from yaraast.optimization.expression_optimizer import ExpressionOptimizer

if TYPE_CHECKING:
    from yaraast.ast.base import YaraFile
    from yaraast.ast.rules import Rule


class RuleOptimizer:
    """Comprehensive optimizer for YARA rules."""

    def __init__(self) -> None:
        self.expression_optimizer = ExpressionOptimizer()
        self.dead_code_eliminator = DeadCodeEliminator()
        self.optimization_stats: dict[str, int] = {}

    def optimize(
        self,
        yara_file: YaraFile,
        passes: int = 3,
    ) -> tuple[YaraFile, dict[str, Any]]:
        """Perform multiple optimization passes on YARA file.

        Args:
            yara_file: The YARA file AST to optimize
            passes: Number of optimization passes to perform

        Returns:
            Tuple of (optimized AST, optimization statistics)

        """
        total_expr_opts = 0
        total_dead_elims = 0

        current = yara_file
        for passes_performed in range(passes):
            # Expression optimization pass - for now just count rules with conditions
            expr_opts = 0
            for rule in current.rules:
                if rule.condition:
                    rule.condition = self.expression_optimizer.optimize(rule.condition)
                    expr_opts += 1
            total_expr_opts += expr_opts

            # Dead code elimination pass
            old_rules = len(current.rules)
            current = self.dead_code_eliminator.eliminate(current)
            dead_elims = old_rules - len(current.rules)
            total_dead_elims += dead_elims

            passes_performed += 1

            # If no optimizations were made in this pass, we're done
            if expr_opts == 0 and dead_elims == 0:
                break

        stats = {
            "passes_performed": passes_performed,
            "expression_optimizations": total_expr_opts,
            "dead_code_eliminations": total_dead_elims,
            "total_optimizations": total_expr_opts + total_dead_elims,
            "rules_before": len(yara_file.rules),
            "rules_after": len(current.rules),
            "rules_eliminated": len(yara_file.rules) - len(current.rules),
        }

        return current, stats

    def get_optimization_report(self, yara_file: YaraFile) -> dict[str, Any]:
        """Generate a detailed optimization report."""
        # Perform optimization
        optimized, stats = self.optimize(yara_file)

        # Calculate size reduction
        original_strings = sum(len(rule.strings) for rule in yara_file.rules)
        optimized_strings = sum(len(rule.strings) for rule in optimized.rules)

        return {
            "summary": stats,
            "size_reduction": {
                "rules": f"{stats['rules_eliminated']} rules removed",
                "strings": f"{original_strings - optimized_strings} strings removed",
                "percentage": (
                    f"{(1 - len(optimized.rules) / len(yara_file.rules)) * 100:.1f}%"
                    if yara_file.rules
                    else "0%"
                ),
            },
            "optimization_breakdown": {
                "constant_folding": "Evaluated constant expressions",
                "boolean_simplification": "Simplified boolean logic",
                "dead_code_removal": "Removed unreachable code",
                "unused_string_removal": "Removed unused string definitions",
            },
        }

    def optimize_rule(self, rule: Rule) -> Rule:
        """Optimize a single rule."""
        if rule.condition:
            rule.condition = self.expression_optimizer.optimize(rule.condition)
        return rule

    def optimize_file(self, yara_file: YaraFile) -> YaraFile:
        """Optimize a YARA file (simple version for compatibility)."""
        optimized, _ = self.optimize(yara_file)
        return optimized
