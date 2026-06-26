"""Main rule optimizer combining all optimization passes."""

from __future__ import annotations

import copy
from typing import TYPE_CHECKING, Any

from yaraast.ast.base import require_yara_file
from yaraast.optimization.dead_code_eliminator import DeadCodeEliminator
from yaraast.optimization.expression_optimizer import ExpressionOptimizer
from yaraast.shared.numeric_validation import validate_positive_int_setting

if TYPE_CHECKING:
    from yaraast.ast.base import YaraFile
    from yaraast.ast.rules import Rule


class RuleOptimizer:
    """Comprehensive optimizer for YARA rules."""

    def __init__(self) -> None:
        self.expression_optimizer = ExpressionOptimizer()
        self.dead_code_eliminator = DeadCodeEliminator()

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
        yara_file = require_yara_file(yara_file, "yara_file")
        validate_positive_int_setting(passes, "passes")

        total_expr_opts = 0
        total_dead_elims = 0
        original_rule_count = len(yara_file.rules)

        current = copy.deepcopy(yara_file)
        passes_performed = 0
        for _ in range(passes):
            # Expression optimization pass - for now just count rules with conditions
            expr_opts = 0
            for rule in current.rules:
                if rule.condition is not None:
                    self.expression_optimizer.optimization_count = 0
                    rule.condition = self.expression_optimizer.optimize(rule.condition)
                    expr_opts += self.expression_optimizer.optimization_count
            total_expr_opts += expr_opts

            # Dead code elimination pass
            current, dead_elims = self.dead_code_eliminator.eliminate(current)
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
            "rules_before": original_rule_count,
            "rules_after": len(current.rules),
            "rules_eliminated": original_rule_count - len(current.rules),
        }

        return current, stats

    def optimize_rule(self, rule: Rule) -> Rule:
        """Optimize a single rule."""
        rule = copy.deepcopy(rule)
        if rule.condition is not None:
            rule.condition = self.expression_optimizer.optimize(rule.condition)
        return rule
