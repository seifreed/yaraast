"""AST Optimizer for libyara integration."""

import copy
from dataclasses import dataclass

from yaraast.ast.base import YaraFile, require_yara_file
from yaraast.optimization.dead_code_eliminator import DeadCodeEliminator
from yaraast.optimization.expression_optimizer import ExpressionOptimizer


@dataclass
class OptimizationStats:
    """Statistics about AST optimizations performed."""

    rules_optimized: int = 0
    strings_optimized: int = 0
    conditions_simplified: int = 0
    dead_code_removed: int = 0
    constant_folded: int = 0


class ASTOptimizer:
    """Simple optimizer for AST before compilation."""

    def __init__(self) -> None:
        self.stats = OptimizationStats()
        self.optimizations_applied: list[str] = []

    def optimize(self, ast: YaraFile) -> YaraFile:
        """Apply optimizations to AST."""
        ast = require_yara_file(ast, "ast")
        ast.validate_structure()
        self.stats = OptimizationStats()
        self.optimizations_applied = []

        # Create a deep copy to avoid modifying the original
        optimized_ast = copy.deepcopy(ast)

        # Apply dead code elimination
        eliminator = DeadCodeEliminator()
        optimized_ast, elimination_count = eliminator.eliminate(optimized_ast)
        if elimination_count > 0:
            self.stats.strings_optimized += elimination_count
            self.stats.dead_code_removed += elimination_count
            self.optimizations_applied.append(
                f"Removed {elimination_count} unused strings/dead code"
            )

        # Apply expression optimization
        expr_optimizer = ExpressionOptimizer()
        optimized_ast, expr_opt_count = expr_optimizer.optimize(optimized_ast)
        if expr_opt_count > 0:
            self.stats.conditions_simplified += expr_opt_count
            self.stats.constant_folded += expr_opt_count
            self.optimizations_applied.append(f"Applied {expr_opt_count} expression optimizations")

        # Count rules as optimized
        self.stats.rules_optimized = len(optimized_ast.rules)

        return optimized_ast
