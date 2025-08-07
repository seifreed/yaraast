"""Performance optimization for YARA rules."""

from __future__ import annotations

from typing import Any

from yaraast.ast.base import YaraFile
from yaraast.ast.rules import Rule
from yaraast.optimization.rule_optimizer import RuleOptimizer
from yaraast.performance.memory_optimizer import MemoryOptimizer


class PerformanceOptimizer:
    """Optimizes YARA rules for better runtime performance."""

    def __init__(self) -> None:
        self.rule_optimizer = RuleOptimizer()
        self.memory_optimizer = MemoryOptimizer()
        self._stats = {
            "rules_optimized": 0,
            "conditions_simplified": 0,
            "strings_optimized": 0,
        }

    def optimize(
        self,
        target: Rule | YaraFile,
        strategy: str = "balanced",
    ) -> Rule | YaraFile:
        """Optimize a rule or file for performance.

        Args:
            target: Rule or YaraFile to optimize
            strategy: Optimization strategy ('speed', 'memory', 'balanced')

        Returns:
            Optimized rule or file

        """
        if isinstance(target, Rule):
            return self.optimize_rule(target, strategy)
        if isinstance(target, YaraFile):
            return self.optimize_file(target, strategy)
        return target

    def optimize_rule(self, rule: Rule, strategy: str = "balanced") -> Rule:
        """Optimize a single rule."""
        # Apply rule optimizations
        _ = self.rule_optimizer.optimize_rule(rule)

        # Apply memory optimizations if needed
        if strategy in ("memory", "balanced"):
            _ = self.memory_optimizer.optimize_rule(rule)

        # Apply performance-specific optimizations
        if strategy in ("speed", "balanced"):
            _ = self._optimize_for_speed(rule)

        self._stats["rules_optimized"] += 1
        return rule

    def optimize_file(
        self,
        yara_file: YaraFile,
        strategy: str = "balanced",
    ) -> YaraFile:
        """Optimize an entire YARA file."""
        # Apply file-level optimizations
        _ = self.rule_optimizer.optimize_file(yara_file)

        # Apply memory optimizations if needed
        if strategy in ("memory", "balanced"):
            _ = self.memory_optimizer.optimize(yara_file)

        # Apply performance-specific optimizations
        if strategy in ("speed", "balanced"):
            _ = self._optimize_file_for_speed(yara_file)

        return yara_file

    def _optimize_for_speed(self, rule: Rule) -> Rule:
        """Apply speed-specific optimizations to a rule."""
        # Reorder string checks for better performance
        if rule.strings and isinstance(rule.strings, list):
            # Put shorter strings first (faster to check)
            try:
                rule.strings.sort(key=lambda s: len(getattr(s, "value", "")))
                self._stats["strings_optimized"] += len(rule.strings)
            except (TypeError, AttributeError):
                # Skip optimization if strings format is unexpected
                pass

        # Future speed optimizations to implement:
        # - Reorder condition checks by complexity/selectivity
        # - Optimize regex patterns for common use cases
        # - Cache intermediate compilation results
        # - Profile-guided optimization based on usage patterns

        return rule

    def _optimize_file_for_speed(self, yara_file: YaraFile) -> YaraFile:
        """Apply speed-specific optimizations to a file."""
        # Optimize each rule
        for i, rule in enumerate(yara_file.rules):
            yara_file.rules[i] = self._optimize_for_speed(rule)

        # Reorder rules for better performance
        # Put simpler rules first
        yara_file.rules.sort(key=self._rule_complexity)

        return yara_file

    def _rule_complexity(self, rule: Rule) -> int:
        """Estimate rule complexity for ordering."""
        complexity = 0

        # String complexity
        if rule.strings:
            complexity += len(rule.strings) * 10
            for string_def in rule.strings:
                if hasattr(string_def, "regex"):
                    complexity += 50  # Regex is expensive
                elif hasattr(string_def, "tokens"):
                    complexity += len(string_def.tokens) * 5  # Hex patterns

        # Condition complexity
        if rule.condition:
            # Simple heuristic based on string representation
            condition_str = str(rule.condition)
            complexity += len(condition_str)
            complexity += condition_str.count(" and ") * 5
            complexity += condition_str.count(" or ") * 5
            complexity += condition_str.count("for ") * 20

        return complexity

    def get_statistics(self) -> dict[str, Any]:
        """Get optimization statistics."""
        return dict(self._stats)

    def reset_statistics(self) -> None:
        """Reset optimization statistics."""
        self._stats = {
            "rules_optimized": 0,
            "conditions_simplified": 0,
            "strings_optimized": 0,
        }


def optimize_yara_file(
    file_path: str,
    output_path: str | None = None,
    strategy: str = "balanced",
) -> tuple[YaraFile, dict[str, Any]]:
    """Optimize a YARA file for performance.

    Args:
        file_path: Path to input YARA file
        output_path: Optional output path
        strategy: Optimization strategy

    Returns:
        Tuple of (optimized AST, statistics)

    """
    from yaraast.parser import Parser

    # Parse the file
    parser = Parser()
    with open(file_path) as f:
        content = f.read()
    ast = parser.parse(content)

    # Optimize
    optimizer = PerformanceOptimizer()
    _ = optimizer.optimize(ast, strategy)
    stats = optimizer.get_statistics()

    # Write output if requested
    if output_path:
        from yaraast.codegen import CodeGenerator

        gen = CodeGenerator()
        output = gen.generate(ast)
        with open(output_path, "w") as f:
            f.write(output)

    return ast, stats
