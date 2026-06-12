"""Performance optimization for YARA rules."""

from __future__ import annotations

from os import PathLike, fspath
from pathlib import Path
from typing import Any, TypeVar, overload

from yaraast.ast.base import YaraFile, require_yara_file
from yaraast.ast.rules import Rule
from yaraast.ast.strings import HexString, PlainString, RegexString, StringDefinition
from yaraast.optimization.rule_optimizer import RuleOptimizer
from yaraast.performance.memory_optimizer import MemoryOptimizer
from yaraast.performance.string_analysis_helpers import string_value_length
from yaraast.performance.validation import path_exists_and_is_dir

_Target = TypeVar("_Target")
_VALID_STRATEGIES = frozenset({"speed", "memory", "balanced"})


def _require_strategy(strategy: object) -> str:
    if not isinstance(strategy, str):
        msg = "optimization strategy must be a string"
        raise TypeError(msg)
    if strategy not in _VALID_STRATEGIES:
        valid = ", ".join(sorted(_VALID_STRATEGIES))
        msg = f"optimization strategy must be one of: {valid}"
        raise ValueError(msg)
    return strategy


def _require_file_path(value: object, name: str) -> Path:
    if isinstance(value, bool) or not isinstance(value, str | PathLike):
        msg = f"{name} must be a file path"
        raise TypeError(msg)
    raw_path = fspath(value)
    if not isinstance(raw_path, str):
        msg = f"{name} must be a file path"
        raise TypeError(msg)
    if not raw_path.strip():
        msg = f"{name} must not be empty"
        raise ValueError(msg)
    path = Path(raw_path)
    if path_exists_and_is_dir(path):
        msg = f"{name} must not be a directory"
        raise ValueError(msg)
    return path


def _read_yara_text_file(path: Path) -> str:
    try:
        with path.open(encoding="utf-8") as f:
            return f.read()
    except UnicodeDecodeError as exc:
        msg = "YARA file must contain valid UTF-8 text"
        raise ValueError(msg) from exc


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

    @overload
    def optimize(
        self,
        target: Rule,
        strategy: str = "balanced",
    ) -> Rule: ...

    @overload
    def optimize(
        self,
        target: YaraFile,
        strategy: str = "balanced",
    ) -> YaraFile: ...

    @overload
    def optimize(
        self,
        target: _Target,
        strategy: str = "balanced",
    ) -> _Target: ...

    def optimize(
        self,
        target: Rule | YaraFile | _Target,
        strategy: str = "balanced",
    ) -> Rule | YaraFile | _Target:
        """Optimize a rule or file for performance.

        Args:
            target: Rule or YaraFile to optimize
            strategy: Optimization strategy ('speed', 'memory', 'balanced')

        Returns:
            Optimized rule or file

        """
        strategy = _require_strategy(strategy)
        if isinstance(target, Rule):
            return self.optimize_rule(target, strategy)
        if isinstance(target, YaraFile):
            return self.optimize_file(target, strategy)
        return target

    def optimize_rule(self, rule: Rule, strategy: str = "balanced") -> Rule:
        """Optimize a single rule."""
        strategy = _require_strategy(strategy)
        # Apply rule optimizations
        rule = self.rule_optimizer.optimize_rule(rule)

        # Apply memory optimizations if needed
        if strategy in ("memory", "balanced"):
            rule = self.memory_optimizer.optimize_rule(rule)

        # Apply performance-specific optimizations
        if strategy in ("speed", "balanced"):
            rule = self._optimize_for_speed(rule)

        self._stats["rules_optimized"] += 1
        return rule

    def optimize_file(
        self,
        yara_file: YaraFile,
        strategy: str = "balanced",
    ) -> YaraFile:
        """Optimize an entire YARA file."""
        yara_file = require_yara_file(yara_file, "yara_file")
        strategy = _require_strategy(strategy)
        # Apply file-level optimizations
        optimized_file, _ = self.rule_optimizer.optimize(yara_file)
        yara_file = optimized_file

        # Apply memory optimizations if needed
        if strategy in ("memory", "balanced"):
            yara_file = self.memory_optimizer.optimize(yara_file)

        # Apply performance-specific optimizations
        if strategy in ("speed", "balanced"):
            yara_file = self._optimize_file_for_speed(yara_file)

        self._stats["rules_optimized"] += len(yara_file.rules)
        return yara_file

    def _optimize_for_speed(self, rule: Rule) -> Rule:
        """Apply speed-specific optimizations to a rule (returns new sorted lists, not in-place)."""
        # Reorder string checks for better performance
        if rule.strings and isinstance(rule.strings, list):
            optimizable_count = sum(
                1 for string_def in rule.strings if self._is_optimizable_string(string_def)
            )
            rule.strings = sorted(rule.strings, key=self._string_check_cost)
            self._stats["strings_optimized"] += optimizable_count

        # Future speed optimizations to implement:
        # - Reorder condition checks by complexity/selectivity
        # - Optimize regex patterns for common use cases
        # - Cache intermediate compilation results
        # - Profile-guided optimization based on usage patterns

        return rule

    @staticmethod
    def _is_optimizable_string(string_def: StringDefinition) -> bool:
        """Return whether a string definition has enough valid data to optimize."""
        if isinstance(string_def, PlainString):
            return isinstance(string_def.value, str | bytes)
        return isinstance(string_def, HexString | RegexString)

    @staticmethod
    def _string_check_cost(string_def: StringDefinition) -> int:
        """Estimate relative runtime cost for checking a string definition."""
        if isinstance(string_def, PlainString):
            value = string_def.value
            return string_value_length(value) if isinstance(value, str | bytes) else 300
        if isinstance(string_def, HexString):
            return 100 + len(string_def.tokens)
        if isinstance(string_def, RegexString):
            return 200 + len(string_def.regex)
        return 300

    def _optimize_file_for_speed(self, yara_file: YaraFile) -> YaraFile:
        """Apply speed-specific optimizations to a file (creates sorted copies, not in-place)."""
        # Optimize each rule
        for i, rule in enumerate(yara_file.rules):
            yara_file.rules[i] = self._optimize_for_speed(rule)

        # Reorder rules for better performance (new list, not in-place sort)
        yara_file.rules = sorted(yara_file.rules, key=self._rule_complexity)

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
        if rule.condition is not None:
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
    file_path: str | PathLike[str],
    output_path: str | PathLike[str] | None = None,
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
    from yaraast.parser.source import parse_yara_source

    input_file = _require_file_path(file_path, "file_path")
    output_file = (
        _require_file_path(output_path, "output_path") if output_path is not None else None
    )

    # Parse the file
    content = _read_yara_text_file(input_file)
    ast = parse_yara_source(content)

    # Optimize
    optimizer = PerformanceOptimizer()
    optimized_ast = optimizer.optimize(ast, strategy)
    stats = optimizer.get_statistics()

    # Write output if requested
    if output_file is not None:
        from yaraast.yarax.generator import YaraXGenerator

        gen = YaraXGenerator()
        output = gen.generate(optimized_ast)
        with output_file.open("w", encoding="utf-8") as f:
            f.write(output)

    return optimized_ast, stats
