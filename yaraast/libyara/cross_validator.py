"""Cross-validation between yaraast evaluation and libyara."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from yaraast.evaluation import YaraEvaluator

from .compiler import LibyaraCompiler
from .scanner import LibyaraScanner

if TYPE_CHECKING:
    from yaraast.ast.base import YaraFile


@dataclass
class ValidationResult:
    """Result of cross-validation."""

    valid: bool

    # Rule-level results
    rules_tested: int = 0
    rules_matched: int = 0
    rules_differ: list[str] = field(default_factory=list)

    # Detailed comparisons
    yaraast_results: dict[str, bool] = field(default_factory=dict)
    libyara_results: dict[str, bool] = field(default_factory=dict)

    # Performance metrics
    yaraast_time: float = 0.0
    libyara_compile_time: float = 0.0
    libyara_scan_time: float = 0.0

    # Errors
    errors: list[str] = field(default_factory=list)

    @property
    def total_time(self) -> float:
        """Total validation time."""
        return self.yaraast_time + self.libyara_compile_time + self.libyara_scan_time

    @property
    def match_rate(self) -> float:
        """Percentage of rules that matched."""
        if self.rules_tested == 0:
            return 0.0
        return (self.rules_matched / self.rules_tested) * 100


class CrossValidator:
    """Cross-validate between yaraast and libyara."""

    def __init__(self) -> None:
        """Initialize cross-validator."""
        self.compiler = LibyaraCompiler()
        self.scanner = LibyaraScanner()

    def validate(
        self,
        ast: YaraFile,
        test_data: bytes,
        externals: dict[str, Any] | None = None,
    ) -> ValidationResult:
        """Cross-validate AST against libyara.

        Args:
            ast: YARA AST to validate
            test_data: Data to scan
            externals: External variables

        Returns:
            ValidationResult with comparison

        """
        result = ValidationResult(valid=True)

        # Step 1: Evaluate with yaraast
        start_time = time.time()
        try:
            evaluator = YaraEvaluator(test_data)
            yaraast_results = evaluator.evaluate_file(ast)
            result.yaraast_results = yaraast_results
            result.yaraast_time = time.time() - start_time
        except Exception as e:
            result.valid = False
            result.errors.append(f"YaraAST evaluation failed: {e!s}")
            return result

        # Step 2: Compile with libyara
        start_time = time.time()
        try:
            if externals:
                self.compiler.externals = externals

            compilation = self.compiler.compile_ast(ast)
            result.libyara_compile_time = time.time() - start_time

            if not compilation.success:
                result.valid = False
                result.errors.extend(compilation.errors)
                return result
        except Exception as e:
            result.valid = False
            result.errors.append(f"LibYARA compilation failed: {e!s}")
            return result

        # Step 3: Scan with libyara
        start_time = time.time()
        try:
            scan_result = self.scanner.scan_data(compilation.compiled_rules, test_data)
            result.libyara_scan_time = time.time() - start_time

            if not scan_result.success:
                result.valid = False
                result.errors.extend(scan_result.errors)
                return result

            # Convert scan results to rule -> bool mapping
            libyara_matched = set(scan_result.matched_rules)
            for rule in ast.rules:
                result.libyara_results[rule.name] = rule.name in libyara_matched

        except Exception as e:
            result.valid = False
            result.errors.append(f"LibYARA scanning failed: {e!s}")
            return result

        # Step 4: Compare results
        result.rules_tested = len(yaraast_results)

        for rule_name in yaraast_results:
            yaraast_match = yaraast_results.get(rule_name, False)
            libyara_match = result.libyara_results.get(rule_name, False)

            if yaraast_match == libyara_match:
                result.rules_matched += 1
            else:
                result.valid = False
                result.rules_differ.append(
                    f"{rule_name}: yaraast={yaraast_match}, libyara={libyara_match}",
                )

        return result

    def validate_batch(
        self,
        ast: YaraFile,
        test_data_list: list[bytes],
        externals: dict[str, Any] | None = None,
    ) -> list[ValidationResult]:
        """Validate AST against multiple test data samples.

        Args:
            ast: YARA AST to validate
            test_data_list: List of data samples to test
            externals: External variables

        Returns:
            List of ValidationResult for each sample

        """
        results = []

        # Compile once with libyara
        compilation = self.compiler.compile_ast(ast)
        if not compilation.success:
            # Return error for all samples
            for _ in test_data_list:
                result = ValidationResult(valid=False)
                result.errors = compilation.errors
                results.append(result)
            return results

        # Test each sample
        for test_data in test_data_list:
            result = self._validate_single(
                ast,
                test_data,
                compilation.compiled_rules,
                externals,
            )
            results.append(result)

        return results

    def _validate_single(
        self,
        ast: YaraFile,
        test_data: bytes,
        compiled_rules: Any,
        externals: dict[str, Any] | None = None,
    ) -> ValidationResult:
        """Validate single sample with pre-compiled rules."""
        result = ValidationResult(valid=True)

        # Evaluate with yaraast
        start_time = time.time()
        try:
            evaluator = YaraEvaluator(test_data)
            yaraast_results = evaluator.evaluate_file(ast)
            result.yaraast_results = yaraast_results
            result.yaraast_time = time.time() - start_time
        except Exception as e:
            result.valid = False
            result.errors.append(f"YaraAST evaluation failed: {e!s}")
            return result

        # Scan with libyara
        start_time = time.time()
        try:
            scan_result = self.scanner.scan_data(compiled_rules, test_data)
            result.libyara_scan_time = time.time() - start_time

            if not scan_result.success:
                result.valid = False
                result.errors.extend(scan_result.errors)
                return result

            # Convert scan results
            libyara_matched = set(scan_result.matched_rules)
            for rule in ast.rules:
                result.libyara_results[rule.name] = rule.name in libyara_matched

        except Exception as e:
            result.valid = False
            result.errors.append(f"LibYARA scanning failed: {e!s}")
            return result

        # Compare results
        result.rules_tested = len(yaraast_results)

        for rule_name in yaraast_results:
            yaraast_match = yaraast_results.get(rule_name, False)
            libyara_match = result.libyara_results.get(rule_name, False)

            if yaraast_match == libyara_match:
                result.rules_matched += 1
            else:
                result.valid = False
                result.rules_differ.append(
                    f"{rule_name}: yaraast={yaraast_match}, libyara={libyara_match}",
                )

        return result
