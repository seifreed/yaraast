"""Equivalence testing for AST round-trip validation."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from yaraast.codegen import CodeGenerator
from yaraast.evaluation import YaraEvaluator
from yaraast.parser import Parser

from .compiler import LibyaraCompiler
from .scanner import LibyaraScanner, ScanResult

if TYPE_CHECKING:
    from yaraast.ast.base import YaraFile


@dataclass
class EquivalenceResult:
    """Result of equivalence testing."""

    # Overall result
    equivalent: bool

    # AST comparison
    ast_equivalent: bool = True
    ast_differences: list[str] = field(default_factory=list)

    # Code generation comparison
    code_equivalent: bool = True
    original_code: str | None = None
    regenerated_code: str | None = None

    # Compilation results
    original_compiles: bool = True
    regenerated_compiles: bool = True
    compilation_errors: list[str] = field(default_factory=list)

    # Scanning results
    scan_equivalent: bool = True
    scan_differences: list[str] = field(default_factory=list)

    # Evaluation results
    eval_equivalent: bool = True
    eval_differences: list[str] = field(default_factory=list)


class EquivalenceTester:
    """Test equivalence of AST transformations."""

    def __init__(self) -> None:
        """Initialize equivalence tester."""
        self.parser = Parser()
        self.codegen = CodeGenerator()
        self.compiler = LibyaraCompiler()
        self.scanner = LibyaraScanner()

    def test_round_trip(
        self,
        original_ast: YaraFile,
        test_data: bytes | None = None,
    ) -> EquivalenceResult:
        """Test AST → code → libyara → re-parse round trip.

        Args:
            original_ast: Original AST
            test_data: Optional data to test scanning/evaluation

        Returns:
            EquivalenceResult with detailed comparison

        """
        result = EquivalenceResult(equivalent=True)

        # Step 1: Generate code from original AST
        try:
            original_code = self.codegen.generate(original_ast)
            result.original_code = original_code
        except Exception as e:
            result.equivalent = False
            result.code_equivalent = False
            result.ast_differences.append(f"Code generation failed: {e!s}")
            return result

        # Step 2: Parse the generated code
        try:
            reparsed_ast = self.parser.parse(original_code)
        except Exception as e:
            result.equivalent = False
            result.ast_equivalent = False
            result.ast_differences.append(f"Re-parsing failed: {e!s}")
            return result

        # Step 3: Generate code from re-parsed AST
        try:
            regenerated_code = self.codegen.generate(reparsed_ast)
            result.regenerated_code = regenerated_code
        except Exception as e:
            result.equivalent = False
            result.code_equivalent = False
            result.ast_differences.append(f"Re-generation failed: {e!s}")
            return result

        # Step 4: Compare generated code (normalized)
        if not self._compare_code(original_code, regenerated_code):
            result.equivalent = False
            result.code_equivalent = False
            result.ast_differences.append("Generated code differs after round-trip")

        # Step 5: Compare AST structures
        ast_diffs = self._compare_ast(original_ast, reparsed_ast)
        if ast_diffs:
            result.equivalent = False
            result.ast_equivalent = False
            result.ast_differences.extend(ast_diffs)

        # Step 6: Compile both versions with libyara
        orig_compilation = self.compiler.compile_source(original_code)
        result.original_compiles = orig_compilation.success
        if not orig_compilation.success:
            result.compilation_errors.extend(orig_compilation.errors)

        regen_compilation = self.compiler.compile_source(regenerated_code)
        result.regenerated_compiles = regen_compilation.success
        if not regen_compilation.success:
            result.compilation_errors.extend(regen_compilation.errors)

        # Step 7: If test data provided, compare scanning results
        if test_data and orig_compilation.success and regen_compilation.success:
            # Scan with both rule sets
            orig_scan = self.scanner.scan_data(
                orig_compilation.compiled_rules,
                test_data,
            )
            regen_scan = self.scanner.scan_data(
                regen_compilation.compiled_rules,
                test_data,
            )

            # Compare scan results
            scan_diffs = self._compare_scans(orig_scan, regen_scan)
            if scan_diffs:
                result.equivalent = False
                result.scan_equivalent = False
                result.scan_differences.extend(scan_diffs)

            # Step 8: Compare with evaluation API
            eval_diffs = self._compare_evaluation(original_ast, reparsed_ast, test_data)
            if eval_diffs:
                result.equivalent = False
                result.eval_equivalent = False
                result.eval_differences.extend(eval_diffs)

        return result

    def test_file_round_trip(
        self,
        filepath: str,
        test_data: bytes | None = None,
    ) -> EquivalenceResult:
        """Test round-trip starting from a file.

        Args:
            filepath: Path to YARA file
            test_data: Optional data to test scanning

        Returns:
            EquivalenceResult

        """
        try:
            with Path(filepath).open() as f:
                original_code = f.read()

            original_ast = self.parser.parse(original_code)
            return self.test_round_trip(original_ast, test_data)
        except Exception as e:
            return EquivalenceResult(
                equivalent=False,
                ast_differences=[f"Failed to parse file: {e!s}"],
            )

    def _compare_code(self, code1: str, code2: str) -> bool:
        """Compare two code strings (normalized)."""
        # Normalize whitespace and line endings
        norm1 = "\n".join(line.strip() for line in code1.strip().split("\n") if line.strip())
        norm2 = "\n".join(line.strip() for line in code2.strip().split("\n") if line.strip())
        return norm1 == norm2

    def _compare_ast(self, ast1: YaraFile, ast2: YaraFile) -> list[str]:
        """Compare two ASTs and return differences."""
        differences = []

        # Compare imports
        if len(ast1.imports) != len(ast2.imports):
            differences.append(
                f"Import count differs: {len(ast1.imports)} vs {len(ast2.imports)}",
            )

        # Compare rules
        if len(ast1.rules) != len(ast2.rules):
            differences.append(
                f"Rule count differs: {len(ast1.rules)} vs {len(ast2.rules)}",
            )
        else:
            for i, (rule1, rule2) in enumerate(
                zip(ast1.rules, ast2.rules, strict=False),
            ):
                if rule1.name != rule2.name:
                    differences.append(
                        f"Rule {i} name differs: {rule1.name} vs {rule2.name}",
                    )

                # Compare strings
                if len(rule1.strings) != len(rule2.strings):
                    differences.append(
                        f"Rule {rule1.name} string count differs: "
                        f"{len(rule1.strings)} vs {len(rule2.strings)}",
                    )

        return differences

    def _compare_scans(self, scan1: ScanResult, scan2: ScanResult) -> list[str]:
        """Compare two scan results."""
        differences = []

        if scan1.success != scan2.success:
            differences.append(
                f"Scan success differs: {scan1.success} vs {scan2.success}",
            )

        rules1 = set(scan1.matched_rules)
        rules2 = set(scan2.matched_rules)

        if rules1 != rules2:
            only_in_1 = rules1 - rules2
            only_in_2 = rules2 - rules1

            if only_in_1:
                differences.append(f"Rules matched only in original: {only_in_1}")
            if only_in_2:
                differences.append(f"Rules matched only in regenerated: {only_in_2}")

        return differences

    def _compare_evaluation(
        self,
        ast1: YaraFile,
        ast2: YaraFile,
        test_data: bytes,
    ) -> list[str]:
        """Compare evaluation results."""
        differences = []

        try:
            # Evaluate both ASTs
            eval1 = YaraEvaluator(test_data)
            results1 = eval1.evaluate_file(ast1)

            eval2 = YaraEvaluator(test_data)
            results2 = eval2.evaluate_file(ast2)

            # Compare results
            for rule_name in set(results1.keys()) | set(results2.keys()):
                if rule_name not in results1:
                    differences.append(
                        f"Rule {rule_name} missing in original evaluation",
                    )
                elif rule_name not in results2:
                    differences.append(
                        f"Rule {rule_name} missing in regenerated evaluation",
                    )
                elif results1[rule_name] != results2[rule_name]:
                    differences.append(
                        f"Rule {rule_name} evaluation differs: "
                        f"{results1[rule_name]} vs {results2[rule_name]}",
                    )

        except Exception as e:
            differences.append(f"Evaluation comparison failed: {e!s}")

        return differences
