"""Equivalence testing for AST round-trip validation."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from yaraast.codegen.generator import CodeGenerator
from yaraast.evaluation.evaluator import YaraEvaluator
from yaraast.parser.parser import Parser

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

    @staticmethod
    def _record_regeneration_failure(result: EquivalenceResult, error: Exception) -> None:
        result.equivalent = False
        result.code_equivalent = False
        result.ast_differences.append(f"Re-generation failed: {error!s}")

    @staticmethod
    def _record_code_difference(
        result: EquivalenceResult,
        original_code: str,
        regenerated_code: str,
    ) -> None:
        if original_code == regenerated_code:
            return
        result.equivalent = False
        result.code_equivalent = False
        result.ast_differences.append("Generated code differs after round-trip")

    @staticmethod
    def _record_ast_differences(
        result: EquivalenceResult,
        differences: list[str],
    ) -> None:
        if not differences:
            return
        result.equivalent = False
        result.ast_equivalent = False
        result.ast_differences.extend(differences)

    @staticmethod
    def _record_scan_differences(
        result: EquivalenceResult,
        differences: list[str],
    ) -> None:
        if not differences:
            return
        result.equivalent = False
        result.scan_equivalent = False
        result.scan_differences.extend(differences)

    @staticmethod
    def _record_eval_differences(
        result: EquivalenceResult,
        differences: list[str],
    ) -> None:
        if not differences:
            return
        result.equivalent = False
        result.eval_equivalent = False
        result.eval_differences.extend(differences)

    def _generate_regenerated_code(
        self,
        reparsed_ast: YaraFile,
        result: EquivalenceResult,
    ) -> str | None:
        """Generate code from a reparsed AST, recording failures in result."""
        try:
            regenerated_code = self.codegen.generate(reparsed_ast)
            result.regenerated_code = regenerated_code
        except Exception as e:
            self._record_regeneration_failure(result, e)
            return None
        return regenerated_code

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
        regenerated_code = self._generate_regenerated_code(reparsed_ast, result)
        if regenerated_code is None:
            return result

        # Step 4: Compare generated code (normalized)
        self._record_code_difference(
            result,
            self._normalize_code(original_code),
            self._normalize_code(regenerated_code),
        )

        # Step 5: Compare AST structures
        ast_diffs = self._compare_ast(original_ast, reparsed_ast)
        self._record_ast_differences(result, ast_diffs)

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
            self._record_scan_differences(result, scan_diffs)

            # Step 8: Compare with evaluation API
            eval_diffs = self._compare_evaluation(original_ast, reparsed_ast, test_data)
            self._record_eval_differences(result, eval_diffs)

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
        return self._normalize_code(code1) == self._normalize_code(code2)

    @staticmethod
    def _normalize_code(code: str) -> str:
        """Normalize code for equivalence comparisons."""
        # Normalize whitespace and line endings
        return "\n".join(line.strip() for line in code.strip().split("\n") if line.strip())

    def _compare_ast(self, ast1: YaraFile, ast2: YaraFile) -> list[str]:
        """Compare two ASTs and return differences."""
        differences = []

        # Compare imports by content
        imports1 = sorted(imp.module for imp in ast1.imports)
        imports2 = sorted(imp.module for imp in ast2.imports)
        if imports1 != imports2:
            differences.append(
                f"Imports differ: {imports1} vs {imports2}",
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

                # Compare modifiers
                if sorted(str(m) for m in rule1.modifiers) != sorted(
                    str(m) for m in rule2.modifiers
                ):
                    differences.append(
                        f"Rule {rule1.name} modifiers differ: {rule1.modifiers} vs {rule2.modifiers}",
                    )

                # Compare strings by count, identifier, and type
                if len(rule1.strings) != len(rule2.strings):
                    differences.append(
                        f"Rule {rule1.name} string count differs: "
                        f"{len(rule1.strings)} vs {len(rule2.strings)}",
                    )
                else:
                    for j, (s1, s2) in enumerate(zip(rule1.strings, rule2.strings, strict=False)):
                        if s1.identifier != s2.identifier:
                            differences.append(
                                f"Rule {rule1.name} string {j} identifier differs: {s1.identifier} vs {s2.identifier}",
                            )
                        if type(s1).__name__ != type(s2).__name__:
                            differences.append(
                                f"Rule {rule1.name} string {s1.identifier} type differs: {type(s1).__name__} vs {type(s2).__name__}",
                            )

                # Compare tags
                tags1 = sorted(t.name if hasattr(t, "name") else str(t) for t in rule1.tags)
                tags2 = sorted(t.name if hasattr(t, "name") else str(t) for t in rule2.tags)
                if tags1 != tags2:
                    differences.append(
                        f"Rule {rule1.name} tags differ: {tags1} vs {tags2}",
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
