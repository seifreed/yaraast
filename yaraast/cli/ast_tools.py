"""AST-based CLI tools for formatting, diffing, and benchmarking."""

import hashlib
import json
import statistics
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from yaraast.ast.base import ASTNode, YaraFile
from yaraast.codegen import CodeGenerator
from yaraast.codegen.pretty_printer import PrettyPrinter, StylePresets
from yaraast.parser import YaraParser
from yaraast.visitor.visitor import ASTVisitor


@dataclass
class ASTDiffResult:
    """Result of AST-based diff analysis."""

    has_changes: bool
    logical_changes: list[str] = field(default_factory=list)
    structural_changes: list[str] = field(default_factory=list)
    style_only_changes: list[str] = field(default_factory=list)
    added_rules: list[str] = field(default_factory=list)
    removed_rules: list[str] = field(default_factory=list)
    modified_rules: list[str] = field(default_factory=list)
    change_summary: dict[str, int] = field(default_factory=dict)


@dataclass
class BenchmarkResult:
    """Result of performance benchmark."""

    operation: str
    file_size: int
    execution_time: float
    rules_count: int
    strings_count: int
    ast_nodes: int
    memory_usage: int | None = None
    success: bool = True
    error: str | None = None


class ASTStructuralAnalyzer(ASTVisitor):
    """Analyze AST structure for diffing purposes."""

    def __init__(self):
        super().__init__()
        self.structural_hash = {}
        self.rule_signatures = {}
        self.string_signatures = {}
        self.condition_signatures = {}

    def analyze(self, ast: YaraFile) -> dict[str, Any]:
        """Analyze AST structure and create signatures."""
        self.structural_hash.clear()
        self.rule_signatures.clear()
        self.string_signatures.clear()
        self.condition_signatures.clear()

        self.visit(ast)

        return {
            "structural_hash": self.structural_hash,
            "rule_signatures": self.rule_signatures,
            "string_signatures": self.string_signatures,
            "condition_signatures": self.condition_signatures,
            "total_rules": len(ast.rules),
            "total_imports": len(ast.imports),
            "total_includes": len(ast.includes),
        }

    def visit_yara_file(self, node: YaraFile) -> Any:
        """Visit YARA file node."""
        file_structure = {
            "imports": [imp.module for imp in node.imports],
            "includes": [inc.path for inc in node.includes],
            "rules": [rule.name for rule in node.rules],
        }
        self.structural_hash["file"] = self._hash_dict(file_structure)

        # Process each rule
        for rule in node.rules:
            self.visit(rule)

        return super().visit_yara_file(node)

    def visit_rule(self, rule) -> Any:
        """Visit rule node and create signature."""
        rule_structure = {
            "name": rule.name,
            "modifiers": sorted(getattr(rule, "modifiers", [])),
            "tags": sorted([tag.name for tag in getattr(rule, "tags", [])]),
            "meta_keys": sorted([meta.key for meta in getattr(rule, "meta", [])]),
            "string_identifiers": sorted([s.identifier for s in getattr(rule, "strings", [])]),
            "has_condition": rule.condition is not None,
        }

        self.rule_signatures[rule.name] = self._hash_dict(rule_structure)

        # Analyze strings
        for string_def in getattr(rule, "strings", []):
            self._analyze_string(string_def)

        # Analyze condition
        if rule.condition:
            self._analyze_condition(rule.condition, rule.name)

        return super().visit_rule(rule)

    def _analyze_string(self, string_def) -> None:
        """Analyze string definition."""
        string_structure = {
            "identifier": string_def.identifier,
            "type": type(string_def).__name__,
            "modifiers": sorted([str(mod) for mod in getattr(string_def, "modifiers", [])]),
        }

        # Add type-specific content hash (without exact content for style independence)
        if hasattr(string_def, "value"):
            string_structure["content_type"] = "literal"
            string_structure["content_length"] = len(str(string_def.value))
        elif hasattr(string_def, "pattern"):
            string_structure["content_type"] = "regex"
            string_structure["pattern_length"] = len(str(string_def.pattern))
        elif hasattr(string_def, "tokens"):
            string_structure["content_type"] = "hex"
            string_structure["token_count"] = len(getattr(string_def, "tokens", []))

        self.string_signatures[string_def.identifier] = self._hash_dict(string_structure)

    def _analyze_condition(self, condition, rule_name: str) -> None:
        """Analyze condition structure."""
        condition_structure = self._get_condition_structure(condition)
        self.condition_signatures[f"{rule_name}.condition"] = self._hash_dict(condition_structure)

    def _get_condition_structure(self, node) -> dict[str, Any]:
        """Get structural representation of condition."""
        if node is None:
            return {"type": "empty"}

        structure = {"type": type(node).__name__}

        # Add node-specific structural information
        if hasattr(node, "operator"):
            structure["operator"] = node.operator

        if hasattr(node, "children"):
            structure["children"] = [
                self._get_condition_structure(child) for child in node.children()
            ]
        elif hasattr(node, "left") and hasattr(node, "right"):
            structure["left"] = self._get_condition_structure(node.left)
            structure["right"] = self._get_condition_structure(node.right)
        elif hasattr(node, "operand"):
            structure["operand"] = self._get_condition_structure(node.operand)

        return structure

    def _hash_dict(self, data: dict[str, Any]) -> str:
        """Create hash of dictionary for comparison."""
        json_str = json.dumps(data, sort_keys=True, default=str)
        return hashlib.md5(json_str.encode()).hexdigest()


class ASTDiffer:
    """Compare ASTs and identify logical vs stylistic changes."""

    def __init__(self):
        self.analyzer = ASTStructuralAnalyzer()

    def diff_files(self, file1_path: Path, file2_path: Path) -> ASTDiffResult:
        """Compare two YARA files at AST level."""
        try:
            # Parse both files
            parser = YaraParser()

            with open(file1_path) as f:
                ast1 = parser.parse(f.read())

            with open(file2_path) as f:
                ast2 = parser.parse(f.read())

            return self.diff_asts(ast1, ast2)

        except Exception as e:
            result = ASTDiffResult(has_changes=False)
            result.logical_changes.append(f"Error comparing files: {e}")
            return result

    def diff_asts(self, ast1: YaraFile, ast2: YaraFile) -> ASTDiffResult:
        """Compare two ASTs and identify types of changes."""
        # Analyze both ASTs
        analysis1 = self.analyzer.analyze(ast1)
        analysis2 = self.analyzer.analyze(ast2)

        result = ASTDiffResult(has_changes=False)

        # Compare file-level structure
        if analysis1["structural_hash"]["file"] != analysis2["structural_hash"]["file"]:
            result.structural_changes.append("File structure changed (imports/includes/rule order)")
            result.has_changes = True

        # Compare rules
        rules1 = set(analysis1["rule_signatures"].keys())
        rules2 = set(analysis2["rule_signatures"].keys())

        result.added_rules = list(rules2 - rules1)
        result.removed_rules = list(rules1 - rules2)
        result.modified_rules = []

        # Check modified rules
        common_rules = rules1 & rules2
        for rule_name in common_rules:
            if analysis1["rule_signatures"][rule_name] != analysis2["rule_signatures"][rule_name]:
                result.modified_rules.append(rule_name)
                result.logical_changes.append(
                    f"Rule '{rule_name}' modified (logic/structure changed)"
                )

        # Check string changes
        strings1 = set(analysis1["string_signatures"].keys())
        strings2 = set(analysis2["string_signatures"].keys())

        added_strings = strings2 - strings1
        removed_strings = strings1 - strings2

        if added_strings:
            result.logical_changes.append(f"Added strings: {', '.join(added_strings)}")
        if removed_strings:
            result.logical_changes.append(f"Removed strings: {', '.join(removed_strings)}")

        # Check condition changes
        conditions1 = set(analysis1["condition_signatures"].keys())
        conditions2 = set(analysis2["condition_signatures"].keys())

        common_conditions = conditions1 & conditions2
        for condition_key in common_conditions:
            if (
                analysis1["condition_signatures"][condition_key]
                != analysis2["condition_signatures"][condition_key]
            ):
                rule_name = condition_key.split(".")[0]
                result.logical_changes.append(f"Condition logic changed in rule '{rule_name}'")

        # Detect style-only changes by comparing generated output
        result = self._detect_style_changes(ast1, ast2, result)

        # Update has_changes flag
        result.has_changes = bool(
            result.logical_changes
            or result.structural_changes
            or result.added_rules
            or result.removed_rules
            or result.modified_rules
        )

        # Create summary
        result.change_summary = {
            "logical_changes": len(result.logical_changes),
            "structural_changes": len(result.structural_changes),
            "style_changes": len(result.style_only_changes),
            "added_rules": len(result.added_rules),
            "removed_rules": len(result.removed_rules),
            "modified_rules": len(result.modified_rules),
        }

        return result

    def _detect_style_changes(
        self, ast1: YaraFile, ast2: YaraFile, result: ASTDiffResult
    ) -> ASTDiffResult:
        """Detect style-only changes by normalizing output."""
        try:
            # Generate normalized code from both ASTs
            generator = CodeGenerator()
            code1_lines = generator.generate(ast1).strip().split("\n")
            code2_lines = generator.generate(ast2).strip().split("\n")

            # If AST diff shows no logical changes but text differs, it's style-only
            if not result.logical_changes and code1_lines != code2_lines:
                # Find specific style differences
                for line_num, (line1, line2) in enumerate(
                    zip(code1_lines, code2_lines, strict=False), 1
                ):
                    if line1.strip() == line2.strip() and line1 != line2:
                        result.style_only_changes.append(
                            f"Line {line_num}: whitespace/indentation change"
                        )
                    elif line1 != line2:
                        # Check if it's just formatting (same tokens, different spacing)
                        tokens1 = line1.split()
                        tokens2 = line2.split()
                        if tokens1 == tokens2:
                            result.style_only_changes.append(
                                f"Line {line_num}: spacing/formatting change"
                            )

        except Exception:
            # If we can't detect style changes, skip this analysis
            pass

        return result


class AST_Formatter:
    """AST-based code formatter using CodeGenerator."""

    def __init__(self):
        self.generator = CodeGenerator()
        self.pretty_printer = PrettyPrinter()

    def format_file(
        self, input_path: Path, output_path: Path | None = None, style: str = "default"
    ) -> tuple[bool, str]:
        """Format YARA file using AST regeneration."""
        try:
            # Parse file
            parser = YaraParser()
            with open(input_path) as f:
                content = f.read()

            ast = parser.parse(content)

            # Apply formatting style
            if style == "compact":
                formatted = self.generator.generate(ast)
            elif style == "pretty":
                formatted = self.pretty_printer.pretty_print(ast, StylePresets.readable())
            elif style == "verbose":
                formatted = self.pretty_printer.pretty_print(ast, StylePresets.verbose())
            else:  # default
                formatted = self.pretty_printer.pretty_print(ast)

            # Write output
            if output_path:
                with open(output_path, "w") as f:
                    f.write(formatted)
                return True, f"Formatted file written to {output_path}"
            return True, formatted

        except Exception as e:
            return False, f"Formatting error: {e}"

    def check_format(self, file_path: Path) -> tuple[bool, list[str]]:
        """Check if file needs formatting."""
        try:
            # Read original
            with open(file_path) as f:
                original = f.read()

            # Parse and regenerate
            parser = YaraParser()
            ast = parser.parse(original)
            formatted = self.pretty_printer.pretty_print(ast)

            if original.strip() == formatted.strip():
                return True, []

            # Find differences
            original_lines = original.strip().split("\n")
            formatted_lines = formatted.strip().split("\n")

            issues = []
            for i, (orig, fmt) in enumerate(zip(original_lines, formatted_lines, strict=False), 1):
                if orig != fmt:
                    issues.append(f"Line {i}: formatting issue")

            return False, issues

        except Exception as e:
            return False, [f"Check error: {e}"]


class ASTBenchmarker:
    """Performance benchmarking for AST operations."""

    def __init__(self):
        self.results: list[BenchmarkResult] = []

    def benchmark_parsing(self, file_path: Path, iterations: int = 10) -> BenchmarkResult:
        """Benchmark parsing performance."""
        try:
            # Read file once
            with open(file_path) as f:
                content = f.read()

            file_size = len(content.encode())
            parser = YaraParser()

            # Warm up
            ast = parser.parse(content)
            rules_count = len(ast.rules)
            strings_count = sum(len(rule.strings) for rule in ast.rules)
            ast_nodes = self._count_ast_nodes(ast)

            # Benchmark
            times = []
            for _ in range(iterations):
                start = time.perf_counter()
                parser = YaraParser()
                ast = parser.parse(content)
                end = time.perf_counter()
                times.append(end - start)

            avg_time = statistics.mean(times)

            result = BenchmarkResult(
                operation="parsing",
                file_size=file_size,
                execution_time=avg_time,
                rules_count=rules_count,
                strings_count=strings_count,
                ast_nodes=ast_nodes,
                success=True,
            )

            self.results.append(result)
            return result

        except Exception as e:
            result = BenchmarkResult(
                operation="parsing",
                file_size=0,
                execution_time=0,
                rules_count=0,
                strings_count=0,
                ast_nodes=0,
                success=False,
                error=str(e),
            )
            self.results.append(result)
            return result

    def benchmark_codegen(self, file_path: Path, iterations: int = 10) -> BenchmarkResult:
        """Benchmark code generation performance."""
        try:
            # Parse file once
            parser = YaraParser()
            with open(file_path) as f:
                content = f.read()

            file_size = len(content.encode())
            ast = parser.parse(content)
            rules_count = len(ast.rules)
            strings_count = sum(len(rule.strings) for rule in ast.rules)
            ast_nodes = self._count_ast_nodes(ast)

            generator = CodeGenerator()

            # Benchmark
            times = []
            for _ in range(iterations):
                start = time.perf_counter()
                generator.generate(ast)
                end = time.perf_counter()
                times.append(end - start)

            avg_time = statistics.mean(times)

            result = BenchmarkResult(
                operation="codegen",
                file_size=file_size,
                execution_time=avg_time,
                rules_count=rules_count,
                strings_count=strings_count,
                ast_nodes=ast_nodes,
                success=True,
            )

            self.results.append(result)
            return result

        except Exception as e:
            result = BenchmarkResult(
                operation="codegen",
                file_size=0,
                execution_time=0,
                rules_count=0,
                strings_count=0,
                ast_nodes=0,
                success=False,
                error=str(e),
            )
            self.results.append(result)
            return result

    def benchmark_roundtrip(self, file_path: Path, iterations: int = 5) -> list[BenchmarkResult]:
        """Benchmark full parse->generate roundtrip."""
        results = []

        try:
            with open(file_path) as f:
                content = f.read()

            file_size = len(content.encode())

            # Test roundtrip
            times = []
            for _ in range(iterations):
                start = time.perf_counter()

                parser = YaraParser()
                ast = parser.parse(content)

                generator = CodeGenerator()
                generator.generate(ast)

                end = time.perf_counter()
                times.append(end - start)

            avg_time = statistics.mean(times)

            # Parse once more for statistics
            parser = YaraParser()
            ast = parser.parse(content)
            rules_count = len(ast.rules)
            strings_count = sum(len(rule.strings) for rule in ast.rules)
            ast_nodes = self._count_ast_nodes(ast)

            result = BenchmarkResult(
                operation="roundtrip",
                file_size=file_size,
                execution_time=avg_time,
                rules_count=rules_count,
                strings_count=strings_count,
                ast_nodes=ast_nodes,
                success=True,
            )

            results.append(result)
            self.results.append(result)

        except Exception as e:
            result = BenchmarkResult(
                operation="roundtrip",
                file_size=0,
                execution_time=0,
                rules_count=0,
                strings_count=0,
                ast_nodes=0,
                success=False,
                error=str(e),
            )
            results.append(result)
            self.results.append(result)

        return results

    def _count_ast_nodes(self, ast: YaraFile) -> int:
        """Count total AST nodes."""
        count = 1  # YaraFile itself

        def count_node(node: ASTNode) -> int:
            node_count = 1
            for child in node.children():
                node_count += count_node(child)
            return node_count

        for child in ast.children():
            count += count_node(child)

        return count

    def get_benchmark_summary(self) -> dict[str, Any]:
        """Get summary of all benchmark results."""
        if not self.results:
            return {"message": "No benchmarks run"}

        by_operation = {}
        for result in self.results:
            if result.operation not in by_operation:
                by_operation[result.operation] = []
            by_operation[result.operation].append(result)

        summary = {}
        for operation, results in by_operation.items():
            successful = [r for r in results if r.success]
            if successful:
                times = [r.execution_time for r in successful]
                summary[operation] = {
                    "count": len(successful),
                    "avg_time": statistics.mean(times),
                    "min_time": min(times),
                    "max_time": max(times),
                    "total_files_processed": len(successful),
                    "total_rules_processed": sum(r.rules_count for r in successful),
                    "avg_rules_per_second": (
                        sum(r.rules_count for r in successful) / sum(times) if sum(times) > 0 else 0
                    ),
                }

        return summary

    def clear_results(self) -> None:
        """Clear benchmark results."""
        self.results.clear()
