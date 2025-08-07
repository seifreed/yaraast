"""AST-based CLI tools for formatting, diffing, and benchmarking."""

import hashlib
import json
import statistics
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.tree import Tree

from yaraast.ast.base import ASTNode, YaraFile
from yaraast.codegen import CodeGenerator
from yaraast.codegen.pretty_printer import PrettyPrinter
from yaraast.parser.parser import Parser
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

    def __init__(self) -> None:
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
        # Handle meta as dict or list
        meta_data = getattr(rule, "meta", [])
        if isinstance(meta_data, dict):
            meta_keys = sorted(meta_data.keys())
        else:
            meta_keys = sorted([m.key for m in meta_data if hasattr(m, "key")])

        rule_structure = {
            "name": rule.name,
            "modifiers": sorted(getattr(rule, "modifiers", [])),
            "tags": sorted([tag.name for tag in getattr(rule, "tags", [])]),
            "meta_keys": meta_keys,
            "string_identifiers": sorted(
                [s.identifier for s in getattr(rule, "strings", [])],
            ),
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
            "modifiers": sorted(
                [str(mod) for mod in getattr(string_def, "modifiers", [])],
            ),
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

        self.string_signatures[string_def.identifier] = self._hash_dict(
            string_structure,
        )

    def _analyze_condition(self, condition, rule_name: str) -> None:
        """Analyze condition structure."""
        condition_structure = self._get_condition_structure(condition)
        self.condition_signatures[f"{rule_name}.condition"] = self._hash_dict(
            condition_structure,
        )

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
        return hashlib.md5(json_str.encode(), usedforsecurity=False).hexdigest()

    # Add all missing abstract methods
    def visit_array_access(self, node) -> Any:
        """Visit Array Access node - not needed for structural analysis."""
        # Implementation not needed for structural analysis

    def visit_at_expression(self, node) -> Any:
        """Visit At Expression node - not needed for structural analysis."""
        # Implementation not needed for structural analysis

    def visit_binary_expression(self, node) -> Any:
        """Visit Binary Expression node - not needed for structural analysis."""
        # Implementation not needed for structural analysis

    def visit_boolean_literal(self, node) -> Any:
        """Visit Boolean Literal node - not needed for structural analysis."""
        # Implementation not needed for structural analysis

    def visit_comment(self, node) -> Any:
        """Visit Comment node - not needed for structural analysis."""
        # Implementation not needed for structural analysis

    def visit_comment_group(self, node) -> Any:
        """Visit Comment Group node - not needed for structural analysis."""
        # Implementation not needed for structural analysis

    def visit_condition(self, node) -> Any:
        """Visit Condition node - not needed for structural analysis."""
        # Implementation not needed for structural analysis

    def visit_defined_expression(self, node) -> Any:
        """Visit Defined Expression node - not needed for structural analysis."""
        # Implementation not needed for structural analysis

    def visit_dictionary_access(self, node) -> Any:
        """Visit Dictionary Access node - not needed for structural analysis."""
        # Implementation not needed for structural analysis

    def visit_double_literal(self, node) -> Any:
        """Visit Double Literal node - not needed for structural analysis."""
        # Implementation not needed for structural analysis

    def visit_expression(self, node) -> Any:
        """Visit Expression node - not needed for structural analysis."""
        # Implementation not needed for structural analysis

    def visit_extern_import(self, node) -> Any:
        """Visit Extern Import node - not needed for structural analysis."""
        # Implementation not needed for structural analysis

    def visit_extern_namespace(self, node) -> Any:
        """Visit Extern Namespace node - not needed for structural analysis."""
        # Implementation not needed for structural analysis

    def visit_extern_rule(self, node) -> Any:
        """Visit Extern Rule node - not needed for structural analysis."""
        # Implementation not needed for structural analysis

    def visit_extern_rule_reference(self, node) -> Any:
        """Visit Extern Rule Reference node - not needed for structural analysis."""
        # Implementation not needed for structural analysis

    def visit_for_expression(self, node) -> Any:
        """Visit For Expression node - not needed for structural analysis."""
        # Implementation not needed for structural analysis

    def visit_for_of_expression(self, node) -> Any:
        """Visit For Of Expression node - not needed for structural analysis."""
        # Implementation not needed for structural analysis

    def visit_function_call(self, node) -> Any:
        """Visit Function Call node - not needed for structural analysis."""
        # Implementation not needed for structural analysis

    def visit_hex_alternative(self, node) -> Any:
        """Visit Hex Alternative node - not needed for structural analysis."""
        # Implementation not needed for structural analysis

    def visit_hex_byte(self, node) -> Any:
        """Visit Hex Byte node - not needed for structural analysis."""
        # Implementation not needed for structural analysis

    def visit_hex_jump(self, node) -> Any:
        """Visit Hex Jump node - not needed for structural analysis."""
        # Implementation not needed for structural analysis

    def visit_hex_nibble(self, node) -> Any:
        """Visit Hex Nibble node - not needed for structural analysis."""
        # Implementation not needed for structural analysis

    def visit_hex_string(self, node) -> Any:
        """Visit Hex String node - not needed for structural analysis."""
        # Implementation not needed for structural analysis

    def visit_hex_token(self, node) -> Any:
        """Visit Hex Token node - not needed for structural analysis."""
        # Implementation not needed for structural analysis

    def visit_hex_wildcard(self, node) -> Any:
        """Visit Hex Wildcard node - not needed for structural analysis."""
        # Implementation not needed for structural analysis

    def visit_identifier(self, node) -> Any:
        """Visit Identifier node - not needed for structural analysis."""
        # Implementation not needed for structural analysis

    def visit_import(self, node) -> Any:
        """Visit Import node - not needed for structural analysis."""
        # Implementation not needed for structural analysis

    def visit_in_expression(self, node) -> Any:
        """Visit In Expression node - not needed for structural analysis."""
        # Implementation not needed for structural analysis

    def visit_in_rule_pragma(self, node) -> Any:
        """Visit In Rule Pragma node - not needed for structural analysis."""
        # Implementation not needed for structural analysis

    def visit_include(self, node) -> Any:
        """Visit Include node - not needed for structural analysis."""
        # Implementation not needed for structural analysis

    def visit_integer_literal(self, node) -> Any:
        """Visit Integer Literal node - not needed for structural analysis."""
        # Implementation not needed for structural analysis

    def visit_member_access(self, node) -> Any:
        """Visit Member Access node - not needed for structural analysis."""
        # Implementation not needed for structural analysis

    def visit_meta(self, node) -> Any:
        """Visit Meta node - not needed for structural analysis."""
        # Implementation not needed for structural analysis

    def visit_module_reference(self, node) -> Any:
        """Visit Module Reference node - not needed for structural analysis."""
        # Implementation not needed for structural analysis

    def visit_of_expression(self, node) -> Any:
        """Visit Of Expression node - not needed for structural analysis."""
        # Implementation not needed for structural analysis

    def visit_parentheses_expression(self, node) -> Any:
        """Visit Parentheses Expression node - not needed for structural analysis."""
        # Implementation not needed for structural analysis

    def visit_plain_string(self, node) -> Any:
        """Visit Plain String node - not needed for structural analysis."""
        # Implementation not needed for structural analysis

    def visit_pragma(self, node) -> Any:
        """Visit Pragma node - not needed for structural analysis."""
        # Implementation not needed for structural analysis

    def visit_pragma_block(self, node) -> Any:
        """Visit Pragma Block node - not needed for structural analysis."""
        # Implementation not needed for structural analysis

    def visit_range_expression(self, node) -> Any:
        """Visit Range Expression node - not needed for structural analysis."""
        # Implementation not needed for structural analysis

    def visit_regex_literal(self, node) -> Any:
        """Visit Regex Literal node - not needed for structural analysis."""
        # Implementation not needed for structural analysis

    def visit_regex_string(self, node) -> Any:
        """Visit Regex String node - not needed for structural analysis."""
        # Implementation not needed for structural analysis

    def visit_set_expression(self, node) -> Any:
        """Visit Set Expression node - not needed for structural analysis."""
        # Implementation not needed for structural analysis

    def visit_string_count(self, node) -> Any:
        """Visit String Count node - not needed for structural analysis."""
        # Implementation not needed for structural analysis

    def visit_string_definition(self, node) -> Any:
        """Visit String Definition node - not needed for structural analysis."""
        # Implementation not needed for structural analysis

    def visit_string_identifier(self, node) -> Any:
        """Visit String Identifier node - not needed for structural analysis."""
        # Implementation not needed for structural analysis

    def visit_string_length(self, node) -> Any:
        """Visit String Length node - not needed for structural analysis."""
        # Implementation not needed for structural analysis

    def visit_string_literal(self, node) -> Any:
        """Visit String Literal node - not needed for structural analysis."""
        # Implementation not needed for structural analysis

    def visit_string_modifier(self, node) -> Any:
        """Visit String Modifier node - not needed for structural analysis."""
        # Implementation not needed for structural analysis

    def visit_string_offset(self, node) -> Any:
        """Visit String Offset node - not needed for structural analysis."""
        # Implementation not needed for structural analysis

    def visit_string_operator_expression(self, node) -> Any:
        """Visit String Operator Expression node - not needed for structural analysis."""
        # Implementation not needed for structural analysis

    def visit_tag(self, node) -> Any:
        """Visit Tag node - not needed for structural analysis."""
        # Implementation not needed for structural analysis

    def visit_unary_expression(self, node) -> Any:
        """Visit Unary Expression node - not needed for structural analysis."""
        # Implementation not needed for structural analysis


class ASTDiffer:
    """Compare ASTs and identify logical vs stylistic changes."""

    def __init__(self) -> None:
        self.analyzer = ASTStructuralAnalyzer()

    def diff_files(self, file1_path: Path, file2_path: Path) -> ASTDiffResult:
        """Compare two YARA files at AST level."""
        try:
            # Parse both files
            with Path(file1_path).open() as f:
                content1 = f.read()
                parser1 = Parser(content1)
                ast1 = parser1.parse()

            with Path(file2_path).open() as f:
                content2 = f.read()
                parser2 = Parser(content2)
                ast2 = parser2.parse()

            return self.diff_asts(ast1, ast2)

        except Exception as e:
            result = ASTDiffResult(has_changes=False)
            result.logical_changes.append(f"Error comparing files: {e}")
            return result

    def diff_asts(self, ast1: YaraFile, ast2: YaraFile) -> ASTDiffResult:
        """Compare two ASTs and identify types of changes."""
        # Analyze both ASTs with fresh analyzers
        analyzer1 = ASTStructuralAnalyzer()
        analyzer2 = ASTStructuralAnalyzer()
        analysis1 = analyzer1.analyze(ast1)
        analysis2 = analyzer2.analyze(ast2)

        result = ASTDiffResult(has_changes=False)

        # Compare file-level structure
        if analysis1["structural_hash"]["file"] != analysis2["structural_hash"]["file"]:
            result.structural_changes.append(
                "File structure changed (imports/includes/rule order)",
            )
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
                    f"Rule '{rule_name}' modified (logic/structure changed)",
                )

        # Check string changes
        strings1 = set(analysis1["string_signatures"].keys())
        strings2 = set(analysis2["string_signatures"].keys())

        added_strings = strings2 - strings1
        removed_strings = strings1 - strings2

        if added_strings:
            result.logical_changes.append(f"Added strings: {', '.join(added_strings)}")
        if removed_strings:
            result.logical_changes.append(
                f"Removed strings: {', '.join(removed_strings)}",
            )

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
                result.logical_changes.append(
                    f"Condition logic changed in rule '{rule_name}'",
                )

        # Detect style-only changes by comparing generated output
        result = self._detect_style_changes(ast1, ast2, result)

        # Update has_changes flag
        result.has_changes = bool(
            result.logical_changes
            or result.structural_changes
            or result.added_rules
            or result.removed_rules
            or result.modified_rules,
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
        self,
        ast1: YaraFile,
        ast2: YaraFile,
        result: ASTDiffResult,
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
                    zip(code1_lines, code2_lines, strict=False),
                    1,
                ):
                    if line1.strip() == line2.strip() and line1 != line2:
                        result.style_only_changes.append(
                            f"Line {line_num}: whitespace/indentation change",
                        )
                    elif line1 != line2:
                        # Check if it's just formatting (same tokens, different spacing)
                        tokens1 = line1.split()
                        tokens2 = line2.split()
                        if tokens1 == tokens2:
                            result.style_only_changes.append(
                                f"Line {line_num}: spacing/formatting change",
                            )

        except (ValueError, TypeError, AttributeError):
            # If we can't detect style changes, skip this analysis
            pass  # Implementation not needed for structural analysis

        return result


class ASTFormatter:
    """AST-based code formatter using CodeGenerator."""

    def __init__(self) -> None:
        self.generator = CodeGenerator()
        self.pretty_printer = PrettyPrinter()

    def format_file(
        self,
        input_path: Path,
        output_path: Path | None = None,
        style: str = "default",
    ) -> tuple[bool, str]:
        """Format YARA file using AST regeneration."""
        try:
            # Parse file
            with Path(input_path).open() as f:
                content = f.read()
                parser = Parser(content)
                ast = parser.parse()

            # Apply formatting style
            if style == "compact":
                formatted = self.generator.generate(ast)
            elif style in ("pretty", "verbose"):
                # Use readable preset by configuring the printer (same for pretty and verbose for now)
                self.pretty_printer = PrettyPrinter()
                formatted = self.pretty_printer.pretty_print(ast)
            else:  # default
                formatted = self.pretty_printer.pretty_print(ast)

            # Write output
            if output_path:
                with Path(output_path).open("w") as f:
                    f.write(formatted)
                return True, f"Formatted file written to {output_path}"
            return True, formatted

        except Exception as e:
            return False, f"Formatting error: {e}"

    def check_format(self, file_path: Path) -> tuple[bool, list[str]]:
        """Check if file needs formatting."""
        try:
            # Read original
            with Path(file_path).open() as f:
                original = f.read()

            # Parse and regenerate
            parser = Parser(original)
            ast = parser.parse()
            formatted = self.pretty_printer.pretty_print(ast)

            if original.strip() == formatted.strip():
                return False, []

            # Find differences
            original_lines = original.strip().split("\n")
            formatted_lines = formatted.strip().split("\n")

            issues = []
            for i, (orig, fmt) in enumerate(
                zip(original_lines, formatted_lines, strict=False),
                1,
            ):
                if orig != fmt:
                    issues.append(f"Line {i}: formatting issue")

            return len(issues) > 0, issues

        except Exception as e:
            return False, [f"Check error: {e}"]


class ASTBenchmarker:
    """Performance benchmarking for AST operations."""

    def __init__(self) -> None:
        self.results: list[BenchmarkResult] = []

    def benchmark_parsing(
        self,
        file_path: Path,
        iterations: int = 10,
    ) -> BenchmarkResult:
        """Benchmark parsing performance."""
        try:
            # Read file once
            with Path(file_path).open() as f:
                content = f.read()

            file_size = len(content.encode())
            # Parser will be instantiated with content

            # Warm up
            parser = Parser(content)
            ast = parser.parse()
            rules_count = len(ast.rules)
            strings_count = sum(len(rule.strings) for rule in ast.rules)
            ast_nodes = self._count_ast_nodes(ast)

            # Benchmark
            times = []
            for _ in range(iterations):
                start = time.perf_counter()
                parser = Parser(content)
                ast = parser.parse()
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

    def benchmark_codegen(
        self,
        file_path: Path,
        iterations: int = 10,
    ) -> BenchmarkResult:
        """Benchmark code generation performance."""
        try:
            # Parse file once
            # Parser will be instantiated with content
            with Path(file_path).open() as f:
                content = f.read()

            file_size = len(content.encode())
            parser = Parser(content)
            ast = parser.parse()
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

    def benchmark_roundtrip(
        self,
        file_path: Path,
        iterations: int = 5,
    ) -> list[BenchmarkResult]:
        """Benchmark full parse->generate roundtrip."""
        results = []

        try:
            with Path(file_path).open() as f:
                content = f.read()

            file_size = len(content.encode())

            # Test roundtrip
            times = []
            for _ in range(iterations):
                start = time.perf_counter()

                parser = Parser(content)
                ast = parser.parse()

                generator = CodeGenerator()
                generator.generate(ast)

                end = time.perf_counter()
                times.append(end - start)

            avg_time = statistics.mean(times)

            # Parse once more for statistics
            # Parser will be instantiated with content
            parser = Parser(content)
            ast = parser.parse()
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


def print_ast(ast: YaraFile, console: Console | None = None) -> None:
    """Print AST in a readable format.

    Args:
        ast: The YARA AST to print
        console: Rich console to use (creates new if None)

    """
    if console is None:
        console = Console()

    tree = Tree("YaraFile")

    _add_imports_to_tree(tree, ast.imports)
    _add_includes_to_tree(tree, ast.includes)
    _add_rules_to_tree(tree, ast.rules)

    console.print(tree)


def _add_imports_to_tree(tree: Tree, imports) -> None:
    """Add imports to the tree."""
    if not imports:
        return

    imports_branch = tree.add("imports")
    for imp in imports:
        imp_text = f'import "{imp.module}"'
        if hasattr(imp, "alias") and imp.alias:
            imp_text += f" as {imp.alias}"
        imports_branch.add(imp_text)


def _add_includes_to_tree(tree: Tree, includes) -> None:
    """Add includes to the tree."""
    if not includes:
        return

    includes_branch = tree.add("includes")
    for inc in includes:
        includes_branch.add(f'include "{inc.path}"')


def _add_rules_to_tree(tree: Tree, rules) -> None:
    """Add rules to the tree."""
    if not rules:
        return

    rules_branch = tree.add("rules")
    for rule in rules:
        rule_branch = _create_rule_branch(rules_branch, rule)
        _add_rule_components(rule_branch, rule)


def _create_rule_branch(rules_branch, rule):
    """Create a rule branch in the tree."""
    rule_text = f"rule {rule.name}"
    if hasattr(rule, "modifiers") and rule.modifiers:
        rule_text = f"{' '.join(rule.modifiers)} {rule_text}"
    return rules_branch.add(rule_text)


def _add_rule_components(rule_branch, rule) -> None:
    """Add rule components (tags, meta, strings, condition) to the rule branch."""
    _add_tags_to_rule(rule_branch, rule)
    _add_meta_to_rule(rule_branch, rule)
    _add_strings_to_rule(rule_branch, rule)
    _add_condition_to_rule(rule_branch, rule)


def _add_tags_to_rule(rule_branch, rule) -> None:
    """Add tags to the rule branch."""
    if not (hasattr(rule, "tags") and rule.tags):
        return

    tags_branch = rule_branch.add("tags")
    for tag in rule.tags:
        tag_name = tag.name if hasattr(tag, "name") else str(tag)
        tags_branch.add(tag_name)


def _add_meta_to_rule(rule_branch, rule) -> None:
    """Add meta to the rule branch."""
    if not (hasattr(rule, "meta") and rule.meta):
        return

    meta_branch = rule_branch.add("meta")
    if isinstance(rule.meta, dict):
        for key, value in rule.meta.items():
            meta_branch.add(f"{key} = {value}")
    else:
        for meta_item in rule.meta:
            if hasattr(meta_item, "key"):
                meta_branch.add(f"{meta_item.key} = {meta_item.value}")


def _add_strings_to_rule(rule_branch, rule) -> None:
    """Add strings to the rule branch."""
    if not (hasattr(rule, "strings") and rule.strings):
        return

    strings_branch = rule_branch.add("strings")
    for string_def in rule.strings:
        string_type = type(string_def).__name__
        strings_branch.add(f"{string_def.identifier} ({string_type})")


def _add_condition_to_rule(rule_branch, rule) -> None:
    """Add condition to the rule branch."""
    if not (hasattr(rule, "condition") and rule.condition):
        return

    condition_branch = rule_branch.add("condition")
    condition_type = type(rule.condition).__name__
    condition_branch.add(condition_type)


def visualize_ast(ast: YaraFile, output_format: str = "tree") -> str:
    """Visualize AST in various formats.

    Args:
        ast: The YARA AST to visualize
        output_format: Format to use ("tree", "json", "yaml")

    Returns:
        String representation in the requested format

    """
    if output_format == "tree":
        # Use print_ast to generate tree
        from io import StringIO

        from rich.console import Console

        string_io = StringIO()
        console = Console(file=string_io, force_terminal=True)
        print_ast(ast, console)
        return string_io.getvalue()

    if output_format == "json":
        # Convert to JSON
        from yaraast.serialization.json_serializer import JsonSerializer

        serializer = JsonSerializer()
        return serializer.serialize(ast)

    if output_format == "yaml":
        # Convert to YAML
        try:
            from yaraast.serialization.yaml_serializer import YamlSerializer

            serializer = YamlSerializer()
            return serializer.serialize(ast)
        except ImportError:
            return "YAML serialization not available (install pyyaml)"

    else:
        return f"Unknown format: {output_format}"
