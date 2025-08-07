"""AST-based complexity analysis for YARA rules."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from yaraast.ast.conditions import ForExpression, ForOfExpression, OfExpression
from yaraast.ast.strings import HexString, PlainString, RegexString
from yaraast.parser import Parser
from yaraast.visitor import ASTVisitor

if TYPE_CHECKING:
    from pathlib import Path

    from yaraast.ast.base import ASTNode, YaraFile
    from yaraast.ast.expressions import BinaryExpression, UnaryExpression
    from yaraast.ast.rules import Rule


@dataclass
class ComplexityMetrics:
    """Complexity metrics for YARA rules."""

    # File-level metrics
    total_rules: int = 0
    total_imports: int = 0
    total_includes: int = 0

    # Rule-level metrics
    rules_with_strings: int = 0
    rules_with_meta: int = 0
    rules_with_tags: int = 0
    private_rules: int = 0
    global_rules: int = 0

    # String complexity
    total_strings: int = 0
    plain_strings: int = 0
    hex_strings: int = 0
    regex_strings: int = 0
    strings_with_modifiers: int = 0

    # Condition complexity
    max_condition_depth: int = 0
    avg_condition_depth: float = 0.0
    total_binary_ops: int = 0
    total_unary_ops: int = 0
    for_expressions: int = 0
    for_of_expressions: int = 0
    of_expressions: int = 0

    # Pattern complexity
    hex_wildcards: int = 0
    hex_jumps: int = 0
    hex_alternatives: int = 0
    regex_groups: int = 0
    regex_quantifiers: int = 0

    # Quality metrics
    unused_strings: list[str] = field(default_factory=list)
    complex_rules: list[str] = field(default_factory=list)  # Rules exceeding thresholds
    cyclomatic_complexity: dict[str, int] = field(default_factory=dict)

    # Dependencies
    string_dependencies: dict[str, set[str]] = field(default_factory=dict)
    module_usage: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert metrics to dictionary for serialization."""
        return {
            "file_metrics": {
                "total_rules": self.total_rules,
                "total_imports": self.total_imports,
                "total_includes": self.total_includes,
            },
            "rule_metrics": {
                "rules_with_strings": self.rules_with_strings,
                "rules_with_meta": self.rules_with_meta,
                "rules_with_tags": self.rules_with_tags,
                "private_rules": self.private_rules,
                "global_rules": self.global_rules,
            },
            "string_metrics": {
                "total_strings": self.total_strings,
                "plain_strings": self.plain_strings,
                "hex_strings": self.hex_strings,
                "regex_strings": self.regex_strings,
                "strings_with_modifiers": self.strings_with_modifiers,
            },
            "condition_metrics": {
                "max_condition_depth": self.max_condition_depth,
                "avg_condition_depth": self.avg_condition_depth,
                "total_binary_ops": self.total_binary_ops,
                "total_unary_ops": self.total_unary_ops,
                "for_expressions": self.for_expressions,
                "for_of_expressions": self.for_of_expressions,
                "of_expressions": self.of_expressions,
            },
            "pattern_metrics": {
                "hex_wildcards": self.hex_wildcards,
                "hex_jumps": self.hex_jumps,
                "hex_alternatives": self.hex_alternatives,
                "regex_groups": self.regex_groups,
                "regex_quantifiers": self.regex_quantifiers,
            },
            "quality_metrics": {
                "unused_strings": self.unused_strings,
                "complex_rules": self.complex_rules,
                "cyclomatic_complexity": self.cyclomatic_complexity,
            },
            "dependencies": {
                "string_dependencies": {k: list(v) for k, v in self.string_dependencies.items()},
                "module_usage": self.module_usage,
            },
        }

    def get_quality_score(self) -> float:
        """Calculate overall quality score (0-100)."""
        score = 100.0

        # Deduct for complexity issues
        if self.max_condition_depth > 8:
            score -= 20
        elif self.max_condition_depth > 5:
            score -= 10

        # Deduct for unused strings
        if self.unused_strings:
            score -= min(20, len(self.unused_strings) * 5)

        # Deduct for very complex rules
        if self.complex_rules:
            score -= min(25, len(self.complex_rules) * 10)

        # Bonus for good practices
        if self.rules_with_meta / max(1, self.total_rules) > 0.8:
            score += 5

        return max(0.0, score)

    def get_complexity_grade(self) -> str:
        """Get letter grade for complexity."""
        score = self.get_quality_score()
        if score >= 90:
            return "A"
        if score >= 80:
            return "B"
        if score >= 70:
            return "C"
        if score >= 60:
            return "D"
        return "F"


class ComplexityAnalyzer(ASTVisitor[None]):
    """Analyzes AST complexity metrics."""

    def __init__(self) -> None:
        self.metrics = ComplexityMetrics()
        self._current_rule: Rule | None = None
        self._condition_depths: list[int] = []
        self._current_depth = 0
        self._string_usage: dict[str, set[str]] = defaultdict(
            set,
        )  # string_id -> rule_names
        self._rule_strings: dict[str, set[str]] = defaultdict(
            set,
        )  # rule_name -> string_ids

    def analyze(self, ast: YaraFile) -> ComplexityMetrics:
        """Analyze AST and return complexity metrics."""
        self.metrics = ComplexityMetrics()
        self._condition_depths.clear()
        self._current_depth = 0
        self._string_usage.clear()
        self._rule_strings.clear()

        # File-level metrics
        self.metrics.total_rules = len(ast.rules)
        self.metrics.total_imports = len(ast.imports)
        self.metrics.total_includes = len(ast.includes)

        # Module usage from imports
        for imp in ast.imports:
            self.metrics.module_usage[imp.module] = self.metrics.module_usage.get(imp.module, 0) + 1

        # Analyze each rule
        for rule in ast.rules:
            self._analyze_rule(rule)

        # Post-analysis calculations
        self._calculate_derived_metrics()

        return self.metrics

    def _analyze_rule(self, rule: Rule) -> None:
        """Analyze a single rule."""
        self._current_rule = rule

        # Rule modifiers
        if "private" in rule.modifiers:
            self.metrics.private_rules += 1
        if "global" in rule.modifiers:
            self.metrics.global_rules += 1

        # Rule sections
        if rule.strings:
            self.metrics.rules_with_strings += 1
            self._analyze_strings(rule)

        if rule.meta:
            self.metrics.rules_with_meta += 1

        if rule.tags:
            self.metrics.rules_with_tags += 1

        # Condition analysis
        if rule.condition:
            self._current_depth = 0
            self.visit(rule.condition)
            rule_max_depth = max(self._condition_depths) if self._condition_depths else 0
            self.metrics.max_condition_depth = max(
                self.metrics.max_condition_depth,
                rule_max_depth,
            )

            # Calculate cyclomatic complexity for this rule
            self.metrics.cyclomatic_complexity[rule.name] = self._calculate_cyclomatic_complexity()

            # Check if rule is complex
            if rule_max_depth > 6 or self.metrics.cyclomatic_complexity[rule.name] > 10:
                self.metrics.complex_rules.append(rule.name)

    def _analyze_strings(self, rule: Rule) -> None:
        """Analyze string definitions in a rule."""
        for string_def in rule.strings:
            self.metrics.total_strings += 1
            self._rule_strings[rule.name].add(string_def.identifier)

            if isinstance(string_def, PlainString):
                self.metrics.plain_strings += 1
                if string_def.modifiers:
                    self.metrics.strings_with_modifiers += 1

            elif isinstance(string_def, HexString):
                self.metrics.hex_strings += 1
                if string_def.modifiers:
                    self.metrics.strings_with_modifiers += 1

                # Analyze hex tokens
                self._analyze_hex_tokens(string_def.tokens)

            elif isinstance(string_def, RegexString):
                self.metrics.regex_strings += 1
                if string_def.modifiers:
                    self.metrics.strings_with_modifiers += 1

                # Analyze regex complexity
                self._analyze_regex_complexity(string_def.regex)

    def _analyze_hex_tokens(self, tokens: list) -> None:
        """Analyze hex string tokens."""
        from yaraast.ast.strings import HexAlternative, HexJump, HexWildcard

        for token in tokens:
            if isinstance(token, HexWildcard):
                self.metrics.hex_wildcards += 1
            elif isinstance(token, HexJump):
                self.metrics.hex_jumps += 1
            elif isinstance(token, HexAlternative):
                self.metrics.hex_alternatives += 1

    def _analyze_regex_complexity(self, regex: str) -> None:
        """Analyze regex pattern complexity."""
        import re

        # Count groups
        self.metrics.regex_groups += len(re.findall(r"\([^?]", regex))

        # Count quantifiers
        quantifiers = r"[*+?{]"
        self.metrics.regex_quantifiers += len(re.findall(quantifiers, regex))

    def _calculate_cyclomatic_complexity(self) -> int:
        """Calculate cyclomatic complexity for current rule."""
        # Start with 1 (linear path)
        complexity = 1

        # Add complexity for each decision point
        complexity += self.metrics.total_binary_ops  # Each binary op is a decision
        complexity += self.metrics.for_expressions
        complexity += self.metrics.for_of_expressions
        complexity += self.metrics.of_expressions

        return complexity

    def _calculate_derived_metrics(self) -> None:
        """Calculate derived metrics after analysis."""
        # Average condition depth
        if self._condition_depths:
            self.metrics.avg_condition_depth = sum(self._condition_depths) / len(
                self._condition_depths,
            )

        # Find unused strings
        for rule_name, string_ids in self._rule_strings.items():
            used_strings = self._string_usage.get(rule_name, set())
            unused = string_ids - used_strings
            for unused_string in unused:
                self.metrics.unused_strings.append(f"{rule_name}:{unused_string}")

        # String dependencies
        for rule_name, string_ids in self._string_usage.items():
            if string_ids:
                self.metrics.string_dependencies[rule_name] = string_ids

    # Visitor methods
    def visit_binary_expression(self, node: BinaryExpression) -> None:
        """Visit binary expression and track complexity."""
        self._current_depth += 1
        self._condition_depths.append(self._current_depth)
        self.metrics.total_binary_ops += 1

        self.visit(node.left)
        self.visit(node.right)
        self._current_depth -= 1

    def visit_unary_expression(self, node: UnaryExpression) -> None:
        """Visit unary expression."""
        self.metrics.total_unary_ops += 1
        self.visit(node.operand)

    def visit_for_expression(self, node: ForExpression) -> None:
        """Visit for expression."""
        self._current_depth += 1
        self._condition_depths.append(self._current_depth)
        self.metrics.for_expressions += 1

        self.visit(node.iterable)
        self.visit(node.body)
        self._current_depth -= 1

    def visit_for_of_expression(self, node: ForOfExpression) -> None:
        """Visit for-of expression."""
        self._current_depth += 1
        self._condition_depths.append(self._current_depth)
        self.metrics.for_of_expressions += 1

        self.visit(node.string_set)
        if node.condition:
            self.visit(node.condition)
        self._current_depth -= 1

    def visit_of_expression(self, node: OfExpression) -> None:
        """Visit of expression."""
        self.metrics.of_expressions += 1

        if hasattr(node.quantifier, "accept"):
            self.visit(node.quantifier)
        if hasattr(node.string_set, "accept"):
            self.visit(node.string_set)

    def visit_string_identifier(self, node) -> None:
        """Track string usage."""
        if self._current_rule:
            self._string_usage[self._current_rule.name].add(node.name)

    # Required visitor methods (minimal implementations)
    def visit_yara_file(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_import(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_include(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_rule(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_tag(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_string_definition(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_plain_string(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_hex_string(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_regex_string(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_string_modifier(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_hex_token(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_hex_byte(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_hex_wildcard(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_hex_jump(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_hex_alternative(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_hex_nibble(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_expression(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_identifier(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_string_count(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_string_offset(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_string_length(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_integer_literal(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_double_literal(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_string_literal(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_regex_literal(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_boolean_literal(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_parentheses_expression(self, node) -> None:
        self.visit(node.expression)

    def visit_set_expression(self, node) -> None:
        for elem in node.elements:
            self.visit(elem)

    def visit_range_expression(self, node) -> None:
        self.visit(node.low)
        self.visit(node.high)

    def visit_function_call(self, node) -> None:
        for arg in node.arguments:
            self.visit(arg)

    def visit_array_access(self, node) -> None:
        self.visit(node.array)
        self.visit(node.index)

    def visit_member_access(self, node) -> None:
        self.visit(node.object)

    def visit_condition(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_at_expression(self, node) -> None:
        self.visit(node.offset)

    def visit_in_expression(self, node) -> None:
        self.visit(node.range)

    def visit_meta(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_module_reference(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_dictionary_access(self, node) -> None:
        self.visit(node.object)

    def visit_comment(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_comment_group(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_defined_expression(self, node) -> None:
        self.visit(node.expression)

    def visit_string_operator_expression(self, node) -> None:
        self.visit(node.left)
        self.visit(node.right)

    # Add missing abstract methods
    def visit_extern_import(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_extern_namespace(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_extern_rule(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_extern_rule_reference(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_in_rule_pragma(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_pragma(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_pragma_block(self, node) -> None:
        pass  # Implementation intentionally empty


@dataclass
class ComplexityReport:
    """Report of complexity analysis for a rule."""

    rule_name: str
    total_complexity: int
    cyclomatic_complexity: int
    cognitive_complexity: int
    string_complexity: int
    condition_complexity: int


class ComplexityCalculator(ASTVisitor[int]):
    """Calculate complexity scores for AST nodes."""

    def __init__(self) -> None:
        self._cognitive_depth = 0
        self._in_logical_op = False

    def calculate(self, node: ASTNode) -> int:
        """Calculate complexity for an AST node."""
        if node is None:
            return 0
        return node.accept(self)

    # Simple expressions - base complexity 1
    def visit_boolean_literal(self, node) -> int:
        return 1

    def visit_integer_literal(self, node) -> int:
        return 1

    def visit_double_literal(self, node) -> int:
        return 1

    def visit_string_literal(self, node) -> int:
        return 1

    def visit_regex_literal(self, node) -> int:
        return 2  # Regex slightly more complex

    def visit_identifier(self, node) -> int:
        return 1

    def visit_string_identifier(self, node) -> int:
        return 1

    # Binary expressions - add complexity for operators
    def visit_binary_expression(self, node: BinaryExpression) -> int:
        complexity = 1  # Base

        # Logical operators add more complexity
        if node.operator in ("and", "or"):
            complexity += 2
            self._in_logical_op = True
        else:
            complexity += 1

        # Add child complexity
        complexity += self.calculate(node.left)
        complexity += self.calculate(node.right)

        self._in_logical_op = False
        return complexity

    # Unary expressions
    def visit_unary_expression(self, node: UnaryExpression) -> int:
        return 2 + self.calculate(node.operand)

    # Function calls
    def visit_function_call(self, node) -> int:
        complexity = 2  # Base function call
        for arg in node.arguments:
            complexity += self.calculate(arg)
        return complexity

    # String operations
    def visit_string_count(self, node) -> int:
        return 2

    def visit_string_offset(self, node) -> int:
        complexity = 2
        if node.index:
            complexity += self.calculate(node.index)
        return complexity

    def visit_string_length(self, node) -> int:
        complexity = 2
        if node.index:
            complexity += self.calculate(node.index)
        return complexity

    # Complex expressions
    def visit_for_expression(self, node: ForExpression) -> int:
        self._cognitive_depth += 1
        complexity = 5  # High base for loops
        complexity += self.calculate(node.iterable)
        complexity += self.calculate(node.body)
        self._cognitive_depth -= 1
        return complexity

    def visit_for_of_expression(self, node: ForOfExpression) -> int:
        self._cognitive_depth += 1
        complexity = 5  # High base for loops
        if hasattr(node.string_set, "accept"):
            complexity += self.calculate(node.string_set)
        else:
            complexity += len(node.string_set) if isinstance(node.string_set, list) else 1
        if node.condition:
            complexity += self.calculate(node.condition)
        self._cognitive_depth -= 1
        return complexity

    def visit_of_expression(self, node: OfExpression) -> int:
        complexity = 4  # Base for of expressions
        if hasattr(node.string_set, "accept"):
            complexity += self.calculate(node.string_set)
        elif isinstance(node.string_set, list):
            complexity += len(node.string_set)
        return complexity

    # Container expressions
    def visit_set_expression(self, node) -> int:
        complexity = 1
        for elem in node.elements:
            complexity += self.calculate(elem)
        return complexity

    def visit_range_expression(self, node) -> int:
        return 1 + self.calculate(node.low) + self.calculate(node.high)

    def visit_array_access(self, node) -> int:
        return 1 + self.calculate(node.array) + self.calculate(node.index)

    def visit_member_access(self, node) -> int:
        return 1 + self.calculate(node.object)

    def visit_parentheses_expression(self, node) -> int:
        return self.calculate(node.expression)

    # Other expressions
    def visit_at_expression(self, node) -> int:
        return 2 + self.calculate(node.offset)

    def visit_in_expression(self, node) -> int:
        return 2 + self.calculate(node.range)

    def visit_defined_expression(self, node) -> int:
        return 1 + self.calculate(node.expression)

    def visit_string_operator_expression(self, node) -> int:
        return 2 + self.calculate(node.left) + self.calculate(node.right)

    def visit_dictionary_access(self, node) -> int:
        complexity = 1 + self.calculate(node.object)
        if hasattr(node.key, "accept"):
            complexity += self.calculate(node.key)
        return complexity

    # Default/unused visitor methods
    def visit_yara_file(self, node) -> int:
        return 0

    def visit_import(self, node) -> int:
        return 0

    def visit_include(self, node) -> int:
        return 0

    def visit_rule(self, node) -> int:
        return 0

    def visit_tag(self, node) -> int:
        return 0

    def visit_string_definition(self, node) -> int:
        return 0

    def visit_plain_string(self, node) -> int:
        return 0

    def visit_hex_string(self, node) -> int:
        return 0

    def visit_regex_string(self, node) -> int:
        return 0

    def visit_string_modifier(self, node) -> int:
        return 0

    def visit_hex_token(self, node) -> int:
        return 0

    def visit_hex_byte(self, node) -> int:
        return 0

    def visit_hex_wildcard(self, node) -> int:
        return 0

    def visit_hex_jump(self, node) -> int:
        return 0

    def visit_hex_alternative(self, node) -> int:
        return 0

    def visit_hex_nibble(self, node) -> int:
        return 0

    def visit_expression(self, node) -> int:
        return 0

    def visit_condition(self, node) -> int:
        return 0

    def visit_meta(self, node) -> int:
        return 0

    def visit_module_reference(self, node) -> int:
        return 0

    def visit_comment(self, node) -> int:
        return 0

    def visit_comment_group(self, node) -> int:
        return 0

    # Add missing abstract methods
    def visit_extern_import(self, node) -> int:
        return 0

    def visit_extern_namespace(self, node) -> int:
        return 0

    def visit_extern_rule(self, node) -> int:
        return 0

    def visit_extern_rule_reference(self, node) -> int:
        return 0

    def visit_in_rule_pragma(self, node) -> int:
        return 0

    def visit_pragma(self, node) -> int:
        return 0

    def visit_pragma_block(self, node) -> int:
        return 0


# Convenience functions
def calculate_rule_complexity(rule: Rule) -> int:
    """Calculate total complexity for a rule."""
    calc = ComplexityCalculator()

    # Base complexity
    complexity = 1

    # Add string complexity
    if rule.strings:
        complexity += len(rule.strings)
        for string in rule.strings:
            if isinstance(string, RegexString):
                complexity += 2
            elif isinstance(string, HexString):
                complexity += 1

    # Add condition complexity
    if rule.condition:
        complexity += calc.calculate(rule.condition)

    # Add modifier complexity
    if "private" in rule.modifiers:
        complexity += 1
    if "global" in rule.modifiers:
        complexity += 1

    return complexity


def calculate_expression_complexity(expr: ASTNode) -> int:
    """Calculate complexity for an expression."""
    calc = ComplexityCalculator()
    return calc.calculate(expr)


def calculate_cyclomatic_complexity(expr: ASTNode) -> int:
    """Calculate cyclomatic complexity (branching)."""
    # Simple approximation based on decision points
    complexity = 1

    if hasattr(expr, "operator") and expr.operator in ("and", "or"):
        complexity += 1

    # Recursively check children
    if hasattr(expr, "left"):
        complexity += calculate_cyclomatic_complexity(expr.left) - 1
    if hasattr(expr, "right"):
        complexity += calculate_cyclomatic_complexity(expr.right) - 1
    if hasattr(expr, "operand"):
        complexity += calculate_cyclomatic_complexity(expr.operand) - 1

    return complexity


def calculate_cognitive_complexity(expr: ASTNode) -> int:
    """Calculate cognitive complexity (mental effort)."""
    calc = ComplexityCalculator()
    base_complexity = calc.calculate(expr)

    # Add extra complexity for nesting
    if isinstance(expr, ForExpression | ForOfExpression):
        return base_complexity + 3

    return base_complexity


def generate_complexity_report(ast: YaraFile) -> dict[str, Any]:
    """Generate a comprehensive complexity report for a YARA file."""
    analyzer = ComplexityAnalyzer()
    metrics = analyzer.analyze(ast)

    rules_data = []
    for rule in ast.rules:
        complexity = calculate_rule_complexity(rule)
        cyclomatic = metrics.cyclomatic_complexity.get(rule.name, 1)
        cognitive = calculate_cognitive_complexity(rule.condition) if rule.condition else 0

        rules_data.append(
            {
                "name": rule.name,
                "total_complexity": complexity,
                "cyclomatic_complexity": cyclomatic,
                "cognitive_complexity": cognitive,
                "strings": len(rule.strings) if rule.strings else 0,
                "modifiers": len(rule.modifiers),
            },
        )

    return {
        "rules": rules_data,
        "summary": {
            "total_rules": len(ast.rules),
            "avg_complexity": sum(r["total_complexity"] for r in rules_data)
            / max(1, len(rules_data)),
            "max_complexity": max(
                (r["total_complexity"] for r in rules_data),
                default=0,
            ),
            "quality_score": metrics.get_quality_score(),
            "quality_grade": metrics.get_complexity_grade(),
        },
        "metrics": metrics.to_dict(),
    }


def analyze_file_complexity(file_path: str | Path) -> dict[str, Any]:
    """Analyze complexity of a YARA file."""
    parser = Parser()

    with open(file_path) as f:
        content = f.read()

    ast = parser.parse(content)
    report = generate_complexity_report(ast)

    return {
        "file": str(file_path),
        "complexity": report,
    }
