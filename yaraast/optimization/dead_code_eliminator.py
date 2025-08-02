"""Dead code eliminator for YARA rules."""

from __future__ import annotations

from yaraast.analysis.string_usage import StringUsageAnalyzer
from yaraast.ast.base import *
from yaraast.ast.conditions import *
from yaraast.ast.expressions import *
from yaraast.ast.rules import *
from yaraast.ast.strings import *
from yaraast.visitor import ASTTransformer


class DeadCodeEliminator(ASTTransformer):
    """Eliminate dead code from YARA rules."""

    def __init__(self):
        self.eliminations_count = 0
        self.string_usage_analyzer = StringUsageAnalyzer()
        self.used_strings: set[str] = set()
        self.always_false_rules: set[str] = set()

    def eliminate(self, yara_file: YaraFile) -> tuple[YaraFile, int]:
        """Eliminate dead code and return optimized file with elimination count."""
        self.eliminations_count = 0

        # First pass: analyze string usage
        self.string_usage_analyzer.analyze(yara_file)

        # Second pass: check for always-false conditions
        self._identify_always_false_rules(yara_file)

        # Transform the AST
        optimized = self.visit(yara_file)

        return optimized, self.eliminations_count

    def _identify_always_false_rules(self, yara_file: YaraFile) -> None:
        """Identify rules with always-false conditions."""
        for rule in yara_file.rules:
            if self._is_always_false(rule.condition):
                self.always_false_rules.add(rule.name)

    def _is_always_false(self, expr: Expression) -> bool:
        """Check if expression is always false."""
        if isinstance(expr, BooleanLiteral):
            return not expr.value

        if isinstance(expr, BinaryExpression):
            if expr.operator == "and":
                # If either side is always false, the whole expression is false
                return self._is_always_false(expr.left) or self._is_always_false(expr.right)
            if expr.operator == "or":
                # Both sides must be false for OR to be false
                return self._is_always_false(expr.left) and self._is_always_false(expr.right)

        if isinstance(expr, UnaryExpression) and expr.operator == "not":
            return self._is_always_true(expr.operand)

        return False

    def _is_always_true(self, expr: Expression) -> bool:
        """Check if expression is always true."""
        if isinstance(expr, BooleanLiteral):
            return expr.value

        if isinstance(expr, BinaryExpression):
            if expr.operator == "or":
                # If either side is always true, the whole expression is true
                return self._is_always_true(expr.left) or self._is_always_true(expr.right)
            if expr.operator == "and":
                # Both sides must be true for AND to be true
                return self._is_always_true(expr.left) and self._is_always_true(expr.right)

        if isinstance(expr, UnaryExpression) and expr.operator == "not":
            return self._is_always_false(expr.operand)

        return False

    def visit_yara_file(self, node: YaraFile) -> YaraFile:
        """Remove rules with always-false conditions."""
        imports = [self.visit(imp) for imp in node.imports]
        includes = [self.visit(inc) for inc in node.includes]

        # Filter out rules with always-false conditions
        rules = []
        for rule in node.rules:
            if rule.name in self.always_false_rules:
                self.eliminations_count += 1
                # Skip this rule
                continue

            # Process the rule
            optimized_rule = self.visit(rule)
            rules.append(optimized_rule)

        return YaraFile(imports=imports, includes=includes, rules=rules)

    def visit_rule(self, node: Rule) -> Rule:
        """Remove unused strings from rule."""
        # Analyze string usage in this rule
        self.used_strings.clear()
        self._collect_used_strings(node.condition)

        # Filter out unused strings
        used_string_defs = []
        for string_def in node.strings:
            if string_def.identifier in self.used_strings:
                used_string_defs.append(string_def)
            else:
                self.eliminations_count += 1

        # Remove empty meta entries
        meta = []
        for m in node.meta:
            if m.value is not None and m.value != "":
                meta.append(m)
            else:
                self.eliminations_count += 1

        return Rule(
            name=node.name,
            modifiers=node.modifiers,
            tags=node.tags,
            meta=meta,
            strings=used_string_defs,
            condition=self.visit(node.condition),
        )

    def _collect_used_strings(self, expr: Expression) -> None:
        """Collect all string identifiers used in expression."""
        if isinstance(expr, StringIdentifier):
            self.used_strings.add(expr.name)
        elif isinstance(expr, StringCount | StringOffset | StringLength):
            self.used_strings.add(expr.string_id)
        elif isinstance(expr, AtExpression | InExpression):
            self.used_strings.add(expr.string_id)
            self._collect_used_strings(expr.offset if hasattr(expr, "offset") else expr.range)
        elif isinstance(expr, BinaryExpression):
            self._collect_used_strings(expr.left)
            self._collect_used_strings(expr.right)
        elif isinstance(expr, UnaryExpression):
            self._collect_used_strings(expr.operand)
        elif isinstance(expr, ParenthesesExpression):
            self._collect_used_strings(expr.expression)
        elif isinstance(expr, ForExpression):
            self._collect_used_strings(expr.iterable)
            self._collect_used_strings(expr.body)
        elif isinstance(expr, ForOfExpression):
            self._collect_used_strings(expr.string_set)
            if expr.condition:
                self._collect_used_strings(expr.condition)
        elif isinstance(expr, OfExpression):
            self._collect_used_strings(expr.string_set)
            self._collect_used_strings(expr.quantifier)
        elif isinstance(expr, SetExpression):
            for elem in expr.elements:
                self._collect_used_strings(elem)
        elif isinstance(expr, Identifier) and expr.name == "them":
            # "them" refers to all strings
            for string_def in self.current_rule_strings:
                self.used_strings.add(string_def.identifier)

    def visit_binary_expression(self, node: BinaryExpression) -> Expression:
        """Remove dead branches in binary expressions."""
        left = self.visit(node.left)
        right = self.visit(node.right)

        # Remove dead branches
        if node.operator == "and":
            if isinstance(left, BooleanLiteral) and not left.value:
                self.eliminations_count += 1
                return BooleanLiteral(value=False)
            if isinstance(right, BooleanLiteral) and not right.value:
                self.eliminations_count += 1
                return BooleanLiteral(value=False)

        elif node.operator == "or":
            if isinstance(left, BooleanLiteral) and left.value:
                self.eliminations_count += 1
                return BooleanLiteral(value=True)
            if isinstance(right, BooleanLiteral) and right.value:
                self.eliminations_count += 1
                return BooleanLiteral(value=True)

        if left is not node.left or right is not node.right:
            return BinaryExpression(left=left, operator=node.operator, right=right)

        return node
