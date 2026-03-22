"""YARA condition evaluator."""

from __future__ import annotations

import contextlib
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from yaraast.ast.conditions import *
from yaraast.ast.expressions import *
from yaraast.evaluation.evaluation_helpers import BUILTIN_READERS, LITTLE_ENDIAN_ALIASES
from yaraast.evaluation.evaluator_ops import (
    evaluate_arithmetic,
    evaluate_comparison,
    evaluate_string_operator,
)
from yaraast.evaluation.mock_modules import MockModuleRegistry
from yaraast.evaluation.string_matcher import StringMatcher
from yaraast.visitor.defaults import DefaultASTVisitor

if TYPE_CHECKING:
    from yaraast.ast.base import YaraFile
    from yaraast.ast.rules import Rule


@dataclass
class EvaluationContext:
    """Context for evaluating YARA conditions."""

    data: bytes
    filesize: int = field(init=False)
    entrypoint: int = 0
    string_matches: dict[str, list] = field(default_factory=dict)
    modules: dict[str, Any] = field(default_factory=dict)
    variables: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        self.filesize = len(self.data)


class YaraEvaluator(DefaultASTVisitor[Any]):
    """Evaluate YARA conditions against byte data."""

    _builtin_readers = BUILTIN_READERS
    _little_endian_aliases = LITTLE_ENDIAN_ALIASES

    def __init__(self, data: bytes = b"", modules: MockModuleRegistry | None = None) -> None:
        super().__init__(default=None)
        self.data = data
        self.context = EvaluationContext(data=data)
        self.string_matcher = StringMatcher()
        self.module_registry = modules or MockModuleRegistry()
        self._current_rule: Rule | None = None

    def evaluate_file(self, yara_file: YaraFile) -> dict[str, bool]:
        """Evaluate all rules in a YARA file."""
        results = {}
        self._rule_results = {}  # Track evaluated rule results for cross-references

        # Process imports
        for import_stmt in yara_file.imports:
            module_name = import_stmt.module
            module = self.module_registry.create_module(module_name, self.data)
            if module:
                # Handle aliases
                if import_stmt.alias:
                    self.context.modules[import_stmt.alias] = module
                else:
                    self.context.modules[module_name] = module

        # Evaluate each rule
        for rule in yara_file.rules:
            result = self.evaluate_rule(rule)
            results[rule.name] = result
            self._rule_results[rule.name] = result

        return results

    def evaluate_rule(self, rule: Rule) -> bool:
        """Evaluate a single rule."""
        self._current_rule = rule

        # Reset per-rule state to prevent cross-rule contamination
        self.context.string_matches = {}

        # Match strings
        if rule.strings:
            matches = self.string_matcher.match_all(self.data, rule.strings)
            self.context.string_matches = matches

        # Evaluate condition
        if rule.condition:
            return self.visit(rule.condition)

        return True  # No condition means always match

    # Expression evaluation

    def visit_boolean_literal(self, node: BooleanLiteral) -> bool:
        return node.value

    def visit_integer_literal(self, node: IntegerLiteral) -> int:
        return int(node.value)

    def visit_double_literal(self, node: DoubleLiteral) -> float:
        return node.value

    def visit_string_literal(self, node: StringLiteral) -> str:
        return node.value

    def visit_identifier(self, node: Identifier) -> Any:
        # Check for built-in identifiers
        if node.name == "filesize":
            return self.context.filesize
        if node.name == "entrypoint":
            return self.context.entrypoint
        if node.name == "all":
            return "all"
        if node.name == "any":
            return "any"
        if node.name == "them":
            return list(self.context.string_matches.keys())

        # Check variables
        if node.name in self.context.variables:
            return self.context.variables[node.name]

        # Check modules
        if node.name in self.context.modules:
            return self.context.modules[node.name]

        # Check rule references (condition: other_rule)
        if hasattr(self, "_rule_results") and node.name in self._rule_results:
            return self._rule_results[node.name]

        # Unknown identifier evaluates to false (graceful handling)
        return False

    def visit_string_identifier(self, node: StringIdentifier) -> bool:
        """String identifier evaluates to whether it matched."""
        return (
            node.name in self.context.string_matches
            and len(self.context.string_matches[node.name]) > 0
        )

    def visit_string_wildcard(self, node) -> bool:
        """String wildcard ($*) evaluates to whether any strings matched."""
        return len(self.context.string_matches) > 0 and any(
            len(matches) > 0 for matches in self.context.string_matches.values()
        )

    def visit_string_count(self, node: StringCount) -> int:
        """Get count of string matches."""
        string_id = f"${node.string_id}" if not node.string_id.startswith("$") else node.string_id
        return self.string_matcher.get_match_count(string_id)

    def visit_string_offset(self, node: StringOffset) -> int:
        """Get offset of string match."""
        string_id = f"${node.string_id}" if not node.string_id.startswith("$") else node.string_id
        index = self.visit(node.index) if node.index else 0
        offset = self.string_matcher.get_match_offset(string_id, index)
        return offset if offset is not None else -1

    def visit_string_length(self, node: StringLength) -> int:
        """Get length of string match."""
        string_id = f"${node.string_id}" if not node.string_id.startswith("$") else node.string_id
        index = self.visit(node.index) if node.index else 0
        length = self.string_matcher.get_match_length(string_id, index)
        return length if length is not None else 0

    def visit_binary_expression(self, node: BinaryExpression) -> Any:
        """Evaluate binary expression."""
        left = self.visit(node.left)

        # Short-circuit evaluation for boolean operators
        if node.operator == "and":
            if not left:
                return False
            return self.visit(node.right)
        if node.operator == "or":
            if left:
                return True
            return self.visit(node.right)

        right = self.visit(node.right)

        result = evaluate_arithmetic(left, right, node.operator)
        if result is not None:
            return result

        result = evaluate_comparison(left, right, node.operator)
        if result is not None:
            return result

        result = evaluate_string_operator(left, right, node.operator)
        if result is not None:
            return result

        msg = f"Unknown operator: {node.operator}"
        raise ValueError(msg)

    def visit_unary_expression(self, node: UnaryExpression) -> Any:
        """Evaluate unary expression."""
        operand = self.visit(node.operand)

        if node.operator == "not":
            return not operand
        if node.operator == "-":
            return -operand
        if node.operator == "~":
            return ~operand
        msg = f"Unknown unary operator: {node.operator}"
        raise ValueError(msg)

    def visit_parentheses_expression(self, node: ParenthesesExpression) -> Any:
        """Evaluate parentheses expression."""
        return self.visit(node.expression)

    def visit_set_expression(self, node: SetExpression) -> set:
        """Evaluate set expression."""
        return {self.visit(elem) for elem in node.elements}

    def visit_range_expression(self, node: RangeExpression) -> range:
        """Evaluate range expression."""
        low = self.visit(node.low)
        high = self.visit(node.high)
        return range(low, high + 1)  # Inclusive range

    def visit_function_call(self, node: FunctionCall) -> Any:
        """Evaluate function call."""
        # Evaluate arguments
        args = [self.visit(arg) for arg in node.arguments]

        function = self._little_endian_aliases.get(node.function, node.function)
        reader = self._builtin_readers.get(function)
        if reader:
            return reader(self.data, args[0]) if args else 0

        # Module functions
        if "." in node.function:
            module_name, func_name = node.function.split(".", 1)
            if module_name in self.context.modules:
                module = self.context.modules[module_name]
                # Use class method to avoid attribute shadowing (e.g., pe.imports list vs imports() method)
                class_method = getattr(type(module), func_name, None)
                if class_method is not None and callable(class_method):
                    return class_method(module, *args)
                if hasattr(module, func_name):
                    func = getattr(module, func_name)
                    if callable(func):
                        return func(*args)
                    return func  # Attribute access, not function call

        msg = f"Unknown function: {node.function}"
        raise ValueError(msg)

    def visit_member_access(self, node: MemberAccess) -> Any:
        """Evaluate member access."""
        obj = self.visit(node.object)

        if obj is None:
            return None

        if hasattr(obj, node.member):
            return getattr(obj, node.member)
        if hasattr(obj, "__getitem__"):
            with contextlib.suppress(Exception):
                return obj[node.member]

        return None

    def visit_array_access(self, node: ArrayAccess) -> Any:
        """Evaluate array access."""
        array = self.visit(node.array)
        index = self.visit(node.index)

        try:
            return array[index]
        except (IndexError, KeyError, ValueError, TypeError, AttributeError):
            return None

    # Condition evaluation

    def visit_at_expression(self, node: AtExpression) -> bool:
        """Evaluate 'at' expression."""
        offset = self.visit(node.offset)
        return self.string_matcher.string_at(node.string_id, offset)

    def visit_in_expression(self, node: InExpression) -> bool:
        """Evaluate 'in' expression."""
        range_val = self.visit(node.range)
        if not isinstance(range_val, range):
            return False
        if isinstance(node.subject, str):
            return self.string_matcher.string_in(
                node.string_id,
                range_val.start,
                range_val.stop,
            )
        # OfExpression subject: evaluate the of-expression restricted to the range
        subject_result = self.visit(node.subject)
        return bool(subject_result)

    def visit_of_expression(self, node: OfExpression) -> bool:
        """Evaluate 'of' expression."""
        # Get quantifier value - could be int, string ("all", "any"), or expression
        quantifier = self._resolve_quantifier(node.quantifier)

        string_set = self._resolve_string_set(node.string_set)

        # Count matches
        matched = 0
        for string_id in string_set:
            if self.string_matcher.get_match_count(string_id) > 0:
                matched += 1

        # Evaluate quantifier
        if isinstance(quantifier, str):
            if quantifier == "all":
                return matched == len(string_set)
            if quantifier == "any":
                return matched > 0
            if quantifier == "none":
                return matched == 0
        elif isinstance(quantifier, int):
            return matched >= quantifier

        return False

    def visit_for_expression(self, node: ForExpression) -> bool:
        """Evaluate 'for' expression."""
        # Get quantifier value - could be int, string ("all", "any"), or expression
        quantifier = self._resolve_quantifier(node.quantifier)

        iterable = self.visit(node.iterable)

        # Count true evaluations
        true_count = 0
        for item in iterable:
            # Set loop variable
            old_value = self.context.variables.get(node.variable)
            self.context.variables[node.variable] = item

            try:
                if self.visit(node.body):
                    true_count += 1
            finally:
                # Restore variable
                if old_value is not None:
                    self.context.variables[node.variable] = old_value
                else:
                    self.context.variables.pop(node.variable, None)

        # Evaluate quantifier
        if isinstance(quantifier, str):
            if quantifier == "all":
                return true_count == len(iterable)
            if quantifier == "any":
                return true_count > 0
            if quantifier == "none":
                return true_count == 0
        elif isinstance(quantifier, int):
            return true_count >= quantifier

        return False

    # Helper methods for reading data

    def _resolve_quantifier(self, quantifier: Any) -> int | str:
        if isinstance(quantifier, int | str):
            return quantifier
        return self.visit(quantifier)

    def _resolve_string_set(self, string_set_node: Any) -> list[str]:
        """Resolve a string set to a list of string identifiers for 'of'/'for...of' evaluation."""
        from yaraast.ast.expressions import SetExpression, StringIdentifier, StringWildcard

        # "them" keyword → all matched strings
        if hasattr(string_set_node, "name") and string_set_node.name == "them":
            return list(self.context.string_matches.keys())

        # SetExpression → expand wildcards and collect identifiers
        if isinstance(string_set_node, SetExpression):
            result = []
            for elem in string_set_node.elements:
                if isinstance(elem, StringWildcard):
                    pattern = elem.pattern
                    prefix = pattern.rstrip("*")
                    result.extend(
                        sid for sid in self.context.string_matches if sid.startswith(prefix)
                    )
                elif isinstance(elem, StringIdentifier):
                    result.append(elem.name)
                else:
                    result.append(str(self.visit(elem)))
            return result

        # Try visiting the node and handling the result
        visited = self.visit(string_set_node)
        if isinstance(visited, str) and visited == "them":
            return list(self.context.string_matches.keys())
        if isinstance(visited, list | set | tuple):
            return list(visited)

        # Fallback: all defined strings
        return list(self.context.string_matches.keys())

    # Base expression visitor (dispatch to specific expression types)
    def visit_expression(self, node: Expression) -> Any:
        """Visit generic expression node."""
        # This will dispatch to the specific expression type visitor
        return self.visit(node)

    def visit_module_reference(self, node) -> Any:
        """Visit module reference and return the module object."""
        from yaraast.ast.modules import ModuleReference

        if isinstance(node, ModuleReference):
            if node.module in self.context.modules:
                return self.context.modules[node.module]
            msg = f"Unknown module: {node.module}"
            raise ValueError(msg)
        return None

    def visit_for_of_expression(self, node) -> bool:
        """Evaluate 'for ... of' expression (ForOfExpression: quantifier, string_set, condition)."""
        quantifier = self._resolve_quantifier(node.quantifier)
        string_set = self._resolve_string_set(node.string_set)

        # Count how many strings match
        matches = 0
        for string_id in string_set:
            if node.condition is not None:
                # Set up implicit $ variable for the condition body
                old_value = self.context.variables.get("$")
                self.context.variables["$"] = string_id
                try:
                    if self.visit(node.condition):
                        matches += 1
                finally:
                    if old_value is not None:
                        self.context.variables["$"] = old_value
                    else:
                        self.context.variables.pop("$", None)
            else:
                # No condition — just check if the string matched
                if self.string_matcher.get_match_count(string_id) > 0:
                    matches += 1

        # Evaluate quantifier
        if isinstance(quantifier, str):
            if quantifier == "all":
                return matches == len(string_set)
            if quantifier == "any":
                return matches > 0
            if quantifier == "none":
                return matches == 0
        elif isinstance(quantifier, int):
            return matches >= quantifier
        elif isinstance(quantifier, float):
            # Percentage (e.g., 50% of them)
            required = int(len(string_set) * quantifier)
            return matches >= required

        return False

    def visit_regex_literal(self, node) -> str:
        """Return regex pattern string."""
        # For regex literals, we'll return the pattern
        # The actual matching is handled by the binary expression "matches" operator
        return node.pattern

    def visit_defined_expression(self, node) -> bool:
        """Evaluate 'defined' expression."""
        # Get the expression being checked
        expr = node.expression

        if isinstance(expr, Identifier):
            # Check if it's a module
            if expr.name in self.context.modules:
                return True
            # Check if it's a variable
            if expr.name in self.context.variables:
                return True
        elif (
            isinstance(expr, StringIdentifier) and self._current_rule and self._current_rule.strings
        ):
            # Check if string is defined in current rule
            for string_def in self._current_rule.strings:
                if string_def.identifier == expr.name:
                    return True

        return False

    def visit_string_operator_expression(self, node) -> Any:
        """Evaluate string-specific operators like contains, startswith, etc."""
        # This is handled in binary_expression for string operators
        # But we can add specific handling here if needed
        return self.visit_binary_expression(node)
