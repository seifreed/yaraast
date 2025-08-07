"""YARA condition evaluator."""

from __future__ import annotations

import contextlib
import struct
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from yaraast.ast.conditions import *
from yaraast.ast.expressions import *
from yaraast.evaluation.mock_modules import MockModuleRegistry
from yaraast.evaluation.string_matcher import StringMatcher
from yaraast.visitor import ASTVisitor

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


class YaraEvaluator(ASTVisitor[Any]):
    """Evaluate YARA conditions against byte data."""

    def __init__(self, data: bytes = b"", modules: MockModuleRegistry | None = None) -> None:
        self.data = data
        self.context = EvaluationContext(data=data)
        self.string_matcher = StringMatcher()
        self.module_registry = modules or MockModuleRegistry()
        self._current_rule: Rule | None = None

    def evaluate_file(self, yara_file: YaraFile) -> dict[str, bool]:
        """Evaluate all rules in a YARA file."""
        results = {}

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
            results[rule.name] = self.evaluate_rule(rule)

        return results

    def evaluate_rule(self, rule: Rule) -> bool:
        """Evaluate a single rule."""
        self._current_rule = rule

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

        msg = f"Unknown identifier: {node.name}"
        raise ValueError(msg)

    def visit_string_identifier(self, node: StringIdentifier) -> bool:
        """String identifier evaluates to whether it matched."""
        return (
            node.name in self.context.string_matches
            and len(self.context.string_matches[node.name]) > 0
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

        # Arithmetic operators
        if node.operator == "+":
            return left + right
        if node.operator == "-":
            return left - right
        if node.operator == "*":
            return left * right
        if node.operator == "/":
            return left // right if isinstance(left, int) else left / right
        if node.operator == "%":
            return left % right
        if node.operator == "<<":
            return left << right
        if node.operator == ">>":
            return left >> right
        if node.operator == "&":
            return left & right
        if node.operator == "|":
            return left | right
        if node.operator == "^":
            return left ^ right

        # Comparison operators
        if node.operator == "==":
            return left == right
        if node.operator == "!=":
            return left != right
        if node.operator == "<":
            return left < right
        if node.operator == "<=":
            return left <= right
        if node.operator == ">":
            return left > right
        if node.operator == ">=":
            return left >= right

        # String operators
        if node.operator == "contains":
            return right in left
        if node.operator == "icontains":
            return right.lower() in left.lower()
        if node.operator == "startswith":
            return left.startswith(right)
        if node.operator == "istartswith":
            return left.lower().startswith(right.lower())
        if node.operator == "endswith":
            return left.endswith(right)
        if node.operator == "iendswith":
            return left.lower().endswith(right.lower())
        if node.operator == "iequals":
            return left.lower() == right.lower()
        if node.operator == "matches":
            # Simplified regex matching
            import re

            try:
                return bool(re.search(right, left))
            except (ValueError, TypeError, AttributeError):
                return False

        else:
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

        # Built-in functions
        if node.function == "uint8":
            return self._read_uint8(args[0]) if args else 0
        if node.function == "uint16":
            return self._read_uint16(args[0]) if args else 0
        if node.function == "uint32":
            return self._read_uint32(args[0]) if args else 0
        if node.function == "int8":
            return self._read_int8(args[0]) if args else 0
        if node.function == "int16":
            return self._read_int16(args[0]) if args else 0
        if node.function == "int32":
            return self._read_int32(args[0]) if args else 0

        # Big-endian variants
        if node.function == "uint16be":
            return self._read_uint16_be(args[0]) if args else 0
        if node.function == "uint32be":
            return self._read_uint32_be(args[0]) if args else 0
        if node.function == "int16be":
            return self._read_int16_be(args[0]) if args else 0
        if node.function == "int32be":
            return self._read_int32_be(args[0]) if args else 0

        # Little-endian variants (same as normal for x86)
        if node.function in ["uint16le", "uint32le", "int16le", "int32le"]:
            base_func = node.function[:-2]  # Remove 'le'
            return self.visit_function_call(
                FunctionCall(function=base_func, arguments=node.arguments),
            )

        # Module functions
        if "." in node.function:
            module_name, func_name = node.function.split(".", 1)
            if module_name in self.context.modules:
                module = self.context.modules[module_name]
                if hasattr(module, func_name):
                    func = getattr(module, func_name)
                    return func(*args)

        msg = f"Unknown function: {node.function}"
        raise ValueError(msg)

    def visit_member_access(self, node: MemberAccess) -> Any:
        """Evaluate member access."""
        obj = self.visit(node.object)

        if hasattr(obj, node.member):
            return getattr(obj, node.member)
        if hasattr(obj, "__getitem__"):
            with contextlib.suppress(Exception):
                return obj[node.member]

        msg = f"Cannot access member {node.member}"
        raise ValueError(msg)

    def visit_array_access(self, node: ArrayAccess) -> Any:
        """Evaluate array access."""
        array = self.visit(node.array)
        index = self.visit(node.index)

        try:
            return array[index]
        except (ValueError, TypeError, AttributeError):
            return None

    # Condition evaluation

    def visit_at_expression(self, node: AtExpression) -> bool:
        """Evaluate 'at' expression."""
        offset = self.visit(node.offset)
        return self.string_matcher.string_at(node.string_id, offset)

    def visit_in_expression(self, node: InExpression) -> bool:
        """Evaluate 'in' expression."""
        range_val = self.visit(node.range)
        if isinstance(range_val, range):
            return self.string_matcher.string_in(
                node.string_id,
                range_val.start,
                range_val.stop,
            )
        return False

    def visit_of_expression(self, node: OfExpression) -> bool:
        """Evaluate 'of' expression."""
        # Get quantifier value - could be int, string ("all", "any"), or expression
        if isinstance(node.quantifier, int | str):
            quantifier = node.quantifier
        else:
            quantifier = self.visit(node.quantifier)

        string_set = self.visit(node.string_set)

        if isinstance(string_set, str) and string_set == "them":
            string_set = list(self.context.string_matches.keys())

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
        if isinstance(node.quantifier, int | str):
            quantifier = node.quantifier
        else:
            quantifier = self.visit(node.quantifier)

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

    def _read_uint8(self, offset: int) -> int:
        if 0 <= offset < len(self.data):
            return self.data[offset]
        return 0

    def _read_uint16(self, offset: int) -> int:
        if 0 <= offset <= len(self.data) - 2:
            return struct.unpack("<H", self.data[offset : offset + 2])[0]
        return 0

    def _read_uint32(self, offset: int) -> int:
        if 0 <= offset <= len(self.data) - 4:
            return struct.unpack("<I", self.data[offset : offset + 4])[0]
        return 0

    def _read_int8(self, offset: int) -> int:
        if 0 <= offset < len(self.data):
            return struct.unpack("b", bytes([self.data[offset]]))[0]
        return 0

    def _read_int16(self, offset: int) -> int:
        if 0 <= offset <= len(self.data) - 2:
            return struct.unpack("<h", self.data[offset : offset + 2])[0]
        return 0

    def _read_int32(self, offset: int) -> int:
        if 0 <= offset <= len(self.data) - 4:
            return struct.unpack("<i", self.data[offset : offset + 4])[0]
        return 0

    def _read_uint16_be(self, offset: int) -> int:
        if 0 <= offset <= len(self.data) - 2:
            return struct.unpack(">H", self.data[offset : offset + 2])[0]
        return 0

    def _read_uint32_be(self, offset: int) -> int:
        if 0 <= offset <= len(self.data) - 4:
            return struct.unpack(">I", self.data[offset : offset + 4])[0]
        return 0

    def _read_int16_be(self, offset: int) -> int:
        if 0 <= offset <= len(self.data) - 2:
            return struct.unpack(">h", self.data[offset : offset + 2])[0]
        return 0

    def _read_int32_be(self, offset: int) -> int:
        if 0 <= offset <= len(self.data) - 4:
            return struct.unpack(">i", self.data[offset : offset + 4])[0]
        return 0

    # Base expression visitor (dispatch to specific expression types)
    def visit_expression(self, node: Expression) -> Any:
        """Visit generic expression node."""
        # This will dispatch to the specific expression type visitor
        return self.visit(node)

    # Visit method stubs for completeness
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

    def visit_meta(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_module_reference(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_dictionary_access(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_condition(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_for_of_expression(self, node) -> bool:
        """Evaluate 'for ... of' expression."""
        # This is similar to for_expression but specifically for strings
        quantifier = self.visit(node.quantifier)
        string_set = self.visit(node.string_set)

        if isinstance(string_set, str) and string_set == "them":
            string_set = list(self.context.string_matches.keys())

        # Count how many strings match the condition
        matches = 0
        for string_id in string_set:
            # Set up context for string iteration
            old_value = self.context.variables.get(node.variable)
            self.context.variables[node.variable] = string_id

            try:
                if self.visit(node.body):
                    matches += 1
            finally:
                # Restore variable
                if old_value is not None:
                    self.context.variables[node.variable] = old_value
                else:
                    self.context.variables.pop(node.variable, None)

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

    def visit_hex_nibble(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_comment(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_comment_group(self, node) -> None:
        pass  # Implementation intentionally empty

    def visit_string_operator_expression(self, node) -> Any:
        """Evaluate string-specific operators like contains, startswith, etc."""
        # This is handled in binary_expression for string operators
        # But we can add specific handling here if needed
        return self.visit_binary_expression(node)

    def visit_extern_import(self, node) -> None:
        """Visit extern import - not evaluated."""
        # Implementation intentionally empty

    def visit_extern_namespace(self, node) -> None:
        """Visit extern namespace - not evaluated."""
        # Implementation intentionally empty

    def visit_extern_rule(self, node) -> None:
        """Visit extern rule - not evaluated."""
        # Implementation intentionally empty

    def visit_extern_rule_reference(self, node) -> None:
        """Visit extern rule reference - not evaluated."""
        # Implementation intentionally empty

    def visit_in_rule_pragma(self, node) -> None:
        """Visit in-rule pragma - not evaluated."""
        # Implementation intentionally empty

    def visit_pragma(self, node) -> None:
        """Visit pragma - not evaluated."""
        # Implementation intentionally empty

    def visit_pragma_block(self, node) -> None:
        """Visit pragma block - not evaluated."""
        # Implementation intentionally empty


# Alias for compatibility
Evaluator = YaraEvaluator
