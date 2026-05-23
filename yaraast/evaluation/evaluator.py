"""YARA condition evaluator."""

from __future__ import annotations

import contextlib
from dataclasses import dataclass, field
import math
from typing import TYPE_CHECKING, Any

from yaraast.ast.conditions import *
from yaraast.ast.expressions import *
from yaraast.errors import EvaluationError
from yaraast.evaluation.evaluation_helpers import (
    BUILTIN_READERS,
    LITTLE_ENDIAN_ALIASES,
    YARA_UNDEFINED,
    is_yara_undefined,
)
from yaraast.evaluation.evaluator_ops import (
    evaluate_arithmetic,
    evaluate_comparison,
    evaluate_regex_match,
    evaluate_string_operator,
)
from yaraast.evaluation.mock_modules import MockModuleRegistry
from yaraast.evaluation.string_matcher import StringMatcher
from yaraast.shared.integer_semantics import normalize_int64
from yaraast.visitor.defaults import DefaultASTVisitor

if TYPE_CHECKING:
    from yaraast.ast.base import YaraFile
    from yaraast.ast.rules import Rule


def _is_evaluation_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_evaluation_truthy(value: Any) -> bool:
    if is_yara_undefined(value):
        return False
    if isinstance(value, float):
        return value != 0.0 or math.copysign(1.0, value) < 0.0
    return bool(value)


@dataclass
class EvaluationContext:
    """Context for evaluating YARA conditions."""

    data: bytes
    filesize: int = field(init=False)
    entrypoint: int = 0
    string_matches: dict[str, list] = field(default_factory=dict)
    modules: dict[str, object] = field(default_factory=dict)
    variables: dict[str, object] = field(default_factory=dict)

    def __post_init__(self):
        self.filesize = len(self.data)


class YaraEvaluator(DefaultASTVisitor[Any]):
    """Evaluate YARA conditions against byte data."""

    _builtin_readers = BUILTIN_READERS
    _little_endian_aliases = LITTLE_ENDIAN_ALIASES
    _missing_loop_value = object()

    def __init__(
        self,
        data: bytes = b"",
        modules: MockModuleRegistry | None = None,
        string_matcher: StringMatcher | None = None,
    ) -> None:
        super().__init__(default=None)
        self.data = data
        self.context = EvaluationContext(data=data)
        self.string_matcher = string_matcher or StringMatcher()
        self.module_registry = modules or MockModuleRegistry()
        self._current_rule: Rule | None = None

    def evaluate_file(self, yara_file: YaraFile) -> dict[str, bool]:
        """Evaluate all rules in a YARA file."""
        results = {}
        self._rule_results = {}  # Track evaluated rule results for cross-references
        self._rule_map = {rule.name: rule for rule in yara_file.rules}
        self._evaluating_rules = set()
        self.context.modules = {}

        # Process imports
        for import_stmt in yara_file.imports:
            module_name = import_stmt.module
            module = self.module_registry.create_module(module_name, self.data)
            if module:
                self.context.modules[module_name] = module
                if import_stmt.alias:
                    self.context.modules[import_stmt.alias] = module

        # Evaluate each rule
        for rule in yara_file.rules:
            result = self._evaluate_rule_by_name(rule.name)
            results[rule.name] = result

        return results

    def _evaluate_rule_by_name(self, rule_name: str) -> bool:
        if rule_name in self._rule_results:
            return bool(self._rule_results[rule_name])
        if rule_name in self._evaluating_rules:
            return False

        rule = self._rule_map.get(rule_name)
        if rule is None:
            return False

        saved_rule = self._current_rule
        saved_context_matches = {
            string_id: list(matches) for string_id, matches in self.context.string_matches.items()
        }
        saved_matcher_matches = {
            string_id: list(matches) for string_id, matches in self.string_matcher.matches.items()
        }

        self._evaluating_rules.add(rule_name)
        try:
            result = self.evaluate_rule(rule)
            self._rule_results[rule_name] = result
            return result
        finally:
            self._evaluating_rules.discard(rule_name)
            self._current_rule = saved_rule
            self.context.string_matches = saved_context_matches
            self.string_matcher.matches = saved_matcher_matches

    def evaluate_rule(self, rule: Rule) -> bool:
        """Evaluate a single rule."""
        self._current_rule = rule

        # Reset per-rule state to prevent cross-rule contamination
        self.context.string_matches = {}
        self.string_matcher.matches.clear()

        # Match strings
        if rule.strings:
            matches = self.string_matcher.match_all(self.data, rule.strings)
            self.context.string_matches = matches

        # Evaluate condition
        if rule.condition:
            result = self.visit(rule.condition)
            return _is_evaluation_truthy(result)

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
        if hasattr(self, "_rule_map") and node.name in self._rule_map:
            return self._evaluate_rule_by_name(node.name)

        # Unknown identifier evaluates to false (graceful handling)
        return False

    def visit_string_identifier(self, node: StringIdentifier) -> Any:
        """String identifier evaluates to whether it matched."""
        local_value = self._lookup_explicit_string_variable(node.name)
        if local_value is not self._missing_loop_value:
            return local_value

        string_id = self._normalize_string_id(node.name)
        return (
            string_id in self.context.string_matches
            and len(self.context.string_matches[string_id]) > 0
        )

    def _lookup_explicit_string_variable(self, name: str) -> Any:
        if name == "$":
            return self._missing_loop_value
        return self.context.variables.get(name, self._missing_loop_value)

    def visit_string_wildcard(self, node) -> bool:
        """String wildcard ($*) evaluates to whether any strings matched."""
        return any(
            self.string_matcher.get_match_count(string_id) > 0
            for string_id in self._resolve_string_set(node.pattern)
        )

    def visit_string_count(self, node: StringCount) -> Any:
        """Get count of string matches."""
        local_value = self._lookup_explicit_string_variable(node.string_id)
        if local_value is not self._missing_loop_value:
            return local_value
        string_id = self._normalize_string_id(node.string_id)
        return self.string_matcher.get_match_count(string_id)

    def visit_string_offset(self, node: StringOffset) -> Any:
        """Get offset of string match."""
        local_value = self._lookup_explicit_string_variable(node.string_id)
        if local_value is not self._missing_loop_value:
            return local_value
        string_id = self._normalize_string_id(node.string_id)
        index = self._resolve_match_index(node.index)
        offset = self.string_matcher.get_match_offset(string_id, index)
        return offset if offset is not None else YARA_UNDEFINED

    def visit_string_length(self, node: StringLength) -> Any:
        """Get length of string match."""
        local_value = self._lookup_explicit_string_variable(node.string_id)
        if local_value is not self._missing_loop_value:
            return local_value
        string_id = self._normalize_string_id(node.string_id)
        index = self._resolve_match_index(node.index)
        length = self.string_matcher.get_match_length(string_id, index)
        return length if length is not None else YARA_UNDEFINED

    def _resolve_match_index(self, index_node: Expression | None) -> int:
        if index_node is None:
            return 0
        index = self.visit(index_node)
        return index - 1 if _is_evaluation_int(index) else -1

    def visit_binary_expression(self, node: BinaryExpression) -> Any:
        """Evaluate binary expression."""
        left = self.visit(node.left)

        # Short-circuit evaluation for boolean operators
        if node.operator == "and":
            if not _is_evaluation_truthy(left):
                return False
            right = self.visit(node.right)
            return False if is_yara_undefined(right) else right
        if node.operator == "or":
            if _is_evaluation_truthy(left):
                return True
            right = self.visit(node.right)
            return False if is_yara_undefined(right) else right

        right = self.visit(node.right)

        result = evaluate_arithmetic(left, right, node.operator)
        if result is not None:
            return result

        result = evaluate_comparison(left, right, node.operator)
        if result is not None:
            return result

        if node.operator == "matches" and isinstance(node.right, RegexLiteral):
            return evaluate_regex_match(left, node.right.pattern, node.right.modifiers)

        result = evaluate_string_operator(left, right, node.operator)
        if result is not None:
            return result

        msg = f"Unknown operator: {node.operator}"
        raise EvaluationError(msg)

    def visit_unary_expression(self, node: UnaryExpression) -> Any:
        """Evaluate unary expression."""
        operand = self.visit(node.operand)

        if node.operator == "not":
            if is_yara_undefined(operand):
                return operand
            return not _is_evaluation_truthy(operand)
        if node.operator == "-":
            if is_yara_undefined(operand):
                return operand
            if _is_evaluation_int(operand):
                return normalize_int64(-operand)
            if isinstance(operand, float):
                return -operand
            return YARA_UNDEFINED
        if node.operator == "~":
            if is_yara_undefined(operand):
                return operand
            if _is_evaluation_int(operand):
                return normalize_int64(~operand)
            return YARA_UNDEFINED
        msg = f"Unknown unary operator: {node.operator}"
        raise EvaluationError(msg)

    def visit_parentheses_expression(self, node: ParenthesesExpression) -> Any:
        """Evaluate parentheses expression."""
        return self.visit(node.expression)

    def visit_set_expression(self, node: SetExpression) -> set:
        """Evaluate set expression."""
        return {self.visit(elem) for elem in node.elements}

    def visit_range_expression(self, node: RangeExpression) -> Any:
        """Evaluate range expression."""
        low = self.visit(node.low)
        high = self.visit(node.high)
        if is_yara_undefined(low) or is_yara_undefined(high):
            return YARA_UNDEFINED
        if not _is_evaluation_int(low) or not _is_evaluation_int(high):
            return YARA_UNDEFINED
        if high < low:
            return YARA_UNDEFINED
        return range(low, high + 1)  # Inclusive range

    def visit_function_call(self, node: FunctionCall) -> Any:
        """Evaluate function call."""
        # Evaluate arguments
        args = [self.visit(arg) for arg in node.arguments]

        function = self._little_endian_aliases.get(node.function, node.function)
        reader = self._builtin_readers.get(function)
        if reader:
            if len(args) != 1:
                msg = f"{node.function}() expects exactly 1 argument"
                raise EvaluationError(msg)
            offset = args[0]
            if is_yara_undefined(offset):
                return YARA_UNDEFINED
            if not _is_evaluation_int(offset):
                msg = f"{node.function}() offset must be an integer"
                raise EvaluationError(msg)
            return reader(self.data, offset)

        local_function = self.context.variables.get(node.function)
        if callable(local_function):
            return local_function(*args)

        # Module functions
        if "." in node.function:
            module_name, func_name = node.function.split(".", 1)
            if module_name in self.context.modules:
                module = self.context.modules[module_name]
                resolved = self._resolve_module_function(module, func_name)
                if resolved is not None:
                    target, member_name = resolved
                    module_args = [
                        arg if isinstance(arg, RegexLiteral) else evaluated_arg
                        for arg, evaluated_arg in zip(node.arguments, args, strict=True)
                    ]
                    class_method = getattr(type(target), member_name, None)
                    if class_method is not None and callable(class_method):
                        return class_method(target, *module_args)
                    if hasattr(target, member_name):
                        func = getattr(target, member_name)
                        if callable(func):
                            return func(*module_args)
                        return func

        msg = f"Unknown function: {node.function}"
        raise EvaluationError(msg)

    def _resolve_module_function(
        self, module: object, dotted_name: str
    ) -> tuple[object, str] | None:
        target = module
        parts = dotted_name.split(".")
        for part in parts[:-1]:
            if not hasattr(target, part):
                return None
            target = getattr(target, part)
        return target, parts[-1]

    def visit_member_access(self, node: MemberAccess) -> Any:
        """Evaluate member access."""
        obj = self.visit(node.object)

        if obj is None:
            return None

        if hasattr(obj, node.member):
            value = getattr(obj, node.member)
            if callable(value):
                return YARA_UNDEFINED
            return value
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

    def visit_dictionary_access(self, node) -> Any:
        """Evaluate dictionary-style access."""
        obj = self.visit(node.object)
        key = self.visit(node.key) if hasattr(node.key, "accept") else node.key

        if obj is None:
            return None

        try:
            return obj[key]
        except (IndexError, KeyError, ValueError, TypeError, AttributeError):
            if isinstance(key, str) and hasattr(obj, key):
                return getattr(obj, key)
            return None

    def visit_list_expression(self, node) -> list[Any]:
        """Evaluate YARA-X list expression."""
        from yaraast.yarax.ast_nodes import SpreadOperator

        values = []
        for element in node.elements:
            if isinstance(element, SpreadOperator) and not element.is_dict:
                spread_value = self.visit(element.expression)
                try:
                    values.extend(spread_value)
                except TypeError:
                    values.append(spread_value)
            else:
                values.append(self.visit(element))
        return values

    def visit_tuple_expression(self, node) -> tuple[Any, ...]:
        """Evaluate YARA-X tuple expression."""
        return tuple(self.visit(element) for element in node.elements)

    def visit_dict_expression(self, node) -> dict[Any, Any]:
        """Evaluate YARA-X dictionary expression."""
        from yaraast.yarax.ast_nodes import SpreadOperator

        values = {}
        for item in node.items:
            if isinstance(item.value, SpreadOperator) and item.value.is_dict:
                spread_value = self.visit(item.value.expression)
                if isinstance(spread_value, dict):
                    values.update(spread_value)
                else:
                    with contextlib.suppress(TypeError, ValueError):
                        values.update(dict(spread_value))
                continue

            key, value = self.visit_dict_item(item)
            values[key] = value
        return values

    def visit_dict_item(self, node) -> tuple[Any, Any]:
        """Evaluate one YARA-X dictionary item."""
        return self.visit(node.key), self.visit(node.value)

    def visit_tuple_indexing(self, node) -> Any:
        """Evaluate YARA-X tuple indexing."""
        tuple_value = self.visit(node.tuple_expr)
        index = self.visit(node.index)
        try:
            return tuple_value[index]
        except (IndexError, KeyError, ValueError, TypeError, AttributeError):
            return None

    def visit_slice_expression(self, node) -> Any:
        """Evaluate YARA-X slice expression."""
        target = self.visit(node.target)
        start = self.visit(node.start) if node.start is not None else None
        stop = self.visit(node.stop) if node.stop is not None else None
        step = self.visit(node.step) if node.step is not None else None
        try:
            return target[slice(start, stop, step)]
        except (IndexError, KeyError, ValueError, TypeError, AttributeError):
            return None

    def visit_array_comprehension(self, node) -> list[Any]:
        """Evaluate YARA-X array comprehension."""
        iterable = self._evaluate_for_iterable(node.iterable)
        loop_items = self._loop_items_for_iterable(iterable, 1)
        if loop_items is None:
            return []

        values = []
        for item in loop_items:
            previous_values = self._bind_loop_variables([node.variable], item)
            if previous_values is None:
                continue

            try:
                if node.condition is None or _is_evaluation_truthy(self.visit(node.condition)):
                    values.append(self.visit(node.expression))
            finally:
                self._restore_loop_variables(previous_values)
        return values

    def visit_dict_comprehension(self, node) -> dict[Any, Any]:
        """Evaluate YARA-X dictionary comprehension."""
        variable_names = [node.key_variable]
        if node.value_variable:
            variable_names.append(node.value_variable)

        iterable = self._evaluate_for_iterable(node.iterable)
        loop_items = self._loop_items_for_iterable(iterable, len(variable_names))
        if loop_items is None:
            return {}

        values = {}
        for item in loop_items:
            previous_values = self._bind_loop_variables(variable_names, item)
            if previous_values is None:
                continue

            try:
                if node.condition is None or _is_evaluation_truthy(self.visit(node.condition)):
                    values[self.visit(node.key_expression)] = self.visit(node.value_expression)
            finally:
                self._restore_loop_variables(previous_values)
        return values

    def visit_with_statement(self, node) -> Any:
        """Evaluate YARA-X with statement with scoped declarations."""
        previous_values = {}
        try:
            for declaration in node.declarations:
                value = self.visit(declaration.value)
                names = self._with_declaration_names(declaration.identifier)
                for name in names:
                    if name not in previous_values:
                        previous_values[name] = self.context.variables.get(
                            name,
                            self._missing_loop_value,
                        )
                    self.context.variables[name] = value

            return self.visit(node.body)
        finally:
            self._restore_loop_variables(previous_values)

    def visit_with_declaration(self, node) -> Any:
        """Evaluate a standalone YARA-X with declaration."""
        return self.visit(node.value)

    def visit_pattern_match(self, node) -> Any:
        """Evaluate YARA-X pattern match expression."""
        value = self.visit(node.value)
        for case in node.cases:
            if value == self.visit(case.pattern):
                return self.visit(case.result)
        if node.default is not None:
            return self.visit(node.default)
        return None

    def visit_match_case(self, node) -> Any:
        """Evaluate a standalone YARA-X match case result."""
        return self.visit(node.result)

    def visit_spread_operator(self, node) -> Any:
        """Evaluate YARA-X spread operator."""
        return self.visit(node.expression)

    def visit_lambda_expression(self, node):
        """Evaluate YARA-X lambda expression as a Python callable."""

        def lambda_callable(*args):
            previous_values = {}
            for index, name in enumerate(node.parameters):
                value = args[index] if index < len(args) else YARA_UNDEFINED
                if name not in previous_values:
                    previous_values[name] = self.context.variables.get(
                        name,
                        self._missing_loop_value,
                    )
                self.context.variables[name] = value

            try:
                return self.visit(node.body)
            finally:
                self._restore_loop_variables(previous_values)

        return lambda_callable

    # Condition evaluation

    def visit_at_expression(self, node: AtExpression) -> bool:
        """Evaluate 'at' expression."""
        offset = self.visit(node.offset)
        if not _is_evaluation_int(offset):
            return False
        return self.string_matcher.string_at(self._normalize_string_id(node.string_id), offset)

    def visit_in_expression(self, node: InExpression) -> bool:
        """Evaluate 'in' expression."""
        range_val = self.visit(node.range)
        if not isinstance(range_val, range):
            return False
        if isinstance(node.subject, str):
            return self.string_matcher.string_in(
                self._normalize_string_id(node.subject),
                range_val.start,
                range_val.stop,
            )
        if isinstance(node.subject, OfExpression):
            return self._evaluate_of_expression(node.subject, match_range=range_val)
        return False

    def visit_of_expression(self, node: OfExpression) -> bool:
        """Evaluate 'of' expression."""
        return self._evaluate_of_expression(node)

    def _evaluate_of_expression(
        self,
        node: OfExpression,
        match_range: range | None = None,
    ) -> bool:
        """Evaluate an of-expression, optionally restricted to match offsets."""
        # Get quantifier value - could be int, string ("all", "any"), or expression
        quantifier = self._resolve_quantifier(node.quantifier)

        string_set = self._resolve_string_set(node.string_set)
        if not string_set:
            return False

        # Count matches
        matched = 0
        for string_id in string_set:
            normalized_id = self._normalize_string_id(string_id)
            if match_range is None:
                has_match = self.string_matcher.get_match_count(normalized_id) > 0
            else:
                has_match = self.string_matcher.string_in(
                    normalized_id,
                    match_range.start,
                    match_range.stop,
                )
            if has_match:
                matched += 1

        # Evaluate quantifier
        if isinstance(quantifier, str):
            if quantifier == "all":
                return matched == len(string_set)
            if quantifier == "any":
                return matched > 0
            if quantifier == "none":
                return matched == 0
        elif _is_evaluation_int(quantifier):
            if quantifier < 0:
                return False
            if quantifier == 0:
                return matched == 0
            return matched >= quantifier
        elif isinstance(quantifier, float):
            return len(string_set) > 0 and (matched / len(string_set)) >= quantifier

        return False

    def visit_for_expression(self, node: ForExpression) -> bool:
        """Evaluate 'for' expression."""
        # Get quantifier value - could be int, string ("all", "any"), or expression
        quantifier = self._resolve_quantifier(node.quantifier)

        variable_names = self._loop_variable_names(node.variable)
        iterable = self._evaluate_for_iterable(node.iterable)
        loop_items = self._loop_items_for_iterable(iterable, len(variable_names))
        if loop_items is None:
            return False

        # Count true evaluations
        true_count = 0
        total_count = 0
        for item in loop_items:
            total_count += 1
            previous_values = self._bind_loop_variables(variable_names, item)
            if previous_values is None:
                continue

            try:
                if _is_evaluation_truthy(self.visit(node.body)):
                    true_count += 1
            finally:
                self._restore_loop_variables(previous_values)

        # Evaluate quantifier
        if isinstance(quantifier, str):
            if quantifier == "all":
                return true_count == total_count
            if quantifier == "any":
                return true_count > 0
            if quantifier == "none":
                return true_count == 0
        elif _is_evaluation_int(quantifier):
            if quantifier < 0:
                return False
            if quantifier == 0:
                return true_count == 0
            return true_count >= quantifier

        return False

    def _loop_variable_names(self, variable: str) -> list[str]:
        return [name.strip() for name in variable.split(",") if name.strip()]

    def _evaluate_for_iterable(self, node: Expression | None) -> Any:
        if node is None:
            return YARA_UNDEFINED
        if isinstance(node, SetExpression):
            return [self._evaluate_for_iterable(element) for element in node.elements]
        return self.visit(node)

    def _loop_items_for_iterable(self, iterable: Any, variable_count: int) -> Any | None:
        if is_yara_undefined(iterable):
            return None
        if variable_count > 1 and isinstance(iterable, dict):
            return iterable.items()
        try:
            iter(iterable)
        except TypeError:
            return None
        return iterable

    def _bind_loop_variables(
        self,
        variable_names: list[str],
        item: Any,
    ) -> dict[str, object] | None:
        if len(variable_names) == 1:
            values = [item]
        else:
            values = self._loop_item_values(item)
            if len(values) != len(variable_names):
                return None

        previous_values: dict[str, object] = {}
        for name, value in zip(variable_names, values, strict=True):
            if name not in previous_values:
                previous_values[name] = self.context.variables.get(
                    name,
                    self._missing_loop_value,
                )
            self.context.variables[name] = value
        return previous_values

    def _loop_item_values(self, item: Any) -> list[Any]:
        if isinstance(item, str | bytes):
            return [item]
        try:
            return list(item)
        except TypeError:
            return [item]

    def _restore_loop_variables(self, previous_values: dict[str, object]) -> None:
        for name, previous_value in previous_values.items():
            if previous_value is self._missing_loop_value:
                self.context.variables.pop(name, None)
            else:
                self.context.variables[name] = previous_value

    def _with_declaration_names(self, identifier: str) -> list[str]:
        names = [identifier]
        stripped = identifier.lstrip("$")
        if stripped != identifier:
            names.append(stripped)
        return names

    # Helper methods for reading data

    def _resolve_quantifier(self, quantifier: QuantifierValue) -> int | str | float | Any:
        if isinstance(quantifier, int | str | float):
            return quantifier
        return self.visit(quantifier)

    def _resolve_string_set(self, string_set_node: Any) -> list[str]:
        """Resolve a string set to a list of string identifiers for 'of'/'for...of' evaluation."""
        from yaraast.ast.expressions import (
            ParenthesesExpression,
            SetExpression,
            StringIdentifier,
            StringWildcard,
        )

        anonymous_string_ids = self._anonymous_string_ids()

        def expand_text(text: str) -> list[str]:
            if text == "them":
                return list(self.context.string_matches.keys())
            if text.endswith("*"):
                raw_prefix = text[:-1].lstrip("#@!")
                if raw_prefix in {"", "$"}:
                    return list(self.context.string_matches.keys())
                prefixes = (
                    [raw_prefix] if raw_prefix.startswith("$") else [f"${raw_prefix}", raw_prefix]
                )
                return [
                    sid
                    for sid in self.context.string_matches
                    if sid not in anonymous_string_ids
                    and any(sid.startswith(prefix) for prefix in prefixes)
                ]
            return [self._normalize_string_id(text)]

        def resolve_visited_value(value: Any) -> list[str]:
            if isinstance(value, str):
                return expand_text(value)
            if isinstance(value, list | tuple | set | frozenset):
                result = []
                for item in value:
                    result.extend(resolve_visited_value(item))
                return result
            return expand_text(str(value))

        def resolve_value(value: Any) -> list[str]:
            if isinstance(value, str):
                return expand_text(value)
            if isinstance(value, StringWildcard):
                return expand_text(value.pattern)
            if isinstance(value, StringIdentifier):
                return [self._normalize_string_id(value.name)]
            if isinstance(value, ParenthesesExpression):
                return resolve_value(value.expression)
            if hasattr(value, "name") and value.name == "them":
                return list(self.context.string_matches.keys())
            if isinstance(value, SetExpression):
                return resolve_values(value.elements)
            if isinstance(value, list | tuple | set | frozenset):
                return resolve_values(value)
            if hasattr(value, "accept"):
                return resolve_visited_value(self.visit(value))
            return expand_text(str(value))

        def resolve_values(values: Any) -> list[str]:
            result = []
            for elem in values:
                result.extend(resolve_value(elem))
            return result

        return resolve_value(string_set_node)

    def _anonymous_string_ids(self) -> set[str]:
        if self._current_rule is None:
            return set()
        return {
            self._normalize_string_id(string_def.identifier)
            for string_def in self._current_rule.strings
            if getattr(string_def, "is_anonymous", False)
        }

    def _normalize_string_id(self, string_id: Any) -> str:
        text = str(string_id)
        if text in {"", "$"}:
            implicit = self.context.variables.get("$")
            if isinstance(implicit, str):
                text = implicit

        text = text.lstrip("#@!")
        if text in self.context.string_matches:
            return text
        if text.startswith("$"):
            return text

        prefixed = f"${text}"
        if prefixed in self.context.string_matches:
            return prefixed
        return prefixed

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
            raise EvaluationError(msg)
        return None

    def visit_for_of_expression(self, node) -> bool:
        """Evaluate 'for ... of' expression (ForOfExpression: quantifier, string_set, condition)."""
        quantifier = self._resolve_quantifier(node.quantifier)
        string_set = self._resolve_string_set(node.string_set)
        if not string_set:
            return False

        # Count how many strings match
        matches = 0
        for string_id in string_set:
            if node.condition is not None:
                # Set up implicit $ variable for the condition body
                old_value = self.context.variables.get("$", self._missing_loop_value)
                self.context.variables["$"] = string_id
                try:
                    if _is_evaluation_truthy(self.visit(node.condition)):
                        matches += 1
                finally:
                    if old_value is not self._missing_loop_value:
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
        elif _is_evaluation_int(quantifier):
            if quantifier < 0:
                return False
            if quantifier == 0:
                return matches == 0
            return matches >= quantifier
        elif isinstance(quantifier, float):
            return len(string_set) > 0 and (matches / len(string_set)) >= quantifier

        return False

    def visit_regex_literal(self, node) -> str:
        """Return regex pattern string."""
        # For regex literals, we'll return the pattern
        # The actual matching is handled by the binary expression "matches" operator
        return node.pattern

    def visit_defined_expression(self, node) -> bool:
        """Evaluate 'defined' expression."""
        from yaraast.ast.modules import DictionaryAccess, ModuleReference

        # Get the expression being checked
        expr = node.expression

        if isinstance(expr, Identifier):
            # Check if it's a module
            if expr.name in self.context.modules:
                return True
            # Check if it's a variable
            if expr.name in self.context.variables:
                return True
            if expr.name in {"filesize", "entrypoint", "all", "any", "them"}:
                return True
            return hasattr(self, "_rule_map") and expr.name in self._rule_map
        if isinstance(expr, ModuleReference):
            return expr.module in self.context.modules
        if isinstance(expr, DictionaryAccess | MemberAccess | ArrayAccess | FunctionCall):
            value = self.visit(expr)
            return value is not None and not is_yara_undefined(value)
        if isinstance(expr, StringIdentifier) and self._current_rule and self._current_rule.strings:
            if self._lookup_explicit_string_variable(expr.name) is not self._missing_loop_value:
                return True
            # Check if string is defined in current rule
            target = self._normalize_string_id(expr.name)
            for string_def in self._current_rule.strings:
                if self._normalize_string_id(string_def.identifier) == target:
                    return True

            return False
        if isinstance(expr, StringIdentifier):
            return self._lookup_explicit_string_variable(expr.name) is not self._missing_loop_value

        value = self.visit(expr)
        return value is not None and not is_yara_undefined(value)

    def visit_string_operator_expression(self, node) -> Any:
        """Evaluate string-specific operators like contains, startswith, etc."""
        # This is handled in binary_expression for string operators
        # But we can add specific handling here if needed
        return self.visit_binary_expression(node)
