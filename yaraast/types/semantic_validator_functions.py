"""Function call semantic validation."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

from yaraast.types.module_contracts import FunctionDefinition
from yaraast.types.module_loader import ModuleLoader
from yaraast.types.semantic_validator_core import ValidationResult
from yaraast.types.semantic_validator_helpers import BUILTIN_FUNCTION_ARITY
from yaraast.types.type_system import TypeEnvironment
from yaraast.visitor.defaults import DefaultASTVisitor

if TYPE_CHECKING:
    from yaraast.ast.expressions import FunctionCall


class FunctionCallValidator(DefaultASTVisitor[None]):
    """Validator for function calls and module function existence."""

    def __init__(self, result: ValidationResult, env: TypeEnvironment) -> None:
        super().__init__(default=None)
        self.result = result
        self.env = env
        self.module_loader = ModuleLoader()

    def visit_function_call(self, node: FunctionCall) -> None:
        function_name = self._function_name_or_none(node.function, node)
        arguments = self._function_arguments(node.arguments, node)
        if function_name is None:
            self._visit_function_arguments(arguments, node)
            return

        if "." in function_name:
            parts = function_name.split(".", 1)
            if len(parts) == 2:
                module_name, func_name = parts
                self._validate_module_function_call(node, module_name, func_name, arguments)
        else:
            self._validate_builtin_function_call(node, function_name, arguments)

        self._visit_function_arguments(arguments, node)

    def _function_name_or_none(self, value: Any, node: FunctionCall) -> str | None:
        if isinstance(value, str):
            return value
        self.result.add_error(
            "Function name must be a string",
            node.location,
            "Use a function name such as 'uint16' or 'pe.imphash'.",
        )
        return None

    def _function_arguments(self, value: Any, node: FunctionCall) -> list[Any]:
        if isinstance(value, list | tuple):
            return list(value)
        self.result.add_error(
            "Function arguments must be a list",
            node.location,
            "Use a list of expression arguments.",
        )
        return []

    def _visit_function_arguments(self, arguments: list[Any], node: FunctionCall) -> None:
        for arg in arguments:
            self._visit_required_expression(arg, node, "Function arguments item")

    def _validate_module_function_call(
        self,
        node: FunctionCall,
        module_name: str,
        func_name: str,
        arguments: list[Any],
    ) -> None:
        if not self.env.has_module(module_name):
            self.result.add_error(
                f"Module '{module_name}' not imported, cannot call '{node.function}'",
                node.location,
                f"Add 'import \"{module_name}\"' at the top of your file.",
            )
            return

        actual_module = self.env.get_module_name(module_name)
        if not actual_module:
            return

        module_def = self.module_loader.get_module(actual_module)
        if not module_def:
            self.result.add_warning(
                f"Module definition for '{actual_module}' not found, cannot validate function '{func_name}'",
                node.location,
            )
            return

        if func_name not in module_def.functions:
            available_funcs = sorted(module_def.functions)
            self.result.add_error(
                f"Function '{func_name}' not found in module '{actual_module}'",
                node.location,
                (
                    f"Available functions: {', '.join(available_funcs)}"
                    if available_funcs
                    else "No functions available"
                ),
            )
            return

        func_def = module_def.functions[func_name]
        self._validate_function_arity(node, func_def, arguments)

    def _validate_builtin_function_call(
        self,
        node: FunctionCall,
        func_name: str,
        arguments: list[Any],
    ) -> None:
        if func_name in BUILTIN_FUNCTION_ARITY:
            min_args, max_args = BUILTIN_FUNCTION_ARITY[func_name]
            actual_args = len(arguments)

            if actual_args < min_args:
                self.result.add_error(
                    f"Function '{func_name}' expects at least {min_args} argument(s), got {actual_args}",
                    node.location,
                )
            elif actual_args > max_args:
                self.result.add_error(
                    f"Function '{func_name}' expects at most {max_args} argument(s), got {actual_args}",
                    node.location,
                )
        else:
            self.result.add_warning(
                f"Unknown function '{func_name}'. If this is a module function, use 'module.{func_name}' syntax.",
                node.location,
            )

    def _validate_function_arity(
        self,
        node: FunctionCall,
        func_def: FunctionDefinition,
        arguments: list[Any],
    ) -> None:
        max_args = len(func_def.parameters)
        min_args = func_def.min_parameters if func_def.min_parameters is not None else max_args
        actual_args = len(arguments)

        if actual_args < min_args:
            self.result.add_error(
                f"Function '{func_def.name}' expects at least {min_args} argument(s), got {actual_args}",
                node.location,
            )
            return

        if not func_def.variadic and actual_args > max_args:
            param_names = [p[0] for p in func_def.parameters]
            self.result.add_error(
                f"Function '{func_def.name}' expects at most {max_args} argument(s) ({', '.join(param_names)}), got {actual_args}",
                node.location,
            )
            return

    def visit_binary_expression(self, node: Any) -> None:
        self._visit_required_expression(node.left, node, "Binary expression left operand")
        self._visit_required_expression(node.right, node, "Binary expression right operand")

    def visit_unary_expression(self, node: Any) -> None:
        self._visit_required_expression(node.operand, node, "Unary expression operand")

    def visit_member_access(self, node: Any) -> None:
        self._visit_required_expression(node.object, node, "Member access object")

    def visit_parentheses_expression(self, node: Any) -> None:
        self._visit_required_expression(node.expression, node, "Parenthesized expression")

    def visit_set_expression(self, node: Any) -> None:
        self._visit_expression_sequence(node.elements, node, "Set expression elements")

    def visit_range_expression(self, node: Any) -> None:
        self._visit_required_expression(node.low, node, "Range low bound")
        self._visit_required_expression(node.high, node, "Range high bound")

    def visit_array_access(self, node: Any) -> None:
        self._visit_required_expression(node.array, node, "Array access target")
        self._visit_required_expression(node.index, node, "Array access index")

    def visit_dictionary_access(self, node: Any) -> None:
        self._visit_required_expression(node.object, node, "Dictionary access object")
        self._visit_ast_value(node.key)

    def visit_string_offset(self, node: Any) -> None:
        self._visit_ast_value(node.index)

    def visit_string_length(self, node: Any) -> None:
        self._visit_ast_value(node.index)

    def visit_defined_expression(self, node: Any) -> None:
        self._visit_required_expression(node.expression, node, "Defined expression operand")

    def visit_string_operator_expression(self, node: Any) -> None:
        self._visit_required_expression(node.left, node, "String operator left operand")
        self._visit_required_expression(node.right, node, "String operator right operand")

    def visit_for_expression(self, node: Any) -> None:
        self._visit_ast_value(node.quantifier)
        self._visit_required_expression(node.iterable, node, "For-expression iterable")
        self._visit_required_expression(node.body, node, "For-expression body")

    def visit_for_of_expression(self, node: Any) -> None:
        self._visit_ast_value(node.quantifier)
        self._visit_ast_value(node.string_set)
        if node.condition is not None:
            self._visit_required_expression(node.condition, node, "For-of condition")

    def visit_at_expression(self, node: Any) -> None:
        if not isinstance(node.string_id, str):
            self._visit_ast_value(node.string_id)
        self._visit_required_expression(node.offset, node, "At-expression offset")

    def visit_in_expression(self, node: Any) -> None:
        if not isinstance(node.subject, str):
            self._visit_ast_value(node.subject)
        self._visit_required_expression(node.range, node, "In-expression range")

    def visit_of_expression(self, node: Any) -> None:
        self._visit_ast_value(node.quantifier)
        self._visit_ast_value(node.string_set)

    def visit_with_statement(self, node: Any) -> None:
        self._visit_expression_sequence(node.declarations, node, "With-statement declarations")
        self._visit_required_expression(node.body, node, "With-statement body")

    def visit_with_declaration(self, node: Any) -> None:
        self._visit_required_expression(node.value, node, "With declaration value")

    def visit_array_comprehension(self, node: Any) -> None:
        self._visit_ast_value(node.expression)
        self._visit_ast_value(node.iterable)
        self._visit_ast_value(node.condition)

    def visit_dict_comprehension(self, node: Any) -> None:
        self._visit_ast_value(node.key_expression)
        self._visit_ast_value(node.value_expression)
        self._visit_ast_value(node.iterable)
        self._visit_ast_value(node.condition)

    def visit_tuple_expression(self, node: Any) -> None:
        self._visit_expression_sequence(node.elements, node, "Tuple expression elements")

    def visit_tuple_indexing(self, node: Any) -> None:
        self._visit_required_expression(node.tuple_expr, node, "Tuple indexing target")
        self._visit_required_expression(node.index, node, "Tuple indexing index")

    def visit_list_expression(self, node: Any) -> None:
        self._visit_expression_sequence(node.elements, node, "List expression elements")

    def visit_dict_expression(self, node: Any) -> None:
        self._visit_expression_sequence(node.items, node, "Dict expression items")

    def visit_dict_item(self, node: Any) -> None:
        self._visit_required_expression(node.key, node, "Dict item key")
        self._visit_required_expression(node.value, node, "Dict item value")

    def visit_slice_expression(self, node: Any) -> None:
        self._visit_required_expression(node.target, node, "Slice expression target")
        self._visit_ast_value(node.start)
        self._visit_ast_value(node.stop)
        self._visit_ast_value(node.step)

    def visit_lambda_expression(self, node: Any) -> None:
        self._visit_required_expression(node.body, node, "Lambda expression body")

    def visit_pattern_match(self, node: Any) -> None:
        self._visit_required_expression(node.value, node, "Pattern match value")
        self._visit_expression_sequence(node.cases, node, "Pattern match cases")
        self._visit_ast_value(node.default)

    def visit_match_case(self, node: Any) -> None:
        self._visit_required_expression(node.pattern, node, "Match case pattern")
        self._visit_required_expression(node.result, node, "Match case result")

    def visit_spread_operator(self, node: Any) -> None:
        self._visit_required_expression(node.expression, node, "Spread operator expression")

    def _visit_ast_value(self, value: Any) -> None:
        if hasattr(value, "accept"):
            self.visit(value)
        elif isinstance(value, Mapping):
            for item in value.values():
                self._visit_ast_value(item)
        elif isinstance(value, list | tuple | set | frozenset):
            for item in value:
                self._visit_ast_value(item)

    def _visit_required_expression(self, value: Any, node: Any, field_name: str) -> None:
        if hasattr(value, "accept"):
            self.visit(value)
            return
        self.result.add_error(
            f"{field_name} must be Expression",
            getattr(node, "location", None),
            "Use expression nodes for expression fields.",
        )

    def _visit_expression_sequence(self, value: Any, node: Any, field_name: str) -> None:
        if not isinstance(value, list | tuple | set | frozenset):
            self.result.add_error(
                f"{field_name} must be a sequence",
                getattr(node, "location", None),
                "Use a list, tuple, set, or frozenset of expression nodes.",
            )
            return
        for item in value:
            self._visit_required_expression(item, node, f"{field_name} item")
