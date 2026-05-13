"""Function call semantic validation."""

from __future__ import annotations

from typing import TYPE_CHECKING

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
        if "." in node.function:
            parts = node.function.split(".", 1)
            if len(parts) == 2:
                module_name, func_name = parts
                self._validate_module_function_call(node, module_name, func_name)
        else:
            self._validate_builtin_function_call(node)

        for arg in node.arguments:
            self.visit(arg)

    def _validate_module_function_call(
        self,
        node: FunctionCall,
        module_name: str,
        func_name: str,
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
            available_funcs = list(module_def.functions.keys())
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
        self._validate_function_arity(node, func_def)

    def _validate_builtin_function_call(self, node: FunctionCall) -> None:
        func_name = node.function
        if func_name in BUILTIN_FUNCTION_ARITY:
            min_args, max_args = BUILTIN_FUNCTION_ARITY[func_name]
            actual_args = len(node.arguments)

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
    ) -> None:
        expected_args = len(func_def.parameters)
        actual_args = len(node.arguments)

        if actual_args > expected_args:
            param_names = [p[0] for p in func_def.parameters]
            self.result.add_error(
                f"Function '{func_def.name}' expects at most {expected_args} argument(s) ({', '.join(param_names)}), got {actual_args}",
                node.location,
            )
            return

    def visit_binary_expression(self, node) -> None:
        self.visit(node.left)
        self.visit(node.right)

    def visit_unary_expression(self, node) -> None:
        self.visit(node.operand)

    def visit_member_access(self, node) -> None:
        self.visit(node.object)

    def visit_parentheses_expression(self, node) -> None:
        self.visit(node.expression)

    def visit_set_expression(self, node) -> None:
        for elem in node.elements:
            self.visit(elem)

    def visit_range_expression(self, node) -> None:
        self.visit(node.low)
        self.visit(node.high)

    def visit_array_access(self, node) -> None:
        self.visit(node.array)
        self.visit(node.index)

    def visit_for_expression(self, node) -> None:
        self.visit(node.iterable)
        self.visit(node.body)

    def visit_for_of_expression(self, node) -> None:
        self._visit_ast_value(node.string_set)
        if node.condition:
            self.visit(node.condition)

    def visit_at_expression(self, node) -> None:
        self.visit(node.offset)

    def visit_in_expression(self, node) -> None:
        if not isinstance(node.subject, str):
            self._visit_ast_value(node.subject)
        self.visit(node.range)

    def visit_of_expression(self, node) -> None:
        self._visit_ast_value(node.quantifier)
        self._visit_ast_value(node.string_set)

    def visit_with_statement(self, node) -> None:
        for declaration in node.declarations:
            self.visit(declaration)
        self.visit(node.body)

    def visit_with_declaration(self, node) -> None:
        self.visit(node.value)

    def visit_array_comprehension(self, node) -> None:
        self._visit_ast_value(node.expression)
        self._visit_ast_value(node.iterable)
        self._visit_ast_value(node.condition)

    def visit_dict_comprehension(self, node) -> None:
        self._visit_ast_value(node.key_expression)
        self._visit_ast_value(node.value_expression)
        self._visit_ast_value(node.iterable)
        self._visit_ast_value(node.condition)

    def visit_tuple_expression(self, node) -> None:
        for element in node.elements:
            self.visit(element)

    def visit_tuple_indexing(self, node) -> None:
        self.visit(node.tuple_expr)
        self.visit(node.index)

    def visit_list_expression(self, node) -> None:
        for element in node.elements:
            self.visit(element)

    def visit_dict_expression(self, node) -> None:
        for item in node.items:
            self.visit(item)

    def visit_dict_item(self, node) -> None:
        self.visit(node.key)
        self.visit(node.value)

    def visit_slice_expression(self, node) -> None:
        self.visit(node.target)
        self._visit_ast_value(node.start)
        self._visit_ast_value(node.stop)
        self._visit_ast_value(node.step)

    def visit_lambda_expression(self, node) -> None:
        self.visit(node.body)

    def visit_pattern_match(self, node) -> None:
        self.visit(node.value)
        for case in node.cases:
            self.visit(case)
        self._visit_ast_value(node.default)

    def visit_match_case(self, node) -> None:
        self.visit(node.pattern)
        self.visit(node.result)

    def visit_spread_operator(self, node) -> None:
        self.visit(node.expression)

    def _visit_ast_value(self, value) -> None:
        if hasattr(value, "accept"):
            self.visit(value)
        elif isinstance(value, list):
            for item in value:
                self._visit_ast_value(item)
