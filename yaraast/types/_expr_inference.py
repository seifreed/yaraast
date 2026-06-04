"""Expression type inference for YARA."""

from __future__ import annotations

import math
from typing import Any

from yaraast.ast.comments import Comment, CommentGroup
from yaraast.ast.conditions import (
    AtExpression,
    ForExpression,
    ForOfExpression,
    InExpression,
    OfExpression,
)
from yaraast.ast.expressions import (
    ArrayAccess,
    BinaryExpression,
    BooleanLiteral,
    DoubleLiteral,
    Expression,
    FunctionCall,
    Identifier,
    IntegerLiteral,
    MemberAccess,
    ParenthesesExpression,
    RangeExpression,
    RegexLiteral,
    SetExpression,
    StringCount,
    StringIdentifier,
    StringLength,
    StringLiteral,
    StringOffset,
    StringWildcard,
    UnaryExpression,
)
from yaraast.ast.extern import ExternImport, ExternNamespace, ExternRule, ExternRuleReference
from yaraast.ast.modules import DictionaryAccess, ModuleReference
from yaraast.ast.operators import DefinedExpression, StringOperatorExpression
from yaraast.ast.pragmas import InRulePragma, Pragma, PragmaBlock
from yaraast.string_references import normalize_string_reference_id
from yaraast.visitor.defaults import DefaultASTVisitor
from yaraast.yarax.ast_nodes import SpreadOperator

from . import _expr_inference_ops as ops
from ._registry import (
    ArrayType,
    BooleanType,
    DictionaryType,
    DoubleType,
    IntegerType,
    ModuleType,
    RangeType,
    RegexType,
    StringIdentifierType,
    StringSetType,
    StringType,
    StructType,
    TypeEnvironment,
    UnknownType,
    YaraType,
)
from .type_environment import _normalize_identifier


class _TypeBaseVisitor(DefaultASTVisitor[YaraType]):
    """Base visitor with default UnknownType responses."""

    def __init__(self) -> None:
        super().__init__(default=UnknownType())

    def visit_comment(self, _node: Comment) -> YaraType:
        return UnknownType()

    def visit_comment_group(self, _node: CommentGroup) -> YaraType:
        return UnknownType()

    def visit_defined_expression(self, _node: DefinedExpression) -> YaraType:
        return BooleanType()

    def visit_string_operator_expression(self, _node: StringOperatorExpression) -> YaraType:
        return BooleanType()

    def visit_extern_import(self, _node: ExternImport) -> YaraType:
        return UnknownType()

    def visit_extern_namespace(self, _node: ExternNamespace) -> YaraType:
        return UnknownType()

    def visit_extern_rule(self, _node: ExternRule) -> YaraType:
        return UnknownType()

    def visit_extern_rule_reference(self, _node: ExternRuleReference) -> YaraType:
        return UnknownType()

    def visit_in_rule_pragma(self, _node: InRulePragma) -> YaraType:
        return UnknownType()

    def visit_pragma(self, _node: Pragma) -> YaraType:
        return UnknownType()

    def visit_pragma_block(self, _node: PragmaBlock) -> YaraType:
        return UnknownType()


class ExpressionTypeInference(_TypeBaseVisitor):
    """Type inference visitor for expressions."""

    def __init__(self, env: TypeEnvironment) -> None:
        super().__init__()
        self.env = env
        self.errors: list[str] = []

    def _normalize_string_id(self, string_id: str) -> str:
        return normalize_string_reference_id(string_id)

    def _resolve_module_type(self, module_name: str) -> ModuleType | None:
        try:
            if not self.env.has_module(module_name):
                return None
            actual_module = self.env.get_module_name(module_name)
        except ValueError:
            return None

        if not actual_module:
            return None

        from yaraast.types.module_loader import ModuleLoader

        loader = ModuleLoader()
        module_def = loader.get_module(actual_module)
        if not module_def:
            return None

        return ModuleType(
            module_name=actual_module,
            attributes=module_def.attributes,
        )

    def infer(self, node: Expression) -> YaraType:
        """Infer type of expression."""
        return self.visit(node)

    def _invalid_literal(self, message: str) -> YaraType:
        self.errors.append(message)
        return UnknownType()

    def _sequence_or_empty(self, value: Any, message: str) -> list[Any]:
        if isinstance(value, list | tuple | set | frozenset):
            return list(value)
        self.errors.append(message)
        return []

    def _visit_expression_or_unknown(self, value: Any, message: str) -> YaraType:
        if hasattr(value, "accept"):
            return self.visit(value)
        self.errors.append(message)
        return UnknownType()

    def visit_integer_literal(self, node: IntegerLiteral) -> YaraType:
        if isinstance(node.value, bool) or not isinstance(node.value, int):
            return self._invalid_literal("Integer literal value must be an integer")
        return IntegerType()

    def visit_double_literal(self, node: DoubleLiteral) -> YaraType:
        if isinstance(node.value, bool) or not isinstance(node.value, int | float):
            return self._invalid_literal("Double literal value must be numeric")
        if not math.isfinite(node.value):
            return self._invalid_literal("Double literal value must be finite")
        return DoubleType()

    def visit_string_literal(self, node: StringLiteral) -> YaraType:
        if not isinstance(node.value, str):
            return self._invalid_literal("String literal value must be a string")
        return StringType()

    def visit_regex_literal(self, node: RegexLiteral) -> YaraType:
        if not isinstance(node.pattern, str):
            return self._invalid_literal("Regex literal pattern must be a string")
        if not isinstance(node.modifiers, str):
            return self._invalid_literal("Regex literal modifiers must be a string")
        return RegexType()

    def visit_boolean_literal(self, node: BooleanLiteral) -> YaraType:
        if not isinstance(node.value, bool):
            return self._invalid_literal("Boolean literal value must be a boolean")
        return BooleanType()

    def visit_identifier(self, node: Identifier) -> YaraType:
        if not isinstance(node.name, str):
            return self._invalid_literal("Identifier name must be a string")
        return ops.infer_identifier(self, node)

    def visit_string_identifier(self, node: StringIdentifier) -> YaraType:
        if node.name == "$":
            scoped_type = self.env.lookup("$")
            if scoped_type:
                return scoped_type
        try:
            normalized = normalize_string_reference_id(node.name, allow_wildcard=False)
        except (TypeError, ValueError) as exc:
            self.errors.append(str(exc))
            return UnknownType()

        scoped_type = self.env.lookup(node.name) or self.env.lookup(normalized)
        if scoped_type:
            return scoped_type
        if self.env.has_string(normalized):
            return StringIdentifierType()
        self.errors.append(f"Undefined string: {normalized}")
        return UnknownType()

    def visit_string_wildcard(self, node: StringWildcard) -> YaraType:
        try:
            normalize_string_reference_id(node.pattern)
        except (TypeError, ValueError) as exc:
            self.errors.append(str(exc))
            return UnknownType()
        return StringSetType()

    def visit_string_count(self, node: StringCount) -> YaraType:
        return ops.infer_string_count_like(self, node.string_id, "String count")

    def visit_string_offset(self, node: StringOffset) -> YaraType:
        return ops.infer_string_count_like(
            self, node.string_id, "String offset", getattr(node, "index", None)
        )

    def visit_string_length(self, node: StringLength) -> YaraType:
        return ops.infer_string_count_like(
            self, node.string_id, "String length", getattr(node, "index", None)
        )

    def visit_binary_expression(self, node: BinaryExpression) -> YaraType:
        return ops.infer_binary_expression(self, node)

    def visit_unary_expression(self, node: UnaryExpression) -> YaraType:
        return ops.infer_unary_expression(self, node)

    def visit_defined_expression(self, node: DefinedExpression) -> YaraType:
        expression_type = self.visit(node.expression)
        if isinstance(expression_type, UnknownType):
            if isinstance(node.expression, StringIdentifier):
                return BooleanType()
            if isinstance(node.expression, Identifier):
                self.errors.append(f"Undefined identifier: {node.expression.name}")
            else:
                self.errors.append("'defined' cannot be applied to expression of unknown type")
        if isinstance(expression_type, ArrayType | DictionaryType | StructType | ModuleType):
            self.errors.append(
                f"'defined' cannot be applied to non-scalar expression of type {expression_type}"
            )
        return BooleanType()

    def visit_string_operator_expression(self, node: StringOperatorExpression) -> YaraType:
        return ops.infer_binary_expression(
            self,
            BinaryExpression(
                left=node.left,
                operator=node.operator,
                right=node.right,
            ),
        )

    def visit_extern_rule_reference(self, _node: ExternRuleReference) -> YaraType:
        return BooleanType()

    def visit_parentheses_expression(self, node: ParenthesesExpression) -> YaraType:
        return self.visit(node.expression)

    def visit_set_expression(self, node: SetExpression) -> YaraType:
        return ops.infer_set_or_range(self, node)

    def visit_range_expression(self, node: RangeExpression) -> YaraType:
        return ops.infer_set_or_range(self, node)

    def visit_function_call(self, node: FunctionCall) -> YaraType:
        return ops.infer_function_call(self, node)

    def visit_array_access(self, node: ArrayAccess) -> YaraType:
        return ops.infer_collection_access(self, node)

    def visit_member_access(self, node: MemberAccess) -> YaraType:
        return ops.infer_member_access(self, node)

    def visit_module_reference(self, node: ModuleReference) -> YaraType:
        return ops.infer_module_or_condition(self, node)

    def visit_dictionary_access(self, node: DictionaryAccess) -> YaraType:
        return ops.infer_collection_access(self, node)

    def visit_at_expression(self, node: AtExpression) -> YaraType:
        return ops.infer_module_or_condition(self, node)

    def visit_in_expression(self, node: InExpression) -> YaraType:
        return ops.infer_module_or_condition(self, node)

    def visit_of_expression(self, node: OfExpression) -> YaraType:
        return ops.infer_module_or_condition(self, node)

    def visit_for_expression(self, node: ForExpression) -> YaraType:
        return ops.infer_module_or_condition(self, node)

    def visit_for_of_expression(self, node: ForOfExpression) -> YaraType:
        return ops.infer_module_or_condition(self, node)

    def visit_with_statement(self, node: Any) -> YaraType:
        self.env.push_scope()
        for declaration in self._sequence_or_empty(
            node.declarations,
            "With-statement declarations must be a sequence",
        ):
            if not (hasattr(declaration, "identifier") and hasattr(declaration, "value")):
                self.errors.append("With-statement declarations item must be WithDeclaration")
                continue
            self.visit(declaration)
        body_type = self._visit_expression_or_unknown(
            node.body,
            "With-statement body must be Expression",
        )
        self.env.pop_scope()
        return body_type

    def visit_with_declaration(self, node: Any) -> YaraType:
        value_type = self._visit_expression_or_unknown(
            node.value,
            "With declaration value must be Expression",
        )
        identifier = self._normalize_local_variable(
            node.identifier,
            allow_string_identifier=True,
        )
        if identifier is None:
            return value_type
        self.env.define(identifier, value_type)
        self.env.define(identifier.lstrip("$"), value_type)
        return value_type

    def visit_list_expression(self, node: Any) -> YaraType:
        element_types: list[YaraType] = []
        for element in node.elements:
            element_type = self.visit(element)
            if isinstance(element, SpreadOperator) and not element.is_dict:
                if isinstance(element_type, ArrayType):
                    element_types.append(element_type.element_type)
                else:
                    self.errors.append(f"List spread requires array, got {element_type}")
                    element_types.append(UnknownType())
                continue
            element_types.append(element_type)
        return ArrayType(self._infer_common_type_from_types(element_types))

    def visit_tuple_expression(self, node: Any) -> YaraType:
        return ArrayType(self._infer_common_type(node.elements))

    def visit_dict_expression(self, node: Any) -> YaraType:
        key_types: list[YaraType] = []
        value_types: list[YaraType] = []
        for item in self._sequence_or_empty(
            node.items,
            "Dict expression items must be a sequence",
        ):
            if not (hasattr(item, "key") and hasattr(item, "value")):
                self.errors.append("Dict expression items item must be DictItem")
                key_types.append(UnknownType())
                value_types.append(UnknownType())
                continue
            if isinstance(item.value, SpreadOperator) and item.value.is_dict:
                spread_type = self.visit(item.value)
                if isinstance(spread_type, DictionaryType):
                    key_types.append(spread_type.key_type)
                    value_types.append(spread_type.value_type)
                else:
                    self.errors.append(f"Dict spread requires dictionary, got {spread_type}")
                    key_types.append(UnknownType())
                    value_types.append(UnknownType())
                continue
            key_types.append(self.visit(item.key))
            value_types.append(self.visit(item.value))
        return DictionaryType(
            self._infer_common_type_from_types(key_types),
            self._infer_common_type_from_types(value_types),
        )

    def visit_dict_item(self, node: Any) -> YaraType:
        return self.visit(node.value)

    def visit_array_comprehension(self, node: Any) -> YaraType:
        self.env.push_scope()
        variable = self._normalize_local_variable(node.variable)
        if variable is not None:
            self._define_iteration_variable(variable, node.iterable)
        elif node.iterable is not None:
            self.visit(node.iterable)
        if node.condition is not None:
            condition_type = self.visit(node.condition)
            if not isinstance(condition_type, BooleanType):
                self.errors.append(
                    f"Array comprehension filter must be boolean, got {condition_type}"
                )
        element_type = self.visit(node.expression) if node.expression is not None else UnknownType()
        self.env.pop_scope()
        return ArrayType(element_type)

    def visit_dict_comprehension(self, node: Any) -> YaraType:
        self.env.push_scope()
        key_variable = self._normalize_local_variable(node.key_variable)
        value_variable = (
            self._normalize_local_variable(node.value_variable)
            if node.value_variable is not None
            else None
        )
        if key_variable is not None:
            self._define_dict_comprehension_variables(
                key_variable,
                value_variable,
                node.iterable,
            )
        elif node.iterable is not None:
            self.visit(node.iterable)
        if node.condition is not None:
            condition_type = self.visit(node.condition)
            if not isinstance(condition_type, BooleanType):
                self.errors.append(
                    f"Dict comprehension filter must be boolean, got {condition_type}"
                )
        key_type = (
            self.visit(node.key_expression) if node.key_expression is not None else UnknownType()
        )
        value_type = (
            self.visit(node.value_expression)
            if node.value_expression is not None
            else UnknownType()
        )
        self.env.pop_scope()
        return DictionaryType(key_type, value_type)

    def visit_tuple_indexing(self, node: Any) -> YaraType:
        tuple_type = self.visit(node.tuple_expr)
        index_type = self.visit(node.index)
        if not isinstance(index_type, IntegerType):
            self.errors.append(f"Tuple index must be integer, got {index_type}")
        if isinstance(tuple_type, ArrayType):
            return tuple_type.element_type
        self.errors.append(f"Cannot index non-tuple type: {tuple_type}")
        return UnknownType()

    def visit_slice_expression(self, node: Any) -> YaraType:
        target_type = self.visit(node.target)
        for bound in (node.start, node.stop, node.step):
            if bound is not None and not isinstance(self.visit(bound), IntegerType):
                self.errors.append("Slice bounds must be integer")
        if isinstance(target_type, ArrayType | StringType):
            return target_type
        self.errors.append(f"Cannot slice non-array or string type: {target_type}")
        return UnknownType()

    def visit_lambda_expression(self, node: Any) -> YaraType:
        self.env.push_scope()
        for parameter in node.parameters:
            normalized = self._normalize_local_variable(parameter)
            if normalized is not None:
                self.env.define(normalized, UnknownType())
        self.visit(node.body)
        self.env.pop_scope()
        return UnknownType()

    def visit_pattern_match(self, node: Any) -> YaraType:
        self._visit_expression_or_unknown(
            node.value,
            "Pattern match value must be Expression",
        )
        result_nodes: list[Any] = []
        for case in self._sequence_or_empty(
            node.cases,
            "Pattern match cases must be a sequence",
        ):
            if not (hasattr(case, "pattern") and hasattr(case, "result")):
                self.errors.append("Pattern match cases item must be MatchCase")
                continue
            self.visit(case.pattern)
            result_nodes.append(case.result)
        if node.default is not None:
            result_nodes.append(node.default)
        return self._infer_common_type(result_nodes)

    def visit_match_case(self, node: Any) -> YaraType:
        self.visit(node.pattern)
        return self.visit(node.result)

    def visit_spread_operator(self, node: Any) -> YaraType:
        return self.visit(node.expression)

    def _define_dict_comprehension_variables(
        self,
        key_variable: str,
        value_variable: str | None,
        iterable: Any,
    ) -> None:
        iter_type = self.visit(iterable) if iterable is not None else UnknownType()
        if isinstance(iter_type, DictionaryType):
            self.env.define(key_variable, iter_type.key_type)
            if value_variable:
                self.env.define(value_variable, iter_type.value_type)
            return

        self._define_iteration_variable_from_type(key_variable, iter_type)
        if value_variable:
            self.env.define(value_variable, UnknownType())

    def _define_iteration_variable(self, variable: str, iterable: Any) -> None:
        iter_type = self.visit(iterable) if iterable is not None else UnknownType()
        self._define_iteration_variable_from_type(variable, iter_type)

    def _define_iteration_variable_from_type(self, variable: str, iter_type: YaraType) -> None:
        if isinstance(iter_type, ArrayType):
            self.env.define(variable, iter_type.element_type)
        elif isinstance(iter_type, RangeType):
            self.env.define(variable, IntegerType())
        elif isinstance(iter_type, DictionaryType):
            self.env.define(variable, iter_type.key_type)
        else:
            self.errors.append(f"Cannot iterate over type: {iter_type}")
            self.env.define(variable, UnknownType())

    def _normalize_local_variable(
        self,
        variable: Any,
        *,
        allow_string_identifier: bool = False,
    ) -> str | None:
        if not isinstance(variable, str):
            self.errors.append("Local variable name must be a string")
            return None
        if allow_string_identifier and variable.startswith("$"):
            try:
                return normalize_string_reference_id(variable, allow_wildcard=False)
            except ValueError:
                self.errors.append(f"Invalid local variable identifier: {variable}")
                return None
        try:
            return _normalize_identifier(variable, "Local variable name", "local variable")
        except ValueError:
            self.errors.append(f"Invalid local variable identifier: {variable}")
            return None

    def _infer_common_type(self, nodes: list[Any]) -> YaraType:
        if not nodes:
            return UnknownType()
        return self._infer_common_type_from_types([self.visit(node) for node in nodes])

    def _infer_common_type_from_types(self, types: list[YaraType]) -> YaraType:
        if not types:
            return UnknownType()
        first_type = types[0]
        for current_type in types[1:]:
            if not first_type.is_compatible_with(current_type):
                self.errors.append(
                    f"Collection elements must have compatible types: {first_type} vs {current_type}"
                )
        return first_type
