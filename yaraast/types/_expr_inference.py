"""Expression type inference for YARA."""

from __future__ import annotations

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
from yaraast.visitor.defaults import DefaultASTVisitor

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
    TypeEnvironment,
    UnknownType,
    YaraType,
)


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
        if string_id.startswith("$"):
            return string_id
        return f"${string_id}"

    def _resolve_module_type(self, module_name: str) -> ModuleType | None:
        if not self.env.has_module(module_name):
            return None

        actual_module = self.env.get_module_name(module_name)
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

    def visit_integer_literal(self, node: IntegerLiteral) -> YaraType:
        return IntegerType()

    def visit_double_literal(self, node: DoubleLiteral) -> YaraType:
        return DoubleType()

    def visit_string_literal(self, node: StringLiteral) -> YaraType:
        return StringType()

    def visit_regex_literal(self, node: RegexLiteral) -> YaraType:
        return RegexType()

    def visit_boolean_literal(self, node: BooleanLiteral) -> YaraType:
        return BooleanType()

    def visit_identifier(self, node: Identifier) -> YaraType:
        return ops.infer_identifier(self, node)

    def visit_string_identifier(self, node: StringIdentifier) -> YaraType:
        if self.env.has_string(node.name) or self.env.has_string_pattern(node.name):
            return StringIdentifierType()
        self.errors.append(f"Undefined string: {node.name}")
        return UnknownType()

    def visit_string_wildcard(self, node: StringWildcard) -> YaraType:
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
        self.visit(node.expression)
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

    def visit_with_statement(self, node) -> YaraType:
        self.env.push_scope()
        for declaration in node.declarations:
            self.visit(declaration)
        body_type = self.visit(node.body)
        self.env.pop_scope()
        return body_type

    def visit_with_declaration(self, node) -> YaraType:
        value_type = self.visit(node.value)
        self.env.define(node.identifier, value_type)
        self.env.define(node.identifier.lstrip("$"), value_type)
        return value_type

    def visit_list_expression(self, node) -> YaraType:
        return ArrayType(self._infer_common_type(node.elements))

    def visit_tuple_expression(self, node) -> YaraType:
        return ArrayType(self._infer_common_type(node.elements))

    def visit_dict_expression(self, node) -> YaraType:
        keys = [item.key for item in node.items]
        values = [item.value for item in node.items]
        return DictionaryType(
            self._infer_common_type(keys),
            self._infer_common_type(values),
        )

    def visit_dict_item(self, node) -> YaraType:
        return self.visit(node.value)

    def visit_array_comprehension(self, node) -> YaraType:
        self.env.push_scope()
        self._define_iteration_variable(node.variable, node.iterable)
        if node.condition is not None:
            condition_type = self.visit(node.condition)
            if not isinstance(condition_type, BooleanType):
                self.errors.append(
                    f"Array comprehension filter must be boolean, got {condition_type}"
                )
        element_type = self.visit(node.expression) if node.expression is not None else UnknownType()
        self.env.pop_scope()
        return ArrayType(element_type)

    def visit_dict_comprehension(self, node) -> YaraType:
        self.env.push_scope()
        self._define_iteration_variable(node.key_variable, node.iterable)
        if node.value_variable:
            self.env.define(node.value_variable, UnknownType())
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

    def visit_tuple_indexing(self, node) -> YaraType:
        tuple_type = self.visit(node.tuple_expr)
        index_type = self.visit(node.index)
        if not isinstance(index_type, IntegerType):
            self.errors.append(f"Tuple index must be integer, got {index_type}")
        if isinstance(tuple_type, ArrayType):
            return tuple_type.element_type
        self.errors.append(f"Cannot index non-tuple type: {tuple_type}")
        return UnknownType()

    def visit_slice_expression(self, node) -> YaraType:
        target_type = self.visit(node.target)
        for bound in (node.start, node.stop, node.step):
            if bound is not None and not isinstance(self.visit(bound), IntegerType):
                self.errors.append("Slice bounds must be integer")
        if isinstance(target_type, ArrayType | StringType):
            return target_type
        self.errors.append(f"Cannot slice non-array or string type: {target_type}")
        return UnknownType()

    def visit_lambda_expression(self, node) -> YaraType:
        self.env.push_scope()
        for parameter in node.parameters:
            self.env.define(parameter, UnknownType())
        self.visit(node.body)
        self.env.pop_scope()
        return UnknownType()

    def visit_pattern_match(self, node) -> YaraType:
        self.visit(node.value)
        result_nodes = []
        for case in node.cases:
            self.visit(case.pattern)
            result_nodes.append(case.result)
        if node.default is not None:
            result_nodes.append(node.default)
        return self._infer_common_type(result_nodes)

    def visit_match_case(self, node) -> YaraType:
        self.visit(node.pattern)
        return self.visit(node.result)

    def visit_spread_operator(self, node) -> YaraType:
        return self.visit(node.expression)

    def _define_iteration_variable(self, variable: str, iterable) -> None:
        iter_type = self.visit(iterable) if iterable is not None else UnknownType()
        if isinstance(iter_type, ArrayType):
            self.env.define(variable, iter_type.element_type)
        elif isinstance(iter_type, RangeType):
            self.env.define(variable, IntegerType())
        else:
            self.errors.append(f"Cannot iterate over type: {iter_type}")
            self.env.define(variable, UnknownType())

    def _infer_common_type(self, nodes: list) -> YaraType:
        if not nodes:
            return UnknownType()
        first_type = self.visit(nodes[0])
        for node in nodes[1:]:
            current_type = self.visit(node)
            if not first_type.is_compatible_with(current_type):
                self.errors.append(
                    f"Collection elements must have compatible types: {first_type} vs {current_type}"
                )
        return first_type
