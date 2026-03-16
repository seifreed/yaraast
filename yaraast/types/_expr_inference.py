"""Expression type inference for YARA."""

from __future__ import annotations

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
from yaraast.ast.modules import DictionaryAccess, ModuleReference
from yaraast.visitor.defaults import DefaultASTVisitor

from . import _expr_inference_ops as ops
from ._registry import (
    BooleanType,
    DoubleType,
    IntegerType,
    ModuleType,
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

    def visit_comment(self, _node):  # type: ignore[override]
        return UnknownType()

    def visit_comment_group(self, _node):  # type: ignore[override]
        return UnknownType()

    def visit_defined_expression(self, _node):  # type: ignore[override]
        return BooleanType()

    def visit_string_operator_expression(self, _node):  # type: ignore[override]
        return BooleanType()

    def visit_extern_import(self, _node):  # type: ignore[override]
        return UnknownType()

    def visit_extern_namespace(self, _node):  # type: ignore[override]
        return UnknownType()

    def visit_extern_rule(self, _node):  # type: ignore[override]
        return UnknownType()

    def visit_extern_rule_reference(self, _node):  # type: ignore[override]
        return UnknownType()

    def visit_in_rule_pragma(self, _node):  # type: ignore[override]
        return UnknownType()

    def visit_pragma(self, _node):  # type: ignore[override]
        return UnknownType()

    def visit_pragma_block(self, _node):  # type: ignore[override]
        return UnknownType()


class ExpressionTypeInference(_TypeBaseVisitor):
    """Type inference visitor for expressions."""

    def __init__(self, env: TypeEnvironment) -> None:
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
