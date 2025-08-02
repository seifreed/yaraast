"""Expression optimizer for simplifying YARA expressions."""

from __future__ import annotations

from typing import TYPE_CHECKING

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
    SetExpression,
    StringCount,
    StringIdentifier,
    StringLength,
    StringLiteral,
    StringOffset,
    UnaryExpression,
)
from yaraast.visitor import ASTTransformer

if TYPE_CHECKING:
    from yaraast.ast.base import YaraFile
    from yaraast.ast.conditions import (
        AtExpression,
        Condition,
        ForExpression,
        ForOfExpression,
        InExpression,
        OfExpression,
    )
    from yaraast.ast.meta import Meta
    from yaraast.ast.modules import DictionaryAccess, ModuleReference
    from yaraast.ast.rules import Import, Include, Rule, Tag
    from yaraast.ast.strings import (
        HexAlternative,
        HexByte,
        HexJump,
        HexNibble,
        HexString,
        HexToken,
        HexWildcard,
        PlainString,
        RegexString,
        StringDefinition,
        StringModifier,
    )


class ExpressionOptimizer(ASTTransformer):
    """Optimize and simplify YARA expressions."""

    def __init__(self):
        self.optimizations_made = 0

    def optimize(self, yara_file: YaraFile) -> tuple[YaraFile, int]:
        """Optimize a YARA file and return (optimized_file, optimization_count)."""
        self.optimizations_made = 0
        optimized = self.visit(yara_file)
        return optimized, self.optimizations_made

    def visit_binary_expression(self, node: BinaryExpression) -> Expression:
        """Optimize binary expressions."""
        # First optimize children
        left = self.visit(node.left)
        right = self.visit(node.right)

        # Logical optimizations
        if node.operator == "and":
            # true and X => X
            if isinstance(left, BooleanLiteral) and left.value:
                self.optimizations_made += 1
                return right
            # X and true => X
            if isinstance(right, BooleanLiteral) and right.value:
                self.optimizations_made += 1
                return left
            # false and X => false
            if isinstance(left, BooleanLiteral) and not left.value:
                self.optimizations_made += 1
                return left
            # X and false => false
            if isinstance(right, BooleanLiteral) and not right.value:
                self.optimizations_made += 1
                return right

        elif node.operator == "or":
            # false or X => X
            if isinstance(left, BooleanLiteral) and not left.value:
                self.optimizations_made += 1
                return right
            # X or false => X
            if isinstance(right, BooleanLiteral) and not right.value:
                self.optimizations_made += 1
                return left
            # true or X => true
            if isinstance(left, BooleanLiteral) and left.value:
                self.optimizations_made += 1
                return left
            # X or true => true
            if isinstance(right, BooleanLiteral) and right.value:
                self.optimizations_made += 1
                return right

        # Arithmetic constant folding
        elif node.operator in ["+", "-", "*", "/", "%"]:
            if isinstance(left, IntegerLiteral) and isinstance(right, IntegerLiteral):
                self.optimizations_made += 1
                if node.operator == "+":
                    return IntegerLiteral(value=left.value + right.value)
                if node.operator == "-":
                    return IntegerLiteral(value=left.value - right.value)
                if node.operator == "*":
                    return IntegerLiteral(value=left.value * right.value)
                if node.operator == "/" and right.value != 0:
                    return IntegerLiteral(value=left.value // right.value)
                if node.operator == "%" and right.value != 0:
                    return IntegerLiteral(value=left.value % right.value)

        # Comparison constant folding
        elif node.operator in ["<", "<=", ">", ">=", "==", "!="]:
            if isinstance(left, IntegerLiteral) and isinstance(right, IntegerLiteral):
                self.optimizations_made += 1
                if node.operator == "<":
                    return BooleanLiteral(value=left.value < right.value)
                if node.operator == "<=":
                    return BooleanLiteral(value=left.value <= right.value)
                if node.operator == ">":
                    return BooleanLiteral(value=left.value > right.value)
                if node.operator == ">=":
                    return BooleanLiteral(value=left.value >= right.value)
                if node.operator == "==":
                    return BooleanLiteral(value=left.value == right.value)
                if node.operator == "!=":
                    return BooleanLiteral(value=left.value != right.value)

        # No optimization possible
        node.left = left
        node.right = right
        return node

    def visit_unary_expression(self, node: UnaryExpression) -> Expression:
        """Optimize unary expressions."""
        operand = self.visit(node.operand)

        if node.operator == "not":
            # not true => false, not false => true
            if isinstance(operand, BooleanLiteral):
                self.optimizations_made += 1
                return BooleanLiteral(value=not operand.value)
            # not (not X) => X
            if isinstance(operand, UnaryExpression) and operand.operator == "not":
                self.optimizations_made += 1
                return operand.operand

        elif node.operator == "-":
            # -(-X) => X
            if isinstance(operand, UnaryExpression) and operand.operator == "-":
                self.optimizations_made += 1
                return operand.operand
            # -literal
            if isinstance(operand, IntegerLiteral):
                self.optimizations_made += 1
                return IntegerLiteral(value=-operand.value)

        node.operand = operand
        return node

    def visit_parentheses_expression(self, node: ParenthesesExpression) -> Expression:
        """Remove unnecessary parentheses."""
        inner = self.visit(node.expression)

        # Remove parentheses around literals
        if isinstance(inner, IntegerLiteral | BooleanLiteral | StringLiteral | Identifier):
            self.optimizations_made += 1
            return inner

        node.expression = inner
        return node

    # Pass through methods for other node types
    def visit_yara_file(self, node: YaraFile) -> YaraFile:
        node.imports = [self.visit(imp) for imp in node.imports]
        node.includes = [self.visit(inc) for inc in node.includes]
        node.rules = [self.visit(rule) for rule in node.rules]
        return node

    def visit_rule(self, node: Rule) -> Rule:
        node.strings = [self.visit(s) for s in node.strings]
        node.condition = self.visit(node.condition)
        return node

    def visit_import(self, node: Import) -> Import:
        return node

    def visit_include(self, node: Include) -> Include:
        return node

    def visit_tag(self, node: Tag) -> Tag:
        return node

    def visit_string_definition(self, node: StringDefinition) -> StringDefinition:
        return node

    def visit_plain_string(self, node: PlainString) -> PlainString:
        return node

    def visit_hex_string(self, node: HexString) -> HexString:
        return node

    def visit_regex_string(self, node: RegexString) -> RegexString:
        return node

    def visit_string_modifier(self, node: StringModifier) -> StringModifier:
        return node

    def visit_hex_token(self, node: HexToken) -> HexToken:
        return node

    def visit_hex_byte(self, node: HexByte) -> HexByte:
        return node

    def visit_hex_wildcard(self, node: HexWildcard) -> HexWildcard:
        return node

    def visit_hex_jump(self, node: HexJump) -> HexJump:
        return node

    def visit_hex_alternative(self, node: HexAlternative) -> HexAlternative:
        return node

    def visit_hex_nibble(self, node: HexNibble) -> HexNibble:
        return node

    def visit_expression(self, node: Expression) -> Expression:
        return node

    def visit_identifier(self, node: Identifier) -> Identifier:
        return node

    def visit_string_identifier(self, node: StringIdentifier) -> StringIdentifier:
        return node

    def visit_string_count(self, node: StringCount) -> StringCount:
        return node

    def visit_string_offset(self, node: StringOffset) -> StringOffset:
        return node

    def visit_string_length(self, node: StringLength) -> StringLength:
        return node

    def visit_integer_literal(self, node: IntegerLiteral) -> IntegerLiteral:
        return node

    def visit_double_literal(self, node: DoubleLiteral) -> DoubleLiteral:
        return node

    def visit_string_literal(self, node: StringLiteral) -> StringLiteral:
        return node

    def visit_boolean_literal(self, node: BooleanLiteral) -> BooleanLiteral:
        return node

    def visit_set_expression(self, node: SetExpression) -> SetExpression:
        node.elements = [self.visit(elem) for elem in node.elements]
        return node

    def visit_range_expression(self, node: RangeExpression) -> RangeExpression:
        node.low = self.visit(node.low)
        node.high = self.visit(node.high)
        return node

    def visit_function_call(self, node: FunctionCall) -> FunctionCall:
        node.arguments = [self.visit(arg) for arg in node.arguments]
        return node

    def visit_array_access(self, node: ArrayAccess) -> ArrayAccess:
        node.array = self.visit(node.array)
        node.index = self.visit(node.index)
        return node

    def visit_member_access(self, node: MemberAccess) -> MemberAccess:
        node.object = self.visit(node.object)
        return node

    def visit_condition(self, node: Condition) -> Condition:
        return self.visit(node)

    def visit_for_expression(self, node: ForExpression) -> ForExpression:
        node.iterable = self.visit(node.iterable)
        node.body = self.visit(node.body)
        return node

    def visit_for_of_expression(self, node: ForOfExpression) -> ForOfExpression:
        node.quantifier = self.visit(node.quantifier)
        node.string_set = self.visit(node.string_set)
        if node.condition:
            node.condition = self.visit(node.condition)
        return node

    def visit_at_expression(self, node: AtExpression) -> AtExpression:
        node.string_id = self.visit(node.string_id)
        node.offset = self.visit(node.offset)
        return node

    def visit_in_expression(self, node: InExpression) -> InExpression:
        node.string_id = self.visit(node.string_id)
        node.range = self.visit(node.range)
        return node

    def visit_of_expression(self, node: OfExpression) -> OfExpression:
        node.quantifier = self.visit(node.quantifier)
        node.string_set = self.visit(node.string_set)
        return node

    def visit_meta(self, node: Meta) -> Meta:
        return node

    def visit_module_reference(self, node: ModuleReference) -> ModuleReference:
        return node

    def visit_dictionary_access(self, node: DictionaryAccess) -> DictionaryAccess:
        node.object = self.visit(node.object)
        node.key = self.visit(node.key)
        return node
