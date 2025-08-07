"""Visitor pattern implementation for AST traversal."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, TypeVar, cast

T = TypeVar("T")

# Import specific classes from AST modules
from yaraast.ast.base import ASTNode, YaraFile
from yaraast.ast.comments import Comment, CommentGroup
from yaraast.ast.conditions import (
    AtExpression,
    Condition,
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
    UnaryExpression,
)
from yaraast.ast.extern import ExternImport, ExternNamespace, ExternRule, ExternRuleReference
from yaraast.ast.meta import Meta
from yaraast.ast.modifiers import StringModifier
from yaraast.ast.operators import DefinedExpression, StringOperatorExpression
from yaraast.ast.pragmas import InRulePragma, Pragma, PragmaBlock
from yaraast.ast.rules import Import, Include, Rule
from yaraast.ast.simple_nodes import Tag
from yaraast.ast.strings import (
    HexAlternative,
    HexByte,
    HexJump,
    HexString,
    HexToken,
    HexWildcard,
    PlainString,
    RegexString,
    StringDefinition,
)


class ASTVisitor[T](ABC):
    """Base visitor class for traversing AST nodes."""

    def visit(self, node: ASTNode) -> T:
        """Visit a node by calling its accept method."""
        return node.accept(self)

    # Base nodes
    @abstractmethod
    def visit_yara_file(self, node: YaraFile) -> T:
        """Visit YaraFile node."""

    @abstractmethod
    def visit_import(self, node: Import) -> T:
        """Visit Import node."""

    @abstractmethod
    def visit_include(self, node: Include) -> T:
        """Visit Include node."""

    @abstractmethod
    def visit_rule(self, node: Rule) -> T:
        """Visit Rule node."""

    @abstractmethod
    def visit_tag(self, node: Tag) -> T:
        """Visit Tag node."""

    # String definitions
    @abstractmethod
    def visit_string_definition(self, node: StringDefinition) -> T:
        """Visit StringDefinition node."""

    @abstractmethod
    def visit_plain_string(self, node: PlainString) -> T:
        """Visit PlainString node."""

    @abstractmethod
    def visit_hex_string(self, node: HexString) -> T:
        """Visit HexString node."""

    @abstractmethod
    def visit_regex_string(self, node: RegexString) -> T:
        """Visit RegexString node."""

    @abstractmethod
    def visit_string_modifier(self, node: StringModifier) -> T:
        """Visit StringModifier node."""

    # Hex tokens
    @abstractmethod
    def visit_hex_token(self, node: HexToken) -> T:
        """Visit HexToken node."""

    @abstractmethod
    def visit_hex_byte(self, node: HexByte) -> T:
        """Visit HexByte node."""

    @abstractmethod
    def visit_hex_wildcard(self, node: HexWildcard) -> T:
        """Visit HexWildcard node."""

    @abstractmethod
    def visit_hex_jump(self, node: HexJump) -> T:
        """Visit HexJump node."""

    @abstractmethod
    def visit_hex_alternative(self, node: HexAlternative) -> T:
        """Visit HexAlternative node."""

    @abstractmethod
    def visit_hex_nibble(self, node) -> T:
        """Visit HexNibble node."""

    # Expressions
    @abstractmethod
    def visit_expression(self, node: Expression) -> T:
        """Visit Expression node."""

    @abstractmethod
    def visit_identifier(self, node: Identifier) -> T:
        """Visit Identifier node."""

    @abstractmethod
    def visit_string_identifier(self, node: StringIdentifier) -> T:
        """Visit StringIdentifier node."""

    @abstractmethod
    def visit_string_count(self, node: StringCount) -> T:
        """Visit StringCount node."""

    @abstractmethod
    def visit_string_offset(self, node: StringOffset) -> T:
        """Visit StringOffset node."""

    @abstractmethod
    def visit_string_length(self, node: StringLength) -> T:
        """Visit StringLength node."""

    @abstractmethod
    def visit_integer_literal(self, node: IntegerLiteral) -> T:
        """Visit IntegerLiteral node."""

    @abstractmethod
    def visit_double_literal(self, node: DoubleLiteral) -> T:
        """Visit DoubleLiteral node."""

    @abstractmethod
    def visit_string_literal(self, node: StringLiteral) -> T:
        """Visit StringLiteral node."""

    @abstractmethod
    def visit_regex_literal(self, node: RegexLiteral) -> T:
        """Visit RegexLiteral node."""

    @abstractmethod
    def visit_boolean_literal(self, node: BooleanLiteral) -> T:
        """Visit BooleanLiteral node."""

    @abstractmethod
    def visit_binary_expression(self, node: BinaryExpression) -> T:
        """Visit BinaryExpression node."""

    @abstractmethod
    def visit_unary_expression(self, node: UnaryExpression) -> T:
        """Visit UnaryExpression node."""

    @abstractmethod
    def visit_parentheses_expression(self, node: ParenthesesExpression) -> T:
        """Visit ParenthesesExpression node."""

    @abstractmethod
    def visit_set_expression(self, node: SetExpression) -> T:
        """Visit SetExpression node."""

    @abstractmethod
    def visit_range_expression(self, node: RangeExpression) -> T:
        """Visit RangeExpression node."""

    @abstractmethod
    def visit_function_call(self, node: FunctionCall) -> T:
        """Visit FunctionCall node."""

    @abstractmethod
    def visit_array_access(self, node: ArrayAccess) -> T:
        """Visit ArrayAccess node."""

    @abstractmethod
    def visit_member_access(self, node: MemberAccess) -> T:
        """Visit MemberAccess node."""

    # Conditions
    @abstractmethod
    def visit_condition(self, node: Condition) -> T:
        """Visit Condition node."""

    @abstractmethod
    def visit_for_expression(self, node: ForExpression) -> T:
        """Visit ForExpression node."""

    @abstractmethod
    def visit_for_of_expression(self, node: ForOfExpression) -> T:
        """Visit ForOfExpression node."""

    @abstractmethod
    def visit_at_expression(self, node: AtExpression) -> T:
        """Visit AtExpression node."""

    @abstractmethod
    def visit_in_expression(self, node: InExpression) -> T:
        """Visit InExpression node."""

    @abstractmethod
    def visit_of_expression(self, node: OfExpression) -> T:
        """Visit OfExpression node."""

    # Meta
    @abstractmethod
    def visit_meta(self, node: Meta) -> T:
        """Visit Meta node."""

    # Modules
    @abstractmethod
    def visit_module_reference(self, node) -> T:
        """Visit ModuleReference node."""

    @abstractmethod
    def visit_dictionary_access(self, node) -> T:
        """Visit DictionaryAccess node."""

    # Comments
    @abstractmethod
    def visit_comment(self, node: Comment) -> T:
        """Visit Comment node."""

    @abstractmethod
    def visit_comment_group(self, node: CommentGroup) -> T:
        """Visit CommentGroup node."""

    # Operators
    @abstractmethod
    def visit_defined_expression(self, node: DefinedExpression) -> T:
        """Visit DefinedExpression node."""

    @abstractmethod
    def visit_string_operator_expression(self, node: StringOperatorExpression) -> T:
        """Visit StringOperatorExpression node."""

    # Extern rules and references
    @abstractmethod
    def visit_extern_rule(self, node: ExternRule) -> T:
        """Visit ExternRule node."""

    @abstractmethod
    def visit_extern_rule_reference(self, node: ExternRuleReference) -> T:
        """Visit ExternRuleReference node."""

    @abstractmethod
    def visit_extern_import(self, node: ExternImport) -> T:
        """Visit ExternImport node."""

    @abstractmethod
    def visit_extern_namespace(self, node: ExternNamespace) -> T:
        """Visit ExternNamespace node."""

    # Pragmas and directives
    @abstractmethod
    def visit_pragma(self, node: Pragma) -> T:
        """Visit Pragma node."""

    @abstractmethod
    def visit_in_rule_pragma(self, node: InRulePragma) -> T:
        """Visit InRulePragma node."""

    @abstractmethod
    def visit_pragma_block(self, node: PragmaBlock) -> T:
        """Visit PragmaBlock node."""


class ASTTransformer(ASTVisitor[ASTNode]):
    """Base transformer class for modifying AST nodes."""

    def visit_yara_file(self, node: YaraFile) -> YaraFile:
        """Transform YaraFile node."""
        from typing import cast

        imports = [self.visit(imp) for imp in node.imports]
        includes = [self.visit(inc) for inc in node.includes]
        rules = cast("list[Rule]", [self.visit(rule) for rule in node.rules])
        extern_rules = cast(
            "list[ExternRule]",
            [self.visit(extern_rule) for extern_rule in node.extern_rules],
        )
        extern_imports = cast(
            "list[ExternImport]",
            [self.visit(extern_import) for extern_import in node.extern_imports],
        )
        pragmas = cast("list[Pragma]", [self.visit(pragma) for pragma in node.pragmas])
        namespaces = [self.visit(namespace) for namespace in node.namespaces]

        return YaraFile(
            imports=imports,
            includes=includes,
            rules=rules,
            extern_rules=extern_rules,
            extern_imports=extern_imports,
            pragmas=pragmas,
            namespaces=namespaces,
        )

    def visit_import(self, node: Import) -> Import:
        """Transform Import node."""
        return Import(module=node.module, location=node.location)

    def visit_include(self, node: Include) -> Include:
        """Transform Include node."""
        return Include(path=node.path, location=node.location)

    def visit_rule(self, node: Rule) -> Rule:
        """Transform Rule node."""
        tags = [self.visit(tag) for tag in node.tags]
        strings = [self.visit(s) for s in node.strings]
        condition = self.visit(node.condition) if node.condition else None
        pragmas = [self.visit(pragma) for pragma in node.pragmas]

        # Handle enhanced meta entries
        meta = node.meta.copy() if isinstance(node.meta, list) else dict(node.meta)

        return Rule(
            name=node.name,
            modifiers=node.modifiers[:],
            tags=tags,
            meta=meta,
            strings=strings,
            condition=condition,
            pragmas=pragmas,
            location=node.location,
        )

    def visit_tag(self, node: Tag) -> Tag:
        """Transform Tag node."""
        return Tag(name=node.name, location=node.location)

    def visit_string_definition(self, node: StringDefinition) -> StringDefinition:
        """Transform StringDefinition node."""
        return node  # Base implementation

    def visit_plain_string(self, node: PlainString) -> PlainString:
        """Transform PlainString node."""
        modifiers = [self.visit(mod) for mod in node.modifiers]
        return PlainString(
            identifier=node.identifier,
            value=node.value,
            modifiers=modifiers,
            location=node.location,
        )

    def visit_hex_string(self, node: HexString) -> HexString:
        """Transform HexString node."""
        tokens = [cast("HexToken", self.visit(token)) for token in node.tokens]
        modifiers = [cast("StringModifier", self.visit(mod)) for mod in node.modifiers]
        return HexString(
            identifier=node.identifier,
            tokens=tokens,
            modifiers=modifiers,
            location=node.location,
        )

    def visit_regex_string(self, node: RegexString) -> RegexString:
        """Transform RegexString node."""
        modifiers = [self.visit(mod) for mod in node.modifiers]
        return RegexString(
            identifier=node.identifier,
            regex=node.regex,
            modifiers=modifiers,
            location=node.location,
        )

    def visit_string_modifier(self, node: StringModifier) -> StringModifier:
        """Transform StringModifier node."""
        return StringModifier(name=node.name, value=node.value, location=node.location)

    def visit_hex_token(self, node: HexToken) -> HexToken:
        """Transform HexToken node."""
        return node  # Base implementation

    def visit_hex_byte(self, node: HexByte) -> HexByte:
        """Transform HexByte node."""
        return HexByte(value=node.value, location=node.location)

    def visit_hex_wildcard(self, node: HexWildcard) -> HexWildcard:
        """Transform HexWildcard node."""
        return HexWildcard(location=node.location)

    def visit_hex_jump(self, node: HexJump) -> HexJump:
        """Transform HexJump node."""
        return HexJump(min_jump=node.min_jump, max_jump=node.max_jump)

    def visit_hex_alternative(self, node: HexAlternative) -> HexAlternative:
        """Transform HexAlternative node."""
        alternatives = [[self.visit(token) for token in alt] for alt in node.alternatives]
        return HexAlternative(alternatives=alternatives, location=node.location)

    def visit_hex_nibble(self, node) -> Any:
        """Transform HexNibble node."""
        from yaraast.builder.hex_string_builder import HexNibble

        return HexNibble(high=node.high, value=node.value, location=node.location)

    def visit_expression(self, node: Expression) -> Expression:
        """Transform Expression node."""
        return node  # Base implementation

    def visit_identifier(self, node: Identifier) -> Identifier:
        """Transform Identifier node."""
        # expressions.Identifier doesn't accept location
        from yaraast.ast.expressions import Identifier as ExprIdentifier

        return ExprIdentifier(name=node.name)

    def visit_string_identifier(self, node: StringIdentifier) -> StringIdentifier:
        """Transform StringIdentifier node."""
        # StringIdentifier doesn't accept location parameter
        return StringIdentifier(name=node.name)

    def visit_string_count(self, node: StringCount) -> StringCount:
        """Transform StringCount node."""
        return StringCount(string_id=node.string_id)

    def visit_string_offset(self, node: StringOffset) -> StringOffset:
        """Transform StringOffset node."""
        index = cast("Expression", self.visit(node.index)) if node.index else None
        return StringOffset(string_id=node.string_id, index=index)

    def visit_string_length(self, node: StringLength) -> StringLength:
        """Transform StringLength node."""
        index = cast("Expression", self.visit(node.index)) if node.index else None
        return StringLength(string_id=node.string_id, index=index)

    def visit_integer_literal(self, node: IntegerLiteral) -> IntegerLiteral:
        """Transform IntegerLiteral node."""
        return IntegerLiteral(value=node.value)

    def visit_double_literal(self, node: DoubleLiteral) -> DoubleLiteral:
        """Transform DoubleLiteral node."""
        return DoubleLiteral(value=node.value)

    def visit_string_literal(self, node: StringLiteral) -> StringLiteral:
        """Transform StringLiteral node."""
        return StringLiteral(value=node.value)

    def visit_regex_literal(self, node: RegexLiteral) -> RegexLiteral:
        """Transform RegexLiteral node."""
        return RegexLiteral(pattern=node.pattern, modifiers=node.modifiers)

    def visit_boolean_literal(self, node: BooleanLiteral) -> BooleanLiteral:
        """Transform BooleanLiteral node."""
        return BooleanLiteral(value=node.value)

    def visit_binary_expression(self, node: BinaryExpression) -> BinaryExpression:
        """Transform BinaryExpression node."""
        from typing import cast

        left = cast("Expression", self.visit(node.left))
        right = cast("Expression", self.visit(node.right))
        # BinaryExpression doesn't accept location parameter
        return BinaryExpression(left=left, operator=node.operator, right=right)

    def visit_unary_expression(self, node: UnaryExpression) -> UnaryExpression:
        """Transform UnaryExpression node."""
        operand = cast("Expression", self.visit(node.operand))
        return UnaryExpression(operator=node.operator, operand=operand)

    def visit_parentheses_expression(
        self,
        node: ParenthesesExpression,
    ) -> ParenthesesExpression:
        """Transform ParenthesesExpression node."""
        from typing import cast

        expression = cast("Expression", self.visit(node.expression))
        return ParenthesesExpression(expression=expression)

    def visit_set_expression(self, node: SetExpression) -> SetExpression:
        """Transform SetExpression node."""
        elements = [self.visit(elem) for elem in node.elements]
        return SetExpression(elements=elements, location=node.location)

    def visit_range_expression(self, node: RangeExpression) -> RangeExpression:
        """Transform RangeExpression node."""
        from typing import cast

        low = cast("Expression", self.visit(node.low))
        high = cast("Expression", self.visit(node.high))
        result = RangeExpression(low=low, high=high)
        result.location = node.location
        return result

    def visit_function_call(self, node: FunctionCall) -> FunctionCall:
        """Transform FunctionCall node."""
        arguments = [cast("Expression", self.visit(arg)) for arg in node.arguments]
        return FunctionCall(function=node.function, arguments=arguments)

    def visit_array_access(self, node: ArrayAccess) -> ArrayAccess:
        """Transform ArrayAccess node."""
        array = self.visit(node.array)
        index = self.visit(node.index)
        return ArrayAccess(array=array, index=index, location=node.location)

    def visit_member_access(self, node: MemberAccess) -> MemberAccess:
        """Transform MemberAccess node."""
        obj = self.visit(node.object)
        # Ensure obj is an Expression
        if not isinstance(obj, Expression):
            obj = cast("Expression", obj)
        return MemberAccess(object=obj, member=node.member)

    def visit_condition(self, node: Condition) -> Condition:
        """Transform Condition node."""
        return node  # Base implementation

    def visit_for_expression(self, node: ForExpression) -> ForExpression:
        """Transform ForExpression node."""
        iterable = self.visit(node.iterable)
        body = self.visit(node.body)
        return ForExpression(
            quantifier=node.quantifier,
            variable=node.variable,
            iterable=iterable,
            body=body,
            location=node.location,
        )

    def visit_for_of_expression(self, node: ForOfExpression) -> ForOfExpression:
        """Transform ForOfExpression node."""
        string_set = self.visit(node.string_set)
        condition = self.visit(node.condition) if node.condition else None
        return ForOfExpression(
            quantifier=node.quantifier,
            string_set=string_set,
            condition=condition,
            location=node.location,
        )

    def visit_at_expression(self, node: AtExpression) -> AtExpression:
        """Transform AtExpression node."""
        offset = cast("Expression", self.visit(node.offset))
        return AtExpression(string_id=node.string_id, offset=offset)

    def visit_in_expression(self, node: InExpression) -> InExpression:
        """Transform InExpression node."""
        range_expr = cast("Expression", self.visit(node.range))
        return InExpression(string_id=node.string_id, range=range_expr)

    def visit_of_expression(self, node: OfExpression) -> OfExpression:
        """Transform OfExpression node."""
        quantifier = cast("Expression", self.visit(node.quantifier))
        string_set = cast("Expression", self.visit(node.string_set))
        return OfExpression(quantifier=quantifier, string_set=string_set)

    def visit_meta(self, node: Meta) -> Meta:
        """Transform Meta node."""
        return Meta(key=node.key, value=node.value, location=node.location)

    def visit_module_reference(self, node) -> Any:
        """Transform ModuleReference node."""
        from yaraast.ast.modules import ModuleReference

        return ModuleReference(module=node.module, location=node.location)

    def visit_dictionary_access(self, node) -> Any:
        """Transform DictionaryAccess node."""
        from yaraast.ast.modules import DictionaryAccess

        obj = self.visit(node.object)
        key = self.visit(node.key) if isinstance(node.key, Expression) else node.key
        return DictionaryAccess(object=obj, key=key, location=node.location)

    def visit_comment(self, node: Comment) -> Comment:
        """Transform Comment node."""
        return Comment(text=node.text, is_multiline=node.is_multiline)

    def visit_comment_group(self, node: CommentGroup) -> CommentGroup:
        """Transform CommentGroup node."""
        comments = [self.visit(comment) for comment in node.comments]
        return CommentGroup(comments=comments)

    def visit_defined_expression(self, node: DefinedExpression) -> DefinedExpression:
        """Transform DefinedExpression node."""
        expression = self.visit(node.expression)
        return DefinedExpression(expression=expression)

    def visit_string_operator_expression(
        self,
        node: StringOperatorExpression,
    ) -> StringOperatorExpression:
        """Transform StringOperatorExpression node."""
        left = self.visit(node.left)
        right = self.visit(node.right)
        return StringOperatorExpression(left=left, operator=node.operator, right=right)

    # Extern rules and references
    def visit_extern_rule(self, node: ExternRule) -> ExternRule:
        """Transform ExternRule node."""
        return ExternRule(
            name=node.name,
            modifiers=node.modifiers[:],
            namespace=node.namespace,
            location=node.location,
        )

    def visit_extern_rule_reference(
        self,
        node: ExternRuleReference,
    ) -> ExternRuleReference:
        """Transform ExternRuleReference node."""
        return ExternRuleReference(
            rule_name=node.rule_name,
            namespace=node.namespace,
            location=node.location,
        )

    def visit_extern_import(self, node: ExternImport) -> ExternImport:
        """Transform ExternImport node."""
        return ExternImport(
            module_path=node.module_path,
            alias=node.alias,
            namespace=node.namespace,
            location=node.location,
        )

    def visit_extern_namespace(self, node: ExternNamespace) -> ExternNamespace:
        """Transform ExternNamespace node."""
        return ExternNamespace(name=node.name, location=node.location)

    # Pragmas and directives
    def visit_pragma(self, node: Pragma) -> Pragma:
        """Transform Pragma node."""
        return Pragma(
            pragma_type=node.pragma_type,
            name=node.name,
            arguments=node.arguments[:],
            scope=node.scope,
            location=node.location,
        )

    def visit_in_rule_pragma(self, node: InRulePragma) -> InRulePragma:
        """Transform InRulePragma node."""
        pragma = cast("Pragma", self.visit(node.pragma))
        return InRulePragma(pragma=pragma, position=node.position)

    def visit_pragma_block(self, node: PragmaBlock) -> PragmaBlock:
        """Transform PragmaBlock node."""
        pragmas = [self.visit(pragma) for pragma in node.pragmas]
        return PragmaBlock(pragmas=pragmas, scope=node.scope, location=node.location)
