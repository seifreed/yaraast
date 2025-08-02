"""String usage analyzer for YARA rules."""

from typing import Dict, List, Optional, Set, Tuple

from yaraast.ast.base import YaraFile
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
    SetExpression,
    StringCount,
    StringIdentifier,
    StringLength,
    StringLiteral,
    StringOffset,
    UnaryExpression,
)
from yaraast.ast.meta import Meta
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
from yaraast.visitor import ASTVisitor


class StringUsageAnalyzer(ASTVisitor[None]):
    """Analyze string usage in YARA rules."""

    def __init__(self):
        self.defined_strings: Dict[str, Set[str]] = {}  # rule_name -> set of string ids
        self.used_strings: Dict[str, Set[str]] = {}     # rule_name -> set of string ids
        self.current_rule: Optional[str] = None
        self.in_condition: bool = False

    def analyze(self, yara_file: YaraFile) -> Dict[str, Dict[str, any]]:
        """Analyze string usage in YARA file."""
        self.defined_strings.clear()
        self.used_strings.clear()

        self.visit(yara_file)

        # Build analysis results
        results = {}
        for rule_name in self.defined_strings:
            defined = self.defined_strings.get(rule_name, set())
            used = self.used_strings.get(rule_name, set())

            unused = defined - used
            undefined = used - defined

            results[rule_name] = {
                "defined": list(defined),
                "used": list(used),
                "unused": list(unused),
                "undefined": list(undefined),
                "usage_rate": len(used) / len(defined) if defined else 0
            }

        return results

    def get_unused_strings(self, rule_name: Optional[str] = None) -> Dict[str, List[str]]:
        """Get unused strings for a specific rule or all rules."""
        if rule_name:
            defined = self.defined_strings.get(rule_name, set())
            used = self.used_strings.get(rule_name, set())
            return {rule_name: list(defined - used)}

        unused = {}
        for rule in self.defined_strings:
            defined = self.defined_strings[rule]
            used = self.used_strings.get(rule, set())
            unused_in_rule = list(defined - used)
            if unused_in_rule:
                unused[rule] = unused_in_rule

        return unused

    def get_undefined_strings(self, rule_name: Optional[str] = None) -> Dict[str, List[str]]:
        """Get undefined but used strings for a specific rule or all rules."""
        if rule_name:
            defined = self.defined_strings.get(rule_name, set())
            used = self.used_strings.get(rule_name, set())
            return {rule_name: list(used - defined)}

        undefined = {}
        for rule in self.used_strings:
            defined = self.defined_strings.get(rule, set())
            used = self.used_strings[rule]
            undefined_in_rule = list(used - defined)
            if undefined_in_rule:
                undefined[rule] = undefined_in_rule

        return undefined

    # Visitor methods
    def visit_yara_file(self, node: YaraFile) -> None:
        for rule in node.rules:
            self.visit(rule)

    def visit_rule(self, node: Rule) -> None:
        self.current_rule = node.name
        self.defined_strings[node.name] = set()
        self.used_strings[node.name] = set()
        self.in_condition = False

        # Visit strings section
        for string in node.strings:
            self.visit(string)

        # Visit condition section
        self.in_condition = True
        self.visit(node.condition)
        self.in_condition = False

        self.current_rule = None

    def visit_string_definition(self, node: StringDefinition) -> None:
        if self.current_rule:
            self.defined_strings[self.current_rule].add(node.identifier)

    def visit_plain_string(self, node: PlainString) -> None:
        self.visit_string_definition(node)

    def visit_hex_string(self, node: HexString) -> None:
        self.visit_string_definition(node)

    def visit_regex_string(self, node: RegexString) -> None:
        self.visit_string_definition(node)

    def visit_string_identifier(self, node: StringIdentifier) -> None:
        if self.current_rule and self.in_condition:
            self.used_strings[self.current_rule].add(node.name)

    def visit_string_count(self, node: StringCount) -> None:
        if self.current_rule and self.in_condition:
            self.used_strings[self.current_rule].add(node.string_id)

    def visit_string_offset(self, node: StringOffset) -> None:
        if self.current_rule and self.in_condition:
            self.used_strings[self.current_rule].add(node.string_id)

    def visit_string_length(self, node: StringLength) -> None:
        if self.current_rule and self.in_condition:
            self.used_strings[self.current_rule].add(node.string_id)

    def visit_at_expression(self, node: AtExpression) -> None:
        if self.current_rule and self.in_condition:
            self.used_strings[self.current_rule].add(node.string_id)
        self.visit(node.offset)

    def visit_in_expression(self, node: InExpression) -> None:
        if self.current_rule and self.in_condition:
            self.used_strings[self.current_rule].add(node.string_id)
        self.visit(node.range)

    def visit_for_of_expression(self, node: ForOfExpression) -> None:
        # Handle "them" keyword
        if isinstance(node.string_set, Identifier) and node.string_set.name == "them":
            # "them" refers to all defined strings
            if self.current_rule:
                self.used_strings[self.current_rule].update(self.defined_strings[self.current_rule])
        else:
            self.visit(node.string_set)

        if node.condition:
            self.visit(node.condition)

    def visit_of_expression(self, node: OfExpression) -> None:
        self.visit(node.quantifier)
        self.visit(node.string_set)

    def visit_set_expression(self, node: SetExpression) -> None:
        for element in node.elements:
            self.visit(element)

    # Default implementations for other visit methods
    def visit_import(self, node: Import) -> None: pass
    def visit_include(self, node: Include) -> None: pass
    def visit_tag(self, node: Tag) -> None: pass
    def visit_string_modifier(self, node: StringModifier) -> None: pass
    def visit_hex_token(self, node: HexToken) -> None: pass
    def visit_hex_byte(self, node: HexByte) -> None: pass
    def visit_hex_wildcard(self, node: HexWildcard) -> None: pass
    def visit_hex_jump(self, node: HexJump) -> None: pass
    def visit_hex_alternative(self, node: HexAlternative) -> None: pass
    def visit_hex_nibble(self, node: HexNibble) -> None: pass
    def visit_expression(self, node: Expression) -> None: pass
    def visit_identifier(self, node: Identifier) -> None: pass
    def visit_integer_literal(self, node: IntegerLiteral) -> None: pass
    def visit_double_literal(self, node: DoubleLiteral) -> None: pass
    def visit_string_literal(self, node: StringLiteral) -> None: pass
    def visit_boolean_literal(self, node: BooleanLiteral) -> None: pass
    def visit_meta(self, node: Meta) -> None: pass
    def visit_meta_statement(self, node) -> None: pass
    def visit_condition(self, node) -> None: pass
    def visit_comment(self, node) -> None: pass
    def visit_comment_group(self, node) -> None: pass
    def visit_module_reference(self, node) -> None: pass
    def visit_dictionary_access(self, node) -> None: pass

    def visit_binary_expression(self, node: BinaryExpression) -> None:
        self.visit(node.left)
        self.visit(node.right)

    def visit_unary_expression(self, node: UnaryExpression) -> None:
        self.visit(node.operand)

    def visit_parentheses_expression(self, node: ParenthesesExpression) -> None:
        self.visit(node.expression)

    def visit_range_expression(self, node: RangeExpression) -> None:
        self.visit(node.low)
        self.visit(node.high)

    def visit_function_call(self, node: FunctionCall) -> None:
        for arg in node.arguments:
            self.visit(arg)

    def visit_array_access(self, node: ArrayAccess) -> None:
        self.visit(node.array)
        self.visit(node.index)

    def visit_member_access(self, node: MemberAccess) -> None:
        self.visit(node.object)

    def visit_for_expression(self, node: ForExpression) -> None:
        self.visit(node.iterable)
        self.visit(node.body)

    def visit_defined_expression(self, node) -> None: pass
    def visit_string_operator_expression(self, node) -> None: pass
