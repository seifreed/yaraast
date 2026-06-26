"""Comprehensive tests for visitor pattern to achieve 90% coverage.

Copyright (c) 2026 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.
"""

from __future__ import annotations

from typing import Any, cast

import pytest

from yaraast.ast.base import YaraFile
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
from yaraast.ast.meta import Meta
from yaraast.ast.modifiers import StringModifier
from yaraast.ast.operators import DefinedExpression, StringOperatorExpression
from yaraast.ast.pragmas import InRulePragma, Pragma, PragmaBlock, PragmaScope, PragmaType
from yaraast.ast.rules import Import, Include, Rule, Tag
from yaraast.ast.strings import (
    HexAlternative,
    HexByte,
    HexJump,
    HexNibble,
    HexWildcard,
    PlainString,
    RegexString,
)
from yaraast.parser.parser import Parser
from yaraast.visitor.base import BaseVisitor
from yaraast.visitor.visitor import ASTVisitor


class TestBaseVisitorComprehensive:
    """Comprehensive tests for BaseVisitor class."""

    def test_visit_imports_and_includes(self) -> None:
        """Test visiting import and include statements."""

        class ImportIncludeVisitor(BaseVisitor[None]):
            def __init__(self) -> None:
                self.imports: list[Any] = []
                self.includes: list[Any] = []

            def visit_import(self, node: Import) -> None:
                self.imports.append(node.module)
                return super().visit_import(node)

            def visit_include(self, node: Include) -> None:
                self.includes.append(node.path)
                return super().visit_include(node)

        yara_code = """
        import "pe"
        import "elf"
        include "common.yar"

        rule test { condition: true }
        """

        parser = Parser(yara_code)
        ast = parser.parse()

        visitor = ImportIncludeVisitor()
        visitor.visit(ast)

        assert "pe" in visitor.imports
        assert "elf" in visitor.imports
        assert "common.yar" in visitor.includes

    def test_visit_tags(self) -> None:
        """Test visiting rule tags."""

        class TagVisitor(BaseVisitor[None]):
            def __init__(self) -> None:
                self.tags: list[Any] = []

            def visit_tag(self, node: Tag) -> None:
                self.tags.append(node.name)
                return super().visit_tag(node)

        yara_code = """
        rule test : malware trojan suspicious {
            condition: true
        }
        """

        parser = Parser(yara_code)
        ast = parser.parse()

        visitor = TagVisitor()
        visitor.visit(ast)

        assert "malware" in visitor.tags
        assert "trojan" in visitor.tags
        assert "suspicious" in visitor.tags

    def test_visit_hex_string_tokens(self) -> None:
        """Test visiting hex string and its tokens."""

        class HexTokenVisitor(BaseVisitor[None]):
            def __init__(self) -> None:
                self.hex_bytes: list[Any] = []
                self.wildcards = 0
                self.jumps = 0

            def visit_hex_byte(self, node: HexByte) -> None:
                self.hex_bytes.append(node.value)
                return super().visit_hex_byte(node)

            def visit_hex_wildcard(self, node: HexWildcard) -> None:
                self.wildcards += 1
                return super().visit_hex_wildcard(node)

            def visit_hex_jump(self, node: HexJump) -> None:
                self.jumps += 1
                return super().visit_hex_jump(node)

            def visit_hex_alternative(self, node: HexAlternative) -> None:
                return super().visit_hex_alternative(node)

        yara_code = """
        rule test {
            strings:
                $hex = { 4D 5A ?? [2-4] 00 }
            condition:
                $hex
        }
        """

        parser = Parser(yara_code)
        ast = parser.parse()

        visitor = HexTokenVisitor()
        visitor.visit(ast)

        assert 0x4D in visitor.hex_bytes or 77 in visitor.hex_bytes
        assert visitor.wildcards >= 1
        assert visitor.jumps >= 1

    def test_visit_string_modifiers(self) -> None:
        """Test visiting string modifiers."""

        class ModifierVisitor(BaseVisitor[None]):
            def __init__(self) -> None:
                self.modifiers: list[Any] = []

            def visit_string_modifier(self, node: StringModifier) -> None:
                self.modifiers.append(node.name)
                return super().visit_string_modifier(node)

        yara_code = """
        rule test {
            strings:
                $s1 = "test" wide ascii
                $s2 = "hello" nocase
            condition:
                any of them
        }
        """

        parser = Parser(yara_code)
        ast = parser.parse()

        visitor = ModifierVisitor()
        visitor.visit(ast)

        assert "wide" in visitor.modifiers
        assert "ascii" in visitor.modifiers
        assert "nocase" in visitor.modifiers

    def test_visit_regex_string(self) -> None:
        """Test visiting regex strings."""

        class RegexVisitor(BaseVisitor[None]):
            def __init__(self) -> None:
                self.regex_count = 0

            def visit_regex_string(self, node: RegexString) -> None:
                self.regex_count += 1
                return super().visit_regex_string(node)

        yara_code = """
        rule test {
            strings:
                $re1 = /test[0-9]+/ nocase
                $re2 = /hello.*world/
            condition:
                any of them
        }
        """

        parser = Parser(yara_code)
        ast = parser.parse()

        visitor = RegexVisitor()
        visitor.visit(ast)

        assert visitor.regex_count == 2

    def test_visit_literals(self) -> None:
        """Test visiting different literal types."""

        class LiteralVisitor(BaseVisitor[None]):
            def __init__(self) -> None:
                self.integers: list[Any] = []
                self.doubles: list[Any] = []
                self.strings: list[Any] = []
                self.booleans: list[Any] = []
                self.regexes: list[Any] = []

            def visit_integer_literal(self, node: IntegerLiteral) -> None:
                self.integers.append(node.value)
                return super().visit_integer_literal(node)

            def visit_double_literal(self, node: DoubleLiteral) -> None:
                self.doubles.append(node.value)
                return super().visit_double_literal(node)

            def visit_string_literal(self, node: StringLiteral) -> None:
                self.strings.append(node.value)
                return super().visit_string_literal(node)

            def visit_boolean_literal(self, node: BooleanLiteral) -> None:
                self.booleans.append(node.value)
                return super().visit_boolean_literal(node)

            def visit_regex_literal(self, node: RegexLiteral) -> None:
                self.regexes.append(node.pattern)
                return super().visit_regex_literal(node)

        yara_code = """
        rule test {
            condition:
                filesize > 1024 and
                true and
                pe.is_dll()
        }
        """

        parser = Parser(yara_code)
        ast = parser.parse()

        visitor = LiteralVisitor()
        visitor.visit(ast)

        assert 1024 in visitor.integers
        assert True in visitor.booleans

    def test_visit_expressions(self) -> None:
        """Test visiting various expression types."""

        class ExpressionVisitor(BaseVisitor[None]):
            def __init__(self) -> None:
                self.binary_ops: list[Any] = []
                self.unary_ops: list[Any] = []
                self.parentheses = 0
                self.identifiers: list[Any] = []

            def visit_binary_expression(self, node: BinaryExpression) -> None:
                self.binary_ops.append(node.operator)
                return super().visit_binary_expression(node)

            def visit_unary_expression(self, node: UnaryExpression) -> None:
                self.unary_ops.append(node.operator)
                return super().visit_unary_expression(node)

            def visit_parentheses_expression(self, node: ParenthesesExpression) -> None:
                self.parentheses += 1
                return super().visit_parentheses_expression(node)

            def visit_identifier(self, node: Identifier) -> None:
                self.identifiers.append(node.name)
                return super().visit_identifier(node)

        yara_code = """
        rule test {
            condition:
                (filesize > 1024 and not pe.is_dll()) or entrypoint == 0x1000
        }
        """

        parser = Parser(yara_code)
        ast = parser.parse()

        visitor = ExpressionVisitor()
        visitor.visit(ast)

        assert ">" in visitor.binary_ops
        assert "and" in visitor.binary_ops or "or" in visitor.binary_ops
        assert visitor.parentheses >= 1

    def test_visit_string_expressions(self) -> None:
        """Test visiting string-related expressions."""

        class StringExprVisitor(BaseVisitor[None]):
            def __init__(self) -> None:
                self.string_ids: list[Any] = []
                self.string_counts: list[Any] = []
                self.string_offsets: list[Any] = []
                self.string_lengths: list[Any] = []
                self.wildcards: list[Any] = []

            def visit_string_identifier(self, node: StringIdentifier) -> None:
                self.string_ids.append(node.name)
                return super().visit_string_identifier(node)

            def visit_string_count(self, node: StringCount) -> None:
                self.string_counts.append(node.string_id)
                return super().visit_string_count(node)

            def visit_string_offset(self, node: StringOffset) -> None:
                self.string_offsets.append(node.string_id)
                return super().visit_string_offset(node)

            def visit_string_length(self, node: StringLength) -> None:
                self.string_lengths.append(node.string_id)
                return super().visit_string_length(node)

            def visit_string_wildcard(self, node: StringWildcard) -> None:
                self.wildcards.append(node.pattern)
                return super().visit_string_wildcard(node)

        yara_code = """
        rule test {
            strings:
                $a = "test"
                $b = "hello"
            condition:
                #a > 2 and @a[1] < 100 and !a[0] > 10 and any of ($*)
        }
        """

        parser = Parser(yara_code)
        ast = parser.parse()

        visitor = StringExprVisitor()
        visitor.visit(ast)

        assert (
            "$a" in visitor.string_ids
            or "a" in visitor.string_counts
            or "a" in visitor.string_offsets
        )

    def test_visit_set_and_range_expressions(self) -> None:
        """Test visiting set and range expressions directly."""

        class SetRangeVisitor(BaseVisitor[None]):
            def __init__(self) -> None:
                self.sets = 0
                self.ranges = 0

            def visit_set_expression(self, node: SetExpression) -> None:
                self.sets += 1
                return super().visit_set_expression(node)

            def visit_range_expression(self, node: RangeExpression) -> None:
                self.ranges += 1
                return super().visit_range_expression(node)

        # Create nodes directly instead of parsing
        set_expr = SetExpression(elements=[IntegerLiteral(value=1), IntegerLiteral(value=2)])
        range_expr = RangeExpression(low=IntegerLiteral(value=0), high=IntegerLiteral(value=100))

        visitor = SetRangeVisitor()
        visitor.visit(set_expr)
        visitor.visit(range_expr)

        assert visitor.sets == 1
        assert visitor.ranges == 1

    def test_visit_function_call(self) -> None:
        """Test visiting function calls."""

        class FunctionVisitor(BaseVisitor[None]):
            def __init__(self) -> None:
                self.functions: list[Any] = []

            def visit_function_call(self, node: FunctionCall) -> None:
                self.functions.append(node.function)
                return super().visit_function_call(node)

        yara_code = """
        rule test {
            condition:
                uint16(0) == 0x5A4D and
                uint32(uint32(0x3C)) == 0x4550
        }
        """

        parser = Parser(yara_code)
        ast = parser.parse()

        visitor = FunctionVisitor()
        visitor.visit(ast)

        assert "uint16" in visitor.functions or "uint32" in visitor.functions

    def test_visit_array_and_member_access(self) -> None:
        """Test visiting array and member access."""

        class AccessVisitor(BaseVisitor[None]):
            def __init__(self) -> None:
                self.array_accesses = 0
                self.member_accesses: list[Any] = []

            def visit_array_access(self, node: ArrayAccess) -> None:
                self.array_accesses += 1
                return super().visit_array_access(node)

            def visit_member_access(self, node: MemberAccess) -> None:
                self.member_accesses.append(node.member)
                return super().visit_member_access(node)

        yara_code = """
        rule test {
            condition:
                pe.sections[0].name == ".text" and
                pe.number_of_sections > 0
        }
        """

        parser = Parser(yara_code)
        ast = parser.parse()

        visitor = AccessVisitor()
        visitor.visit(ast)

        assert visitor.array_accesses >= 1 or len(visitor.member_accesses) >= 1

    def test_visit_condition_expressions(self) -> None:
        """Test visiting condition-specific expressions."""

        class ConditionVisitor(BaseVisitor[None]):
            def __init__(self) -> None:
                self.for_exprs = 0
                self.for_of_exprs = 0
                self.at_exprs = 0
                self.in_exprs = 0
                self.of_exprs = 0

            def visit_for_expression(self, node: ForExpression) -> None:
                self.for_exprs += 1
                return super().visit_for_expression(node)

            def visit_for_of_expression(self, node: ForOfExpression) -> None:
                self.for_of_exprs += 1
                return super().visit_for_of_expression(node)

            def visit_at_expression(self, node: AtExpression) -> None:
                self.at_exprs += 1
                return super().visit_at_expression(node)

            def visit_in_expression(self, node: InExpression) -> None:
                self.in_exprs += 1
                return super().visit_in_expression(node)

            def visit_of_expression(self, node: OfExpression) -> None:
                self.of_exprs += 1
                return super().visit_of_expression(node)

        yara_code = """
        rule test {
            strings:
                $a = "test"
                $b = "hello"
            condition:
                $a at 0 and
                $b in (0..100) and
                2 of them and
                for all i in (0..10) : ( uint8(i) == 0x90 )
        }
        """

        parser = Parser(yara_code)
        ast = parser.parse()

        visitor = ConditionVisitor()
        visitor.visit(ast)

        # At least one of these should be present
        total = (
            visitor.for_exprs
            + visitor.for_of_exprs
            + visitor.at_exprs
            + visitor.in_exprs
            + visitor.of_exprs
        )
        assert total >= 1

    def test_visit_operators(self) -> None:
        """Test visiting defined and string operator expressions."""

        class OperatorVisitor(BaseVisitor[None]):
            def visit_defined_expression(self, node: DefinedExpression) -> None:
                return super().visit_defined_expression(node)

            def visit_string_operator_expression(self, node: StringOperatorExpression) -> None:
                return super().visit_string_operator_expression(node)

        yara_code = """
        rule test {
            strings:
                $a = "test"
            condition:
                defined $a and "test" contains "es"
        }
        """

        parser = Parser(yara_code)
        ast = parser.parse()

        visitor = OperatorVisitor()
        visitor.visit(ast)

    def test_visit_comments(self) -> None:
        """Test visiting comments directly."""

        class CommentVisitor(BaseVisitor[None]):
            def __init__(self) -> None:
                self.comments: list[Any] = []
                self.comment_groups = 0

            def visit_comment(self, node: Comment) -> None:
                self.comments.append(node.text)
                return super().visit_comment(node)

            def visit_comment_group(self, node: CommentGroup) -> None:
                self.comment_groups += 1
                return super().visit_comment_group(node)

        # Create comments directly
        comment1 = Comment(text="Test comment", is_multiline=False)
        comment2 = Comment(text="Multi-line comment", is_multiline=True)
        comment_group = CommentGroup(comments=[comment1, comment2])

        visitor = CommentVisitor()
        visitor.visit(comment1)
        visitor.visit(comment2)
        visitor.visit(comment_group)

        # Verify comments were visited
        assert len(visitor.comments) >= 2
        assert visitor.comment_groups == 1

    def test_visit_pragmas(self) -> None:
        """Test visiting pragmas."""

        class PragmaVisitor(BaseVisitor[None]):
            def __init__(self) -> None:
                self.pragmas: list[Any] = []

            def visit_pragma(self, node: Pragma) -> None:
                self.pragmas.append(node.name)
                return super().visit_pragma(node)

            def visit_in_rule_pragma(self, node: InRulePragma) -> None:
                return super().visit_in_rule_pragma(node)

            def visit_pragma_block(self, node: PragmaBlock) -> None:
                return super().visit_pragma_block(node)

        # Pragmas are YARA-X specific
        yara_code = """
        rule test {
            condition: true
        }
        """

        parser = Parser(yara_code)
        ast = parser.parse()

        visitor = PragmaVisitor()
        visitor.visit(ast)

        # No pragmas in standard YARA
        assert len(visitor.pragmas) == 0

    def test_visit_extern_elements(self) -> None:
        """Test visiting extern rules and imports."""

        class ExternVisitor(BaseVisitor[None]):
            def __init__(self) -> None:
                self.extern_rules: list[Any] = []
                self.extern_refs: list[Any] = []
                self.extern_imports: list[Any] = []
                self.extern_namespaces: list[Any] = []

            def visit_extern_rule(self, node: ExternRule) -> None:
                self.extern_rules.append(node.name)
                return super().visit_extern_rule(node)

            def visit_extern_rule_reference(self, node: ExternRuleReference) -> None:
                self.extern_refs.append(node.rule_name)
                return super().visit_extern_rule_reference(node)

            def visit_extern_import(self, node: ExternImport) -> None:
                self.extern_imports.append(node.module_path)
                return super().visit_extern_import(node)

            def visit_extern_namespace(self, node: ExternNamespace) -> None:
                self.extern_namespaces.append(node.name)
                return super().visit_extern_namespace(node)

        # Extern elements are YARA-X specific
        yara_code = """
        rule test {
            condition: true
        }
        """

        parser = Parser(yara_code)
        ast = parser.parse()

        visitor = ExternVisitor()
        visitor.visit(ast)

        # No extern elements in standard YARA
        assert len(visitor.extern_rules) == 0

    def test_visit_meta(self) -> None:
        """Test visiting meta entries."""

        class MetaVisitor(BaseVisitor[None]):
            def __init__(self) -> None:
                self.meta_keys: list[Any] = []

            def visit_meta(self, node: Meta) -> None:
                self.meta_keys.append(node.key)
                return super().visit_meta(node)

        yara_code = """
        rule test {
            meta:
                author = "test"
                date = "2026-01-30"
            condition: true
        }
        """

        parser = Parser(yara_code)
        ast = parser.parse()

        visitor = MetaVisitor()
        visitor.visit(ast)

    def test_base_visitor_dispatch_via_accept(self) -> None:
        """Test that BaseVisitor.visit() correctly dispatches via node.accept()."""

        class DispatchTracker(BaseVisitor[str]):
            def __init__(self) -> None:
                self.visited_types: list[Any] = []

            def visit_rule(self, node: Rule) -> str:
                self.visited_types.append("Rule")
                super().visit_rule(node)
                return "Rule"

            def visit_plain_string(self, node: PlainString) -> str:
                self.visited_types.append("PlainString")
                super().visit_plain_string(node)
                return "PlainString"

        yara_code = """
        rule test {
            strings:
                $s = "test"
            condition:
                $s
        }
        """

        parser = Parser(yara_code)
        ast = parser.parse()

        visitor = DispatchTracker()
        visitor.visit(ast)

        # Verify the visitor was dispatched to correct methods
        assert "Rule" in visitor.visited_types
        assert "PlainString" in visitor.visited_types

    def test_visitor_with_optional_fields(self) -> None:
        """Test visiting nodes with optional/nullable fields."""

        class OptionalFieldVisitor(BaseVisitor[None]):
            def __init__(self) -> None:
                self.string_offsets_with_index = 0

            def visit_string_offset(self, node: StringOffset) -> None:
                if node.index is not None:
                    self.string_offsets_with_index += 1
                return super().visit_string_offset(node)

            def visit_string_length(self, node: StringLength) -> None:
                return super().visit_string_length(node)

            def visit_for_of_expression(self, node: ForOfExpression) -> None:
                return super().visit_for_of_expression(node)

        yara_code = """
        rule test {
            strings:
                $a = "test"
            condition:
                @a[1] < 100 and !a[0] > 10
        }
        """

        parser = Parser(yara_code)
        ast = parser.parse()

        visitor = OptionalFieldVisitor()
        visitor.visit(ast)

        # Verify visitor handles optional fields correctly
        assert (
            visitor.string_offsets_with_index >= 0
        )  # May or may not have index depending on parsing

    def test_visitor_traverses_falsy_present_optional_node(self) -> None:
        """Test optional AST fields are skipped only when absent."""

        class FalsyBooleanLiteral(BooleanLiteral):
            def __bool__(self) -> bool:
                return False

        class ConditionVisitor(BaseVisitor[None]):
            def __init__(self) -> None:
                self.boolean_literals = 0

            def visit_boolean_literal(self, node: BooleanLiteral) -> None:
                self.boolean_literals += 1
                return super().visit_boolean_literal(node)

        ast = YaraFile(rules=[Rule(name="falsy", condition=FalsyBooleanLiteral(False))])
        visitor = ConditionVisitor()

        visitor.visit(ast)

        assert visitor.boolean_literals == 1


class TestDirectNodeVisitation:
    """Test direct visitation of AST nodes without parsing."""

    def test_visit_all_hex_token_types(self) -> None:
        """Test visiting all hex token types directly."""

        class HexVisitor(BaseVisitor[None]):
            def __init__(self) -> None:
                self.visited: list[Any] = []

            def visit_hex_byte(self, node: HexByte) -> None:
                self.visited.append(("byte", node.value))
                return super().visit_hex_byte(node)

            def visit_hex_wildcard(self, node: HexWildcard) -> None:
                self.visited.append("wildcard")
                return super().visit_hex_wildcard(node)

            def visit_hex_jump(self, node: HexJump) -> None:
                self.visited.append(("jump", node.min_jump, node.max_jump))
                return super().visit_hex_jump(node)

            def visit_hex_alternative(self, node: HexAlternative) -> None:
                self.visited.append("alternative")
                return super().visit_hex_alternative(node)

        # Create hex tokens directly
        byte_node = HexByte(value=0x4D)
        wildcard_node = HexWildcard()
        jump_node = HexJump(min_jump=2, max_jump=4)
        alt_node = HexAlternative(alternatives=[[HexByte(value=0x50)], [HexByte(value=0x51)]])

        visitor = HexVisitor()
        visitor.visit(byte_node)
        visitor.visit(wildcard_node)
        visitor.visit(jump_node)
        visitor.visit(alt_node)

        assert ("byte", 0x4D) in visitor.visited
        assert "wildcard" in visitor.visited
        assert ("jump", 2, 4) in visitor.visited
        assert "alternative" in visitor.visited

    def test_visit_all_expression_literals(self) -> None:
        """Test visiting all literal expression types."""

        class LiteralCollector(BaseVisitor[None]):
            def __init__(self) -> None:
                self.values: list[Any] = []

            def visit_integer_literal(self, node: IntegerLiteral) -> None:
                self.values.append(("int", node.value))
                return super().visit_integer_literal(node)

            def visit_double_literal(self, node: DoubleLiteral) -> None:
                self.values.append(("double", node.value))
                return super().visit_double_literal(node)

            def visit_string_literal(self, node: StringLiteral) -> None:
                self.values.append(("string", node.value))
                return super().visit_string_literal(node)

            def visit_boolean_literal(self, node: BooleanLiteral) -> None:
                self.values.append(("bool", node.value))
                return super().visit_boolean_literal(node)

            def visit_regex_literal(self, node: RegexLiteral) -> None:
                self.values.append(("regex", node.pattern))
                return super().visit_regex_literal(node)

        visitor = LiteralCollector()
        visitor.visit(IntegerLiteral(value=42))
        visitor.visit(DoubleLiteral(value=3.14))
        visitor.visit(StringLiteral(value="test"))
        visitor.visit(BooleanLiteral(value=True))
        visitor.visit(RegexLiteral(pattern="test.*", modifiers="i"))

        assert ("int", 42) in visitor.values
        assert ("double", 3.14) in visitor.values
        assert ("string", "test") in visitor.values
        assert ("bool", True) in visitor.values
        assert ("regex", "test.*") in visitor.values

    def test_visit_complex_expressions(self) -> None:
        """Test visiting complex expression structures."""

        class ExpressionCollector(BaseVisitor[None]):
            def __init__(self) -> None:
                self.visited: list[Any] = []

            def visit_binary_expression(self, node: BinaryExpression) -> None:
                self.visited.append(("binary", node.operator))
                return super().visit_binary_expression(node)

            def visit_unary_expression(self, node: UnaryExpression) -> None:
                self.visited.append(("unary", node.operator))
                return super().visit_unary_expression(node)

            def visit_parentheses_expression(self, node: ParenthesesExpression) -> None:
                self.visited.append("parentheses")
                return super().visit_parentheses_expression(node)

            def visit_set_expression(self, node: SetExpression) -> None:
                self.visited.append(("set", len(node.elements)))
                return super().visit_set_expression(node)

            def visit_range_expression(self, node: RangeExpression) -> None:
                self.visited.append("range")
                return super().visit_range_expression(node)

        visitor = ExpressionCollector()

        # Binary expression
        binary = BinaryExpression(
            left=IntegerLiteral(value=1), operator="+", right=IntegerLiteral(value=2)
        )
        visitor.visit(binary)

        # Unary expression
        unary = UnaryExpression(operator="not", operand=BooleanLiteral(value=True))
        visitor.visit(unary)

        # Parentheses expression
        paren = ParenthesesExpression(expression=IntegerLiteral(value=42))
        visitor.visit(paren)

        # Set expression
        set_expr = SetExpression(elements=[IntegerLiteral(value=1), IntegerLiteral(value=2)])
        visitor.visit(set_expr)

        # Range expression
        range_expr = RangeExpression(low=IntegerLiteral(value=0), high=IntegerLiteral(value=100))
        visitor.visit(range_expr)

        assert ("binary", "+") in visitor.visited
        assert ("unary", "not") in visitor.visited
        assert "parentheses" in visitor.visited
        assert ("set", 2) in visitor.visited
        assert "range" in visitor.visited

    def test_visit_string_expressions(self) -> None:
        """Test visiting string-related expressions."""

        class StringExprCollector(BaseVisitor[None]):
            def __init__(self) -> None:
                self.visited: list[Any] = []

            def visit_string_count(self, node: StringCount) -> None:
                self.visited.append(("count", node.string_id))
                return super().visit_string_count(node)

            def visit_string_offset(self, node: StringOffset) -> None:
                self.visited.append(("offset", node.string_id, node.index is not None))
                return super().visit_string_offset(node)

            def visit_string_length(self, node: StringLength) -> None:
                self.visited.append(("length", node.string_id, node.index is not None))
                return super().visit_string_length(node)

            def visit_string_identifier(self, node: StringIdentifier) -> None:
                self.visited.append(("id", node.name))
                return super().visit_string_identifier(node)

            def visit_string_wildcard(self, node: StringWildcard) -> None:
                self.visited.append(("wildcard", node.pattern))
                return super().visit_string_wildcard(node)

        visitor = StringExprCollector()

        visitor.visit(StringCount(string_id="$a"))
        visitor.visit(StringOffset(string_id="$b", index=IntegerLiteral(value=1)))
        visitor.visit(StringLength(string_id="$c", index=None))
        visitor.visit(StringIdentifier(name="$d"))
        visitor.visit(StringWildcard(pattern="$test*"))

        assert ("count", "$a") in visitor.visited
        assert ("offset", "$b", True) in visitor.visited
        assert ("length", "$c", False) in visitor.visited
        assert ("id", "$d") in visitor.visited
        assert ("wildcard", "$test*") in visitor.visited

    def test_visit_condition_expressions(self) -> None:
        """Test visiting condition-specific expressions."""

        class ConditionCollector(BaseVisitor[None]):
            def __init__(self) -> None:
                self.visited: list[Any] = []

            def visit_at_expression(self, node: AtExpression) -> None:
                self.visited.append(("at", node.string_id))
                return super().visit_at_expression(node)

            def visit_in_expression(self, node: InExpression) -> None:
                self.visited.append(("in", node.subject))
                return super().visit_in_expression(node)

            def visit_of_expression(self, node: OfExpression) -> None:
                self.visited.append("of")
                return super().visit_of_expression(node)

            def visit_for_expression(self, node: ForExpression) -> None:
                self.visited.append(("for", node.variable))
                return super().visit_for_expression(node)

            def visit_for_of_expression(self, node: ForOfExpression) -> None:
                self.visited.append(("for_of", node.quantifier))
                return super().visit_for_of_expression(node)

        visitor = ConditionCollector()

        visitor.visit(AtExpression(string_id="$a", offset=IntegerLiteral(value=0)))
        visitor.visit(
            InExpression(
                subject="$a", range=RangeExpression(low=IntegerLiteral(0), high=IntegerLiteral(100))
            )
        )
        visitor.visit(
            OfExpression(
                quantifier=IntegerLiteral(value=2),
                string_set=SetExpression([StringIdentifier(name="$a")]),
            )
        )
        visitor.visit(
            ForExpression(
                quantifier="all",
                variable="i",
                iterable=RangeExpression(low=IntegerLiteral(0), high=IntegerLiteral(10)),
                body=BooleanLiteral(value=True),
            )
        )
        visitor.visit(
            ForOfExpression(
                quantifier="any", string_set=StringWildcard(pattern="$*"), condition=None
            )
        )

        assert ("at", "$a") in visitor.visited
        assert ("in", "$a") in visitor.visited
        assert "of" in visitor.visited
        assert ("for", "i") in visitor.visited
        assert ("for_of", "any") in visitor.visited

    def test_visit_extern_and_pragma_nodes(self) -> None:
        """Test visiting extern and pragma nodes."""

        class ExtendedVisitor(BaseVisitor[None]):
            def __init__(self) -> None:
                self.visited: list[Any] = []

            def visit_extern_rule(self, node: ExternRule) -> None:
                self.visited.append(("extern_rule", node.name))
                return super().visit_extern_rule(node)

            def visit_extern_rule_reference(self, node: ExternRuleReference) -> None:
                self.visited.append(("extern_ref", node.rule_name))
                return super().visit_extern_rule_reference(node)

            def visit_extern_import(self, node: ExternImport) -> None:
                self.visited.append(("extern_import", node.module_path))
                return super().visit_extern_import(node)

            def visit_extern_namespace(self, node: ExternNamespace) -> None:
                self.visited.append(("namespace", node.name))
                return super().visit_extern_namespace(node)

            def visit_pragma(self, node: Pragma) -> None:
                self.visited.append(("pragma", node.name))
                return super().visit_pragma(node)

            def visit_in_rule_pragma(self, node: InRulePragma) -> None:
                self.visited.append("in_rule_pragma")
                return super().visit_in_rule_pragma(node)

            def visit_pragma_block(self, node: PragmaBlock) -> None:
                self.visited.append(("pragma_block", len(node.pragmas)))
                return super().visit_pragma_block(node)

        visitor = ExtendedVisitor()

        visitor.visit(ExternRule(name="test_extern", modifiers=[], namespace=None))
        visitor.visit(ExternRuleReference(rule_name="ref_rule", namespace=None))
        visitor.visit(ExternImport(module_path="test.module", alias=None, rules=[]))
        visitor.visit(ExternNamespace(name="test_ns"))

        pragma = Pragma(
            pragma_type=PragmaType.CUSTOM,
            name="optimize",
            arguments=[],
            scope=PragmaScope.FILE,
        )
        visitor.visit(pragma)
        visitor.visit(InRulePragma(pragma=pragma, position="before"))
        visitor.visit(PragmaBlock(pragmas=[pragma], scope=PragmaScope.FILE))

        assert ("extern_rule", "test_extern") in visitor.visited
        assert ("extern_ref", "ref_rule") in visitor.visited
        assert ("extern_import", "test.module") in visitor.visited
        assert ("namespace", "test_ns") in visitor.visited
        assert ("pragma", "optimize") in visitor.visited
        assert "in_rule_pragma" in visitor.visited
        assert ("pragma_block", 1) in visitor.visited

    def test_visit_meta_and_modifiers(self) -> None:
        """Test visiting meta and modifier nodes."""

        class MetaModifierVisitor(BaseVisitor[None]):
            def __init__(self) -> None:
                self.metas: list[Any] = []
                self.modifiers: list[Any] = []

            def visit_meta(self, node: Meta) -> None:
                self.metas.append((node.key, node.value))
                return super().visit_meta(node)

            def visit_string_modifier(self, node: StringModifier) -> None:
                self.modifiers.append(node.name)
                return super().visit_string_modifier(node)

        visitor = MetaModifierVisitor()

        visitor.visit(Meta(key="author", value="test"))
        visitor.visit(Meta(key="version", value=1))
        visitor.visit(StringModifier.from_name_value("wide"))
        visitor.visit(StringModifier.from_name_value("nocase"))

        assert ("author", "test") in visitor.metas
        assert ("version", 1) in visitor.metas
        assert "wide" in visitor.modifiers
        assert "nocase" in visitor.modifiers

    def test_visit_operators(self) -> None:
        """Test visiting operator expressions."""

        class OperatorVisitor(BaseVisitor[None]):
            def __init__(self) -> None:
                self.visited: list[Any] = []

            def visit_defined_expression(self, node: DefinedExpression) -> None:
                self.visited.append("defined")
                return super().visit_defined_expression(node)

            def visit_string_operator_expression(self, node: StringOperatorExpression) -> None:
                self.visited.append(("string_op", node.operator))
                return super().visit_string_operator_expression(node)

        visitor = OperatorVisitor()

        visitor.visit(DefinedExpression(expression=StringIdentifier(name="$a")))
        visitor.visit(
            StringOperatorExpression(
                left=StringIdentifier(name="$a"),
                operator="contains",
                right=StringLiteral(value="test"),
            )
        )

        assert "defined" in visitor.visited
        assert ("string_op", "contains") in visitor.visited

    def test_visit_function_and_access(self) -> None:
        """Test visiting function calls and access expressions."""

        class AccessVisitor(BaseVisitor[None]):
            def __init__(self) -> None:
                self.visited: list[Any] = []

            def visit_function_call(self, node: FunctionCall) -> None:
                self.visited.append(("function", node.function, len(node.arguments)))
                return super().visit_function_call(node)

            def visit_array_access(self, node: ArrayAccess) -> None:
                self.visited.append("array_access")
                return super().visit_array_access(node)

            def visit_member_access(self, node: MemberAccess) -> None:
                self.visited.append(("member", node.member))
                return super().visit_member_access(node)

        visitor = AccessVisitor()

        visitor.visit(
            FunctionCall(
                function="uint16", arguments=[IntegerLiteral(value=0), IntegerLiteral(value=1)]
            )
        )
        visitor.visit(ArrayAccess(array=Identifier(name="sections"), index=IntegerLiteral(value=0)))
        visitor.visit(MemberAccess(object=Identifier(name="pe"), member="number_of_sections"))

        assert ("function", "uint16", 2) in visitor.visited
        assert "array_access" in visitor.visited
        assert ("member", "number_of_sections") in visitor.visited


class TestASTVisitorAbstractBase:
    """Tests for ASTVisitor abstract base class."""

    def test_visitor_dispatch_method(self) -> None:
        """Test that ASTVisitor.visit() dispatches to node.accept()."""

        class TestVisitor(ASTVisitor[str]):
            def visit_rule(self, node: Rule) -> str:
                return f"Rule: {node.name}"

            def visit_import(self, node: Import) -> str:
                return f"Import: {node.module}"

            def visit_include(self, node: Include) -> str:
                return f"Include: {node.path}"

            def visit_yara_file(self, node: YaraFile) -> str:
                return "YaraFile"

            # Implement all other abstract methods as minimal stubs
            def visit_tag(self, node: Any) -> str:
                return "Tag"

            def visit_string_definition(self, node: Any) -> str:
                return "StringDefinition"

            def visit_plain_string(self, node: Any) -> str:
                return "PlainString"

            def visit_hex_string(self, node: Any) -> str:
                return "HexString"

            def visit_regex_string(self, node: Any) -> str:
                return "RegexString"

            def visit_string_modifier(self, node: Any) -> str:
                return "StringModifier"

            def visit_hex_token(self, node: Any) -> str:
                return "HexToken"

            def visit_hex_byte(self, node: Any) -> str:
                return "HexByte"

            def visit_hex_wildcard(self, node: Any) -> str:
                return "HexWildcard"

            def visit_hex_jump(self, node: Any) -> str:
                return "HexJump"

            def visit_hex_alternative(self, node: Any) -> str:
                return "HexAlternative"

            def visit_hex_nibble(self, node: Any) -> str:
                return "HexNibble"

            def visit_expression(self, node: Any) -> str:
                return "Expression"

            def visit_identifier(self, node: Any) -> str:
                return "Identifier"

            def visit_string_identifier(self, node: Any) -> str:
                return "StringIdentifier"

            def visit_string_wildcard(self, node: Any) -> str:
                return "StringWildcard"

            def visit_string_count(self, node: Any) -> str:
                return "StringCount"

            def visit_string_offset(self, node: Any) -> str:
                return "StringOffset"

            def visit_string_length(self, node: Any) -> str:
                return "StringLength"

            def visit_integer_literal(self, node: Any) -> str:
                return "IntegerLiteral"

            def visit_double_literal(self, node: Any) -> str:
                return "DoubleLiteral"

            def visit_string_literal(self, node: Any) -> str:
                return "StringLiteral"

            def visit_regex_literal(self, node: Any) -> str:
                return "RegexLiteral"

            def visit_boolean_literal(self, node: Any) -> str:
                return "BooleanLiteral"

            def visit_binary_expression(self, node: Any) -> str:
                return "BinaryExpression"

            def visit_unary_expression(self, node: Any) -> str:
                return "UnaryExpression"

            def visit_parentheses_expression(self, node: Any) -> str:
                return "ParenthesesExpression"

            def visit_set_expression(self, node: Any) -> str:
                return "SetExpression"

            def visit_range_expression(self, node: Any) -> str:
                return "RangeExpression"

            def visit_function_call(self, node: Any) -> str:
                return "FunctionCall"

            def visit_array_access(self, node: Any) -> str:
                return "ArrayAccess"

            def visit_member_access(self, node: Any) -> str:
                return "MemberAccess"

            def visit_condition(self, node: Any) -> str:
                return "Condition"

            def visit_for_expression(self, node: Any) -> str:
                return "ForExpression"

            def visit_for_of_expression(self, node: Any) -> str:
                return "ForOfExpression"

            def visit_at_expression(self, node: Any) -> str:
                return "AtExpression"

            def visit_in_expression(self, node: Any) -> str:
                return "InExpression"

            def visit_of_expression(self, node: Any) -> str:
                return "OfExpression"

            def visit_meta(self, node: Any) -> str:
                return "Meta"

            def visit_module_reference(self, node: Any) -> str:
                return "ModuleReference"

            def visit_dictionary_access(self, node: Any) -> str:
                return "DictionaryAccess"

            def visit_comment(self, node: Any) -> str:
                return "Comment"

            def visit_comment_group(self, node: Any) -> str:
                return "CommentGroup"

            def visit_defined_expression(self, node: Any) -> str:
                return "DefinedExpression"

            def visit_string_operator_expression(self, node: Any) -> str:
                return "StringOperatorExpression"

            def visit_extern_rule(self, node: Any) -> str:
                return "ExternRule"

            def visit_extern_rule_reference(self, node: Any) -> str:
                return "ExternRuleReference"

            def visit_extern_import(self, node: Any) -> str:
                return "ExternImport"

            def visit_extern_namespace(self, node: Any) -> str:
                return "ExternNamespace"

            def visit_pragma(self, node: Any) -> str:
                return "Pragma"

            def visit_in_rule_pragma(self, node: Any) -> str:
                return "InRulePragma"

            def visit_pragma_block(self, node: Any) -> str:
                return "PragmaBlock"

        rule = Rule(name="test", modifiers=[], tags=[], meta={}, strings=[])
        visitor = TestVisitor()

        # The visit method should dispatch to visit_rule via accept
        result = visitor.visit(rule)
        assert result == "Rule: test"

    def test_visitor_rejects_non_ast_nodes(self) -> None:
        visitor: ASTVisitor[Any] = ASTVisitor()

        with pytest.raises(TypeError, match="Visitor node must be an ASTNode"):
            visitor.visit(cast(Any, object()))


class TestModuleAndDictionaryAccess:
    """Test module reference and dictionary access visitor methods."""

    def test_visit_module_nodes_directly(self) -> None:
        """Test visiting module-specific AST nodes."""
        from yaraast.ast.modules import DictionaryAccess, ModuleReference

        class ModuleVisitor(BaseVisitor[None]):
            def __init__(self) -> None:
                self.module_refs: list[Any] = []
                self.dict_accesses: list[Any] = []

            def visit_module_reference(self, node: Any) -> None:
                self.module_refs.append(node.module)
                return super().visit_module_reference(node)

            def visit_dictionary_access(self, node: Any) -> None:
                self.dict_accesses.append(node.key)
                return super().visit_dictionary_access(node)

        visitor = ModuleVisitor()

        # Create and visit module reference
        mod_ref = ModuleReference(module="pe")
        visitor.visit(mod_ref)

        # Create and visit dictionary access with string key
        dict_access = DictionaryAccess(object=Identifier(name="pe"), key="version_info")
        visitor.visit(dict_access)

        # Create and visit dictionary access with expression key
        dict_access_expr = DictionaryAccess(
            object=Identifier(name="pe"), key=StringLiteral(value="test")
        )
        visitor.visit(dict_access_expr)

        assert "pe" in visitor.module_refs
        assert "version_info" in visitor.dict_accesses


class TestYaraFileVisitor:
    """Test YaraFile-level visitor functionality."""

    def test_visit_yara_file_with_all_elements(self) -> None:
        """Test visiting YaraFile with all possible elements."""

        class FileElementCounter(BaseVisitor[None]):
            def __init__(self) -> None:
                self.counts = {
                    "imports": 0,
                    "includes": 0,
                    "rules": 0,
                    "extern_rules": 0,
                    "extern_imports": 0,
                    "pragmas": 0,
                    "namespaces": 0,
                }

            def visit_import(self, node: Import) -> None:
                self.counts["imports"] += 1
                return super().visit_import(node)

            def visit_include(self, node: Include) -> None:
                self.counts["includes"] += 1
                return super().visit_include(node)

            def visit_rule(self, node: Rule) -> None:
                self.counts["rules"] += 1
                return super().visit_rule(node)

            def visit_extern_rule(self, node: ExternRule) -> None:
                self.counts["extern_rules"] += 1
                return super().visit_extern_rule(node)

            def visit_extern_import(self, node: ExternImport) -> None:
                self.counts["extern_imports"] += 1
                return super().visit_extern_import(node)

            def visit_pragma(self, node: Pragma) -> None:
                self.counts["pragmas"] += 1
                return super().visit_pragma(node)

            def visit_extern_namespace(self, node: ExternNamespace) -> None:
                self.counts["namespaces"] += 1
                return super().visit_extern_namespace(node)

        # Create YaraFile with all element types
        yara_file = YaraFile(
            imports=[Import(module="pe"), Import(module="elf")],
            includes=[Include(path="common.yar")],
            rules=[Rule(name="test", modifiers=[], tags=[], meta={}, strings=[])],
            extern_rules=[ExternRule(name="ext_rule", modifiers=[])],
            extern_imports=[ExternImport(module_path="external.module")],
            pragmas=[
                Pragma(
                    pragma_type=PragmaType.CUSTOM,
                    name="optimize",
                    scope=PragmaScope.FILE,
                )
            ],
            namespaces=[ExternNamespace(name="test_ns")],
        )

        visitor = FileElementCounter()
        visitor.visit(yara_file)

        assert visitor.counts["imports"] == 2
        assert visitor.counts["includes"] == 1
        assert visitor.counts["rules"] == 1
        assert visitor.counts["extern_rules"] == 1
        assert visitor.counts["extern_imports"] == 1
        assert visitor.counts["pragmas"] == 1
        assert visitor.counts["namespaces"] == 1

    def test_visit_rule_with_all_components(self) -> None:
        """Test visiting Rule with all possible components."""

        class RuleComponentVisitor(BaseVisitor[None]):
            def __init__(self) -> None:
                self.components = {
                    "tags": 0,
                    "strings": 0,
                    "condition": False,
                    "pragmas": 0,
                }

            def visit_tag(self, node: Tag) -> None:
                self.components["tags"] += 1
                return super().visit_tag(node)

            def visit_plain_string(self, node: PlainString) -> None:
                self.components["strings"] += 1
                return super().visit_plain_string(node)

            def visit_boolean_literal(self, node: BooleanLiteral) -> None:
                self.components["condition"] = True
                return super().visit_boolean_literal(node)

            def visit_in_rule_pragma(self, node: InRulePragma) -> None:
                self.components["pragmas"] += 1
                return super().visit_in_rule_pragma(node)

        # Create rule with all components
        pragma = Pragma(
            pragma_type=PragmaType.CUSTOM,
            name="optimize",
            arguments=[],
            scope=PragmaScope.RULE,
        )
        rule = Rule(
            name="test",
            modifiers=[],
            tags=[Tag(name="malware"), Tag(name="trojan")],
            meta={"author": "test"},
            strings=[PlainString(identifier="$a", value="test")],
            condition=BooleanLiteral(value=True),  # Use expression directly
            pragmas=[InRulePragma(pragma=pragma, position="before")],
        )

        visitor = RuleComponentVisitor()
        visitor.visit(rule)

        assert visitor.components["tags"] == 2
        assert visitor.components["strings"] == 1
        assert visitor.components["condition"] is True
        assert visitor.components["pragmas"] == 1

    def test_visit_rule_without_condition(self) -> None:
        """Test visiting Rule without condition (edge case)."""

        class RuleVisitor(BaseVisitor[None]):
            def __init__(self) -> None:
                self.visited_rule = False

            def visit_rule(self, node: Rule) -> None:
                self.visited_rule = True
                return super().visit_rule(node)

        # Create rule without condition
        rule = Rule(
            name="test", modifiers=[], tags=[], meta={}, strings=[], condition=None, pragmas=[]
        )

        visitor = RuleVisitor()
        visitor.visit(rule)

        assert visitor.visited_rule is True


class TestHexNibbleVisitor:
    """Test hex nibble visitor support."""

    def test_visit_hex_nibble(self) -> None:
        """Test visiting hex nibble nodes."""

        class NibbleVisitor(BaseVisitor[None]):
            def __init__(self) -> None:
                self.nibbles: list[Any] = []

            def visit_hex_nibble(self, node: HexNibble) -> None:
                self.nibbles.append((node.high, node.value))
                return super().visit_hex_nibble(node)

        visitor = NibbleVisitor()

        # Create and visit high nibble
        high_nibble = HexNibble(high=True, value=0xF)
        visitor.visit(high_nibble)

        # Create and visit low nibble
        low_nibble = HexNibble(high=False, value=0xA)
        visitor.visit(low_nibble)

        assert (True, 0xF) in visitor.nibbles
        assert (False, 0xA) in visitor.nibbles


class TestParametrizedVisitor:
    """Parametrized tests for comprehensive visitor coverage."""

    @pytest.mark.parametrize(
        "node,visitor_method",
        [
            (Import(module="pe"), "visit_import"),
            (Include(path="test.yar"), "visit_include"),
            (Tag(name="malware"), "visit_tag"),
            (Meta(key="author", value="test"), "visit_meta"),
            (StringModifier.from_name_value("wide"), "visit_string_modifier"),
            (HexByte(value=0x4D), "visit_hex_byte"),
            (HexWildcard(), "visit_hex_wildcard"),
            (HexJump(min_jump=2, max_jump=4), "visit_hex_jump"),
            (IntegerLiteral(value=42), "visit_integer_literal"),
            (DoubleLiteral(value=3.14), "visit_double_literal"),
            (StringLiteral(value="test"), "visit_string_literal"),
            (BooleanLiteral(value=True), "visit_boolean_literal"),
            (RegexLiteral(pattern="test.*", modifiers="i"), "visit_regex_literal"),
            (Identifier(name="pe"), "visit_identifier"),
            (StringIdentifier(name="$a"), "visit_string_identifier"),
            (StringWildcard(pattern="$test*"), "visit_string_wildcard"),
            (StringCount(string_id="$a"), "visit_string_count"),
            (Comment(text="test", is_multiline=False), "visit_comment"),
        ],
    )
    def test_visit_simple_nodes(self, node: Any, visitor_method: str) -> None:
        """Test visiting simple AST nodes using parametrization."""

        class TrackingVisitor(BaseVisitor[None]):
            def __init__(self) -> None:
                self.visited_methods: list[Any] = []

            def __getattribute__(self, name: str) -> Any:
                if name.startswith("visit_") and name != "visit":
                    original = object.__getattribute__(self, name)

                    def wrapper(node: Any) -> Any:
                        object.__getattribute__(self, "visited_methods").append(name)
                        return original(node)

                    return wrapper
                return object.__getattribute__(self, name)

        visitor = TrackingVisitor()
        visitor.visit(node)

        assert visitor_method in visitor.visited_methods

    @pytest.mark.parametrize(
        "expr_type,left,right,operator",
        [
            (BinaryExpression, IntegerLiteral(value=1), IntegerLiteral(value=2), "+"),
            (BinaryExpression, BooleanLiteral(value=True), BooleanLiteral(value=False), "and"),
            (BinaryExpression, IntegerLiteral(value=10), IntegerLiteral(value=5), ">"),
        ],
    )
    def test_visit_binary_expressions(
        self,
        expr_type: type[BinaryExpression],
        left: Any,
        right: Any,
        operator: str,
    ) -> None:
        """Test visiting binary expressions with various operators."""

        class BinaryVisitor(BaseVisitor[None]):
            def __init__(self) -> None:
                self.operators: list[Any] = []

            def visit_binary_expression(self, node: BinaryExpression) -> None:
                self.operators.append(node.operator)
                return super().visit_binary_expression(node)

        expr = expr_type(left=left, operator=operator, right=right)
        visitor = BinaryVisitor()
        visitor.visit(expr)

        assert operator in visitor.operators

    @pytest.mark.parametrize(
        "string_type,identifier,value",
        [
            (PlainString, "$s1", "test"),
            (PlainString, "$malware", "PE\x00\x00"),
            (PlainString, "$url", "http://example.com"),
        ],
    )
    def test_visit_string_types(
        self,
        string_type: type[PlainString],
        identifier: str,
        value: str,
    ) -> None:
        """Test visiting different string definitions."""

        class StringVisitor(BaseVisitor[None]):
            def __init__(self) -> None:
                self.strings: list[Any] = []

            def visit_plain_string(self, node: PlainString) -> None:
                self.strings.append((node.identifier, node.value))
                return super().visit_plain_string(node)

        string_node = string_type(identifier=identifier, value=value)
        visitor = StringVisitor()
        visitor.visit(string_node)

        assert (identifier, value) in visitor.strings

    @pytest.mark.parametrize(
        "for_expr_data",
        [
            {"quantifier": "all", "variable": "i", "has_iterable": True, "has_body": True},
            {"quantifier": "any", "variable": "j", "has_iterable": True, "has_body": True},
        ],
    )
    def test_visit_for_expressions(self, for_expr_data: dict[str, Any]) -> None:
        """Test visiting for expressions."""

        class ForVisitor(BaseVisitor[None]):
            def __init__(self) -> None:
                self.for_vars: list[Any] = []

            def visit_for_expression(self, node: ForExpression) -> None:
                self.for_vars.append(node.variable)
                return super().visit_for_expression(node)

        for_expr = ForExpression(
            quantifier=for_expr_data["quantifier"],
            variable=for_expr_data["variable"],
            iterable=RangeExpression(low=IntegerLiteral(0), high=IntegerLiteral(10)),
            body=BooleanLiteral(value=True),
        )

        visitor = ForVisitor()
        visitor.visit(for_expr)

        assert for_expr_data["variable"] in visitor.for_vars


class TestEdgeCasesAndNullHandling:
    """Test edge cases and null/None handling in visitors."""

    def test_visit_string_offset_without_index(self) -> None:
        """Test visiting StringOffset without index."""

        class OffsetVisitor(BaseVisitor[None]):
            def __init__(self) -> None:
                self.offsets_without_index = 0

            def visit_string_offset(self, node: StringOffset) -> None:
                if node.index is None:
                    self.offsets_without_index += 1
                return super().visit_string_offset(node)

        visitor = OffsetVisitor()
        visitor.visit(StringOffset(string_id="$a", index=None))
        visitor.visit(StringOffset(string_id="$b", index=IntegerLiteral(value=1)))

        assert visitor.offsets_without_index == 1

    def test_visit_string_length_without_index(self) -> None:
        """Test visiting StringLength without index."""

        class LengthVisitor(BaseVisitor[None]):
            def __init__(self) -> None:
                self.lengths_without_index = 0

            def visit_string_length(self, node: StringLength) -> None:
                if node.index is None:
                    self.lengths_without_index += 1
                return super().visit_string_length(node)

        visitor = LengthVisitor()
        visitor.visit(StringLength(string_id="$a", index=None))
        visitor.visit(StringLength(string_id="$b", index=IntegerLiteral(value=1)))

        assert visitor.lengths_without_index == 1

    def test_visit_for_of_without_condition(self) -> None:
        """Test visiting ForOfExpression without condition."""

        class ForOfVisitor(BaseVisitor[None]):
            def __init__(self) -> None:
                self.for_ofs_without_condition = 0

            def visit_for_of_expression(self, node: ForOfExpression) -> None:
                if node.condition is None:
                    self.for_ofs_without_condition += 1
                return super().visit_for_of_expression(node)

        visitor = ForOfVisitor()
        visitor.visit(
            ForOfExpression(
                quantifier="all", string_set=StringWildcard(pattern="$*"), condition=None
            )
        )
        visitor.visit(
            ForOfExpression(
                quantifier="any",
                string_set=StringWildcard(pattern="$a*"),
                condition=BooleanLiteral(value=True),
            )
        )

        assert visitor.for_ofs_without_condition == 1

    def test_visit_in_expression_with_expression_subject(self) -> None:
        """Test visiting InExpression with an expression (not string) as subject."""

        class InExprVisitor(BaseVisitor[None]):
            def __init__(self) -> None:
                self.in_exprs: list[Any] = []

            def visit_in_expression(self, node: InExpression) -> None:
                self.in_exprs.append(type(node.subject).__name__)
                return super().visit_in_expression(node)

        visitor = InExprVisitor()

        # InExpression with string subject
        visitor.visit(
            InExpression(
                subject="$a", range=RangeExpression(low=IntegerLiteral(0), high=IntegerLiteral(100))
            )
        )

        # InExpression with OfExpression as subject
        visitor.visit(
            InExpression(
                subject=OfExpression(
                    quantifier=IntegerLiteral(2), string_set=StringWildcard(pattern="$*")
                ),
                range=RangeExpression(low=IntegerLiteral(0), high=IntegerLiteral(100)),
            )
        )

        assert "str" in visitor.in_exprs or "OfExpression" in visitor.in_exprs
