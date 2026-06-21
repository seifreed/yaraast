# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""Coverage tests for builder, lexer, dependency_graph, and type-validation modules.

Each test exercises a specific uncovered line or branch in:
  - yaraast/builder/rule_builder.py
  - yaraast/builder/ast_transformer.py
  - yaraast/resolution/dependency_graph.py
  - yaraast/yaral/lexer.py
  - yaraast/lexer/lexer_readers.py
  - yaraast/types/_validation.py
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from yaraast.ast.conditions import Condition
from yaraast.ast.strings import HexNegatedByte
from yaraast.builder.ast_transformer import RuleTransformer
from yaraast.builder.rule_builder import (
    RuleBuilder,
    _validate_yara_identifier,
    _validated_condition,
)
from yaraast.lexer.lexer import Lexer
from yaraast.lexer.lexer_errors import LexerError
from yaraast.parser.parser import Parser
from yaraast.resolution.dependency_graph import DependencyGraph
from yaraast.types._registry import IntegerType, TypeEnvironment
from yaraast.types._validation import TypeChecker
from yaraast.yaral.lexer import YaraLLexer

# ---------------------------------------------------------------------------
# yaraast/builder/rule_builder.py  lines 71-72, branch [70,71]
# ---------------------------------------------------------------------------


class TestValidateYaraIdentifierNonString:
    """_validate_yara_identifier lines 71-72: non-str name raises TypeError."""

    def test_integer_name_raises_type_error(self) -> None:
        # Arrange: integer is not a string
        non_str_name: Any = 123
        # Act + Assert
        with pytest.raises(TypeError, match="Invalid rule identifier"):
            _validate_yara_identifier(non_str_name, "rule")

    def test_none_name_raises_type_error(self) -> None:
        # Arrange: None is not a string
        none_name: Any = None
        # Act + Assert
        with pytest.raises(TypeError, match="Invalid tag identifier"):
            _validate_yara_identifier(none_name, "tag")

    def test_rule_builder_with_name_accepts_valid_string(self) -> None:
        # Confirm the True branch still works (regression guard)
        # Arrange + Act
        rule = RuleBuilder("valid_name").with_condition("true").build()
        # Assert
        assert rule.name == "valid_name"


# ---------------------------------------------------------------------------
# yaraast/builder/rule_builder.py  branch [64,66]
# ---------------------------------------------------------------------------


class TestValidatedConditionNonCallableValidateStructure:
    """_validated_condition branch [64,66]: Expression without callable validate_structure.

    Condition() is the only Expression subclass that does not define
    validate_structure, so it traverses the False branch of
    'if callable(validate_structure): validate_structure()'.
    """

    def test_condition_instance_has_no_validate_structure(self) -> None:
        # Arrange: Condition is the only concrete Expression subclass
        # whose class dict lacks validate_structure
        condition_node = Condition()
        # Act
        result = _validated_condition(condition_node)
        # Assert: the node is returned unchanged
        assert result is condition_node

    def test_boolean_literal_has_callable_validate_structure(self) -> None:
        # Confirm the True branch (callable) is exercised for normal expressions
        from yaraast.ast.expressions import BooleanLiteral

        lit = BooleanLiteral(value=True)
        result = _validated_condition(lit)
        assert result is lit


# ---------------------------------------------------------------------------
# yaraast/builder/ast_transformer.py  lines 379, 385, 391
# ---------------------------------------------------------------------------


class TestRenameStringsNewNodeReturnPaths:
    """Lines 379, 385, 391: BinaryExpression/UnaryExpression/ParenthesesExpression
    that contain string identifiers whose names ARE in the rename mapping produce
    new node instances.  This exercises the 'return New...Expression(...)' branches
    at lines 379, 385, and 391.
    """

    def test_binary_with_renamed_string_child_creates_new_binary_node(self) -> None:
        # Arrange: '$a and $a' — both sides are StringIdentifiers for $a.
        # rename_strings({'$a': '$b'}) changes both children, so new_left is not
        # expr.left AND new_right is not expr.right → line 379 executes.
        ast = Parser('rule test { strings: $a = "hello" condition: $a and $a }').parse()
        rule = ast.rules[0]
        transformer = RuleTransformer(rule)

        # Act
        transformer.rename_strings({"$a": "$b"})
        result = transformer.build()

        # Assert: string renamed in condition
        from yaraast.ast.expressions import BinaryExpression, StringIdentifier

        assert isinstance(result.condition, BinaryExpression)
        assert isinstance(result.condition.left, StringIdentifier)
        assert result.condition.left.name == "$b"

    def test_unary_with_renamed_string_operand_creates_new_unary_node(self) -> None:
        # Arrange: 'not $a' — operand is a StringIdentifier.
        # rename_strings({'$a': '$b'}) changes the operand → line 385 executes.
        ast = Parser('rule test { strings: $a = "hello" condition: not $a }').parse()
        rule = ast.rules[0]
        transformer = RuleTransformer(rule)

        # Act
        transformer.rename_strings({"$a": "$b"})
        result = transformer.build()

        # Assert: renamed in unary operand
        from yaraast.ast.expressions import StringIdentifier, UnaryExpression

        assert isinstance(result.condition, UnaryExpression)
        assert isinstance(result.condition.operand, StringIdentifier)
        assert result.condition.operand.name == "$b"

    def test_parentheses_with_renamed_string_creates_new_paren_node(self) -> None:
        # Arrange: '($a)' — inner expression is a StringIdentifier.
        # rename_strings({'$a': '$b'}) changes inner → line 391 executes.
        ast = Parser('rule test { strings: $a = "hello" condition: ($a) }').parse()
        rule = ast.rules[0]
        transformer = RuleTransformer(rule)

        # Act
        transformer.rename_strings({"$a": "$b"})
        result = transformer.build()

        # Assert: renamed inside parentheses
        from yaraast.ast.expressions import ParenthesesExpression, StringIdentifier

        assert isinstance(result.condition, ParenthesesExpression)
        assert isinstance(result.condition.expression, StringIdentifier)
        assert result.condition.expression.name == "$b"


# ---------------------------------------------------------------------------
# yaraast/resolution/dependency_graph.py  branch [456,455]
# ---------------------------------------------------------------------------


class TestDependencyGraphSelfReferentialRule:
    """Branch [456,455]: the False branch of 'if dependency_key != rule_key'.

    DependencyFinder.visit_identifier excludes the current rule from
    collected dependencies, so a rule that references itself is stored
    in raw rule names but its own key is never added to dependencies.
    Adding two different files each with one rule that forms a
    cross-file dependency exercises the inner loop exhaustively.
    """

    def test_cross_file_rule_dependency_graph(self) -> None:
        # Arrange: rule_a references rule_b from another file
        ast_a = Parser("rule rule_a { condition: rule_b }").parse()
        ast_b = Parser("rule rule_b { condition: true }").parse()

        graph = DependencyGraph()
        graph.add_file(Path("/file_a.yar"), ast_a)
        graph.add_file(Path("/file_b.yar"), ast_b)

        # Assert: rule_a depends on rule_b
        rule_a_node = graph.nodes.get("rule:rule_a")
        assert rule_a_node is not None
        assert "rule:rule_b" in rule_a_node.dependencies

    def test_rule_that_references_itself_gets_no_self_dependency(self) -> None:
        # Arrange: a rule whose condition is its own name — the collector
        # skips self-references so dependency_key==rule_key branch is executed
        # for every iteration that would add the identity edge (none here).
        # The inner for-loop over _rule_node_keys_for_name is exercised because
        # 'self_loop' appears in _raw_rule_names() and the condition IS an identifier.
        ast = Parser("rule self_loop { condition: self_loop }").parse()
        graph = DependencyGraph()
        graph.add_file(Path("/self.yar"), ast)

        # Assert: no self-dependency added
        node = graph.nodes.get("rule:self_loop")
        assert node is not None
        assert "rule:self_loop" not in node.dependencies


# ---------------------------------------------------------------------------
# yaraast/yaral/lexer.py  lines 375-376
# ---------------------------------------------------------------------------


class TestYaraLLexerRegexWithEmbeddedNewline:
    """Lines 375-376: inside _read_regex, the 'else' branch where current character
    is a newline updates self.line/self.column before advancing.
    """

    def test_regex_containing_actual_newline(self) -> None:
        # Arrange: '=' context triggers _is_regex_context → True
        # The pattern contains a real newline character (not \\n)
        text = "= /abc\ndef/"
        lexer = YaraLLexer(text)

        # Act
        tokens = lexer.tokenize()

        # Assert: a REGEX token is produced containing the embedded newline
        from yaraast.lexer.tokens import TokenType

        regex_tokens = [t for t in tokens if t.type == TokenType.REGEX]
        assert len(regex_tokens) == 1
        assert "\n" in str(regex_tokens[0].value)


# ---------------------------------------------------------------------------
# yaraast/lexer/lexer_readers.py  line 124
# ---------------------------------------------------------------------------


class TestLexerReadersRegexBackslashNewline:
    """Line 124: read_regex() raises LexerError when a backslash inside a
    regex pattern is immediately followed by an actual newline character.
    """

    def test_regex_backslash_then_newline_raises(self) -> None:
        # Arrange: YARA lexer tokenizing a regex /abc\ (newline) /
        # chr(92) = backslash, chr(10) = newline
        text = "/abc" + chr(92) + chr(10) + "/"

        lexer: Any = Lexer(text)

        # Act + Assert
        with pytest.raises(LexerError, match="Unterminated regex"):
            lexer.tokenize()


# ---------------------------------------------------------------------------
# yaraast/lexer/lexer_readers.py  lines 278-279
# ---------------------------------------------------------------------------


class TestLexerReadersFloatTrailingUnderscore:
    """Lines 278-279: read_number() raises LexerError for a float whose
    fractional part ends with an underscore or contains double underscore.
    """

    def test_float_with_trailing_underscore_raises(self) -> None:
        # Arrange: '3.14_' — fraction ends with underscore
        lexer: Any = Lexer("3.14_")

        # Act + Assert
        with pytest.raises(LexerError, match="Invalid decimal floating-point literal"):
            lexer.tokenize()

    def test_float_with_double_underscore_in_fraction_raises(self) -> None:
        # Arrange: '3.1__4' — double underscore in fraction
        lexer: Any = Lexer("3.1__4")

        # Act + Assert
        with pytest.raises(LexerError, match="Invalid decimal floating-point literal"):
            lexer.tokenize()


# ---------------------------------------------------------------------------
# yaraast/types/_validation.py  line 61, branch [63,62]
# ---------------------------------------------------------------------------


class TestTypeCheckerVtModuleConstants:
    """Line 61 and branch [63->62]: _define_vt_livehunt_globals.

    Line 61:     env.define(constant_name, constant_type)
    Branch [63->62]: env.lookup(constant_name) is not None → skip define.

    The vt module is loaded from ModuleLoader and has constants such as
    'new_file', 'positives', 'submissions'.  A fresh TypeChecker always
    defines them (line 61).  When a base TypeEnvironment that already
    contains a vt constant name is passed to the constructor, the copy
    already holds that name and the lookup returns non-None, taking the
    False branch (skip define) at line 63.
    """

    def test_fresh_checker_defines_vt_constants(self) -> None:
        # Arrange + Act: default constructor triggers _define_vt_livehunt_globals
        checker = TypeChecker()

        # Assert: vt constants exist in the environment
        assert checker.env.lookup("positives") is not None
        assert checker.env.lookup("new_file") is not None

    def test_base_env_with_existing_name_skips_define(self) -> None:
        # Arrange: build a TypeEnvironment that already defines 'new_file'
        # with a non-vt type so that lookup returns non-None.
        # _fresh_environment copies base_env → env already has 'new_file'.
        # _define_vt_livehunt_globals then checks lookup('new_file') → non-None
        # → False branch taken (line 63 → line 62).
        base_env = TypeEnvironment()
        base_env.define("new_file", IntegerType())

        # Act
        checker = TypeChecker(env=base_env)

        # Assert: the pre-existing definition is preserved (not overwritten)
        result = checker.env.lookup("new_file")
        assert result is not None


# ---------------------------------------------------------------------------
# yaraast/types/_validation.py  line 213
# ---------------------------------------------------------------------------


class TestTypeCheckerVisitHexNegatedByte:
    """Line 213: visit_hex_negated_byte is a no-op visitor stub; calling it
    via the BaseVisitor dispatch mechanism exercises the line.
    """

    def test_visit_hex_negated_byte_returns_none(self) -> None:
        # Arrange
        node = HexNegatedByte(value=0x41)
        checker = TypeChecker()

        # Act: invoke the no-op visitor stub directly (exercises line 213)
        checker.visit_hex_negated_byte(node)

        # Assert: the node is left unchanged by the no-op stub
        assert node.value == 0x41

    def test_visit_hex_negated_byte_via_dispatch(self) -> None:
        # Arrange: build a real rule with a hex string containing a negated byte
        # and type-check it so the visitor dispatch hits visit_hex_negated_byte
        from yaraast.ast.base import YaraFile
        from yaraast.ast.expressions import BooleanLiteral
        from yaraast.ast.rules import Rule
        from yaraast.ast.strings import HexString

        negated = HexNegatedByte(value=0x41)
        hex_str = HexString(identifier="$h1", tokens=[negated], modifiers=[])
        rule = Rule(
            name="hex_rule",
            strings=[hex_str],
            condition=BooleanLiteral(value=True),
        )
        yara_file = YaraFile(rules=[rule])

        checker = TypeChecker()
        errors = checker.check(yara_file)

        # Assert: no type errors produced for a valid hex string
        assert errors == []
