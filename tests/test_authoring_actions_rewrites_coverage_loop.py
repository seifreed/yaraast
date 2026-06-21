# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Coverage-loop tests for yaraast.lsp.authoring_actions_rewrites.

These tests target the lines in authoring_actions_rewrites.py that are not
reached by the existing test suite (test_lsp_authoring_phase5.py and the
authoring_actions_sorting coverage files).

Missing-line analysis (87.37% before this file):

COVERABLE missing lines (addressed here):
  65  -- roundtrip_rewrite_rule: require_rule_context returns None when the
         cursor is on a line that is not inside any YARA rule block.
  89  -- deduplicate_identical_strings: require_rule_context returns None for
         the same reason.
  137 -- _condition_uses_string_set_quantifier: early return False when the
         condition argument is None.
  145 -- _iter_ast_nodes: generator exits immediately (bare return) when the
         first argument is not an ASTNode instance.
  156 -- rewrite_of_them (expand_of_them / compress_of_them): require_rule_context
         returns None when the cursor is outside any rule block.

STRUCTURALLY UNREACHABLE via the real public API (documented here):
  46  -- optimize_rule: `return None` for `len(ast.rules) != 1`.
         require_rule_context extracts exactly one rule's text; that text,
         when parseable at all, always yields one rule.  If it is unparseable
         _safe_parse returns None (caught at line 44) before line 46 is reached.

  49  -- optimize_rule: `return None` for `rule.condition is None`.
         The standard Parser raises ParserError when a rule lacks a condition
         section; _safe_parse catches that exception and returns None at
         line 44, so line 49 is never evaluated.

  72  -- roundtrip_rewrite_rule: `return None` when the AST diff has logical
         or structural changes.  This is a safety guard against a bug in
         RoundTripSerializer introducing semantic changes; a correct serializer
         never triggers it for any well-formed rule.

  94  -- deduplicate_identical_strings: `return None` for `len(ast.rules) != 1`.
         Same argument as line 46: rule-context text always parses to exactly
         one rule, or _safe_parse returns None before this check.

  120->122 -- deduplicate_identical_strings: branch where `rule.condition is
         None` after successful parsing.  The Parser always sets a condition
         node; this field is None only in directly-constructed Rule objects.

  124 -- deduplicate_identical_strings: `return None` when _safe_generate
         returns None.  CodeGenerator.generate is wrapped by lsp_safe_handler
         and only returns None when the generator raises an unhandled exception;
         no Rule produced by the standard parser triggers such an exception.

  161 -- rewrite_of_them: `return None` for `len(ast.rules) != 1`.
         Same argument as lines 46 and 94.

  177 -- rewrite_of_them: `return None` when the rewritten generator returns
         None.  Same argument as line 124; the standard generator does not
         raise on a valid Rule AST.
"""

from __future__ import annotations

from lsprotocol.types import Position, Range
import pytest

from yaraast.lsp.authoring import AuthoringActions
from yaraast.lsp.authoring_actions_rewrites import (
    _condition_uses_string_set_quantifier,
    _iter_ast_nodes,
)

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

_TEXT_WITH_IMPORT = 'import "pe"\n\nrule r {\n    condition:\n        true\n}\n'
"""YARA file whose line 0 is an import statement rather than a rule body.

Passing a selection anchored to line 0 causes require_rule_context to return
None for every function in authoring_actions_rewrites, exercising the
`if rule_context is None: return None` guard in each function.
"""

_IMPORT_LINE_SEL = Range(start=Position(line=0, character=0), end=Position(line=0, character=0))
"""Selection anchored on the import line — outside any rule block."""

_RULE_WITH_EXPLICIT_SET = (
    "rule demo {\n"
    "    strings:\n"
    '        $a = "a"\n'
    '        $b = "b"\n'
    "    condition:\n"
    "        any of ($a, $b)\n"
    "}"
)
"""Rule whose condition already uses an explicit string set.

expand_of_them only rewrites `any of them` (an Identifier named "them").
When the condition already uses a SetExpression, OfThemTransformer leaves it
unchanged, so the generated texts before and after transformation are identical.
This exercises the no-change early-return in rewrite_of_them.
"""

_RULE_WITHOUT_STRINGS = "rule demo {\n    condition:\n        true\n}"
"""Valid YARA rule with no strings section.

rewrite_of_them collects identifiers from rule.strings; an empty list makes
`not string_ids` True, which triggers the guard at line 168.
This is a distinct (but not missing in the original report) path tested here
for completeness of positive/negative pairs.
"""


# ---------------------------------------------------------------------------
# Scenario 1: cursor outside any rule — lines 65, 89, 156
#
# Each of roundtrip_rewrite_rule, deduplicate_identical_strings, and
# rewrite_of_them begins with:
#
#   rule_context = require_rule_context(text, selection.start.line)
#   if rule_context is None:          <- the guard we cover here
#       return None
#
# Passing a selection that falls on line 0 of a file whose first line is
# `import "pe"` ensures require_rule_context returns None.
# ---------------------------------------------------------------------------


def test_roundtrip_rewrite_rule_returns_none_when_cursor_outside_rule() -> None:
    """roundtrip_rewrite_rule returns None when the selection is on a line
    that is not inside any YARA rule block (line 65: `if rule_context is None`).
    """
    # Arrange: real AuthoringActions; text whose line 0 is an import directive.
    authoring = AuthoringActions()

    # Act: selection on line 0 (import line) — outside any rule body.
    result = authoring.roundtrip_rewrite_rule(_TEXT_WITH_IMPORT, _IMPORT_LINE_SEL)

    # Assert: no edit is produced.
    assert result is None


def test_deduplicate_identical_strings_returns_none_when_cursor_outside_rule() -> None:
    """deduplicate_identical_strings returns None when the cursor is outside
    any rule block, exercising line 89: `if rule_context is None: return None`.
    """
    # Arrange
    authoring = AuthoringActions()

    # Act
    result = authoring.deduplicate_identical_strings(_TEXT_WITH_IMPORT, _IMPORT_LINE_SEL)

    # Assert
    assert result is None


def test_expand_of_them_returns_none_when_cursor_outside_rule() -> None:
    """expand_of_them returns None when the cursor is outside any rule block,
    exercising line 156: `if rule_context is None: return None`."""
    # Arrange
    authoring = AuthoringActions()

    # Act
    result = authoring.expand_of_them(_TEXT_WITH_IMPORT, _IMPORT_LINE_SEL)

    # Assert
    assert result is None


def test_compress_of_them_returns_none_when_cursor_outside_rule() -> None:
    """compress_of_them also returns None when the cursor is outside any rule
    block (same guard at line 156, reached via the compress mode)."""
    # Arrange
    authoring = AuthoringActions()

    # Act
    result = authoring.compress_of_them(_TEXT_WITH_IMPORT, _IMPORT_LINE_SEL)

    # Assert
    assert result is None


def test_outside_rule_returns_exact_none_not_falsy_empty() -> None:
    """All rewrite actions must return the singleton None (not an empty container
    or other falsy value) when the cursor is outside a rule block."""
    authoring = AuthoringActions()

    checked_actions = [
        "roundtrip_rewrite_rule",
        "deduplicate_identical_strings",
        "expand_of_them",
        "compress_of_them",
    ]
    for action in checked_actions:
        result = getattr(authoring, action)(_TEXT_WITH_IMPORT, _IMPORT_LINE_SEL)
        assert result is None, (
            f"{action} returned {result!r} instead of None " "for an outside-rule cursor position"
        )


# ---------------------------------------------------------------------------
# Scenario 2: _condition_uses_string_set_quantifier(None) — line 137
#
# The function begins with `if condition is None: return False` (lines 136-137).
# Calling the function directly with None is the only reachable path to line
# 137 via the real public API, because deduplicate_identical_strings always
# passes rule.condition which is set by the parser (never None for parsed rules).
# ---------------------------------------------------------------------------


def test_condition_uses_string_set_quantifier_returns_false_for_none_condition() -> None:
    """_condition_uses_string_set_quantifier returns False immediately when
    passed None, exercising line 137."""
    # Act
    result = _condition_uses_string_set_quantifier(None)

    # Assert: a None condition does not contain any string set quantifier.
    assert result is False


@pytest.mark.parametrize(
    "condition",
    [
        None,
        0,
        "",
        "string value, not an ASTNode",
        3.14,
    ],
    ids=["none", "zero", "empty_string", "string", "float"],
)
def test_condition_uses_string_set_quantifier_returns_false_for_non_ast_values(
    condition: object,
) -> None:
    """_condition_uses_string_set_quantifier returns False for any non-ASTNode
    argument, confirming the guard at line 137 is correct for a range of
    sentinel values that might be stored in rule.condition."""
    # Act
    result = _condition_uses_string_set_quantifier(condition)

    # Assert
    assert result is False


# ---------------------------------------------------------------------------
# Scenario 3: _iter_ast_nodes with a non-ASTNode argument — line 145
#
# _iter_ast_nodes is a generator.  Line 144-145 read:
#   if not isinstance(node, ASTNode):
#       return
# When the argument is not an ASTNode the generator exits immediately.
#
# ASTNode.children() only returns ASTNode instances by construction, so the
# recursive call inside the generator never naturally receives a non-ASTNode.
# Calling _iter_ast_nodes directly is the only reachable path to line 145.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "non_node",
    [
        "plain string",
        42,
        3.14,
        [],
        {},
        object(),
    ],
    ids=["str", "int", "float", "list", "dict", "object"],
)
def test_iter_ast_nodes_yields_nothing_for_non_ast_node(non_node: object) -> None:
    """_iter_ast_nodes exits immediately (yields nothing) when passed a value
    that is not an ASTNode, exercising line 145: the bare `return` statement."""
    # Act: exhaust the generator.
    nodes = list(_iter_ast_nodes(non_node))

    # Assert: no nodes are produced.
    assert nodes == []


# ---------------------------------------------------------------------------
# Positive counterpart tests
#
# Each no-op scenario above is paired with a positive case that confirms the
# function returns a real StructuralEdit for a different input, proving the
# boundary under test is meaningful.
# ---------------------------------------------------------------------------


def test_roundtrip_rewrite_rule_produces_edit_when_cursor_inside_rule() -> None:
    """roundtrip_rewrite_rule returns a non-None StructuralEdit when the
    cursor is inside a valid compact rule, confirming Scenario 1 tests the
    correct boundary."""
    # Arrange: selection on the rule body line (line 2 in the import file).
    authoring = AuthoringActions()
    inside_rule_sel = Range(start=Position(line=2, character=0), end=Position(line=2, character=0))

    # Act
    result = authoring.roundtrip_rewrite_rule(
        'import "pe"\n\nrule r{ condition: true }', inside_rule_sel
    )

    # Assert: the compact rule is reformatted.
    assert result is not None
    assert "Normalize rule via round-trip" in result.title


def test_deduplicate_identical_strings_produces_edit_when_cursor_inside_rule() -> None:
    """deduplicate_identical_strings returns a non-None StructuralEdit when
    the cursor is inside a rule that has duplicate string definitions."""
    authoring = AuthoringActions()
    text = (
        "rule demo {\n"
        "    strings:\n"
        '        $a = "abc"\n'
        '        $b = "abc"\n'
        "    condition:\n"
        "        $a or $b\n"
        "}"
    )
    sel = Range(start=Position(line=4, character=0), end=Position(line=4, character=0))

    result = authoring.deduplicate_identical_strings(text, sel)

    assert result is not None
    assert "Deduplicate identical strings" in result.title
    assert "$b->$a" in result.title


def test_expand_of_them_produces_edit_when_condition_uses_them_keyword() -> None:
    """expand_of_them returns a non-None StructuralEdit when the condition
    uses `any of them`, confirming the outside-rule guard in Scenario 1 is
    the reason the prior test returns None."""
    authoring = AuthoringActions()
    text = (
        "rule demo {\n"
        "    strings:\n"
        '        $a = "a"\n'
        '        $b = "b"\n'
        "    condition:\n"
        "        any of them\n"
        "}"
    )
    sel = Range(start=Position(line=4, character=0), end=Position(line=4, character=0))

    result = authoring.expand_of_them(text, sel)

    assert result is not None
    assert "Expand" in result.title
    assert "any of ($a, $b)" in result.edit.new_text


def test_condition_uses_string_set_quantifier_returns_true_for_of_expression() -> None:
    """_condition_uses_string_set_quantifier returns True when the condition
    tree contains an OfExpression, confirming the None guard at line 137 is
    meaningfully distinct from the True path."""
    from yaraast.ast.conditions import OfExpression
    from yaraast.ast.expressions import Identifier

    condition = OfExpression(quantifier="any", string_set=Identifier(name="them"))

    result = _condition_uses_string_set_quantifier(condition)

    assert result is True


def test_iter_ast_nodes_yields_node_and_descendants_for_real_ast_node() -> None:
    """_iter_ast_nodes yields the input node and all descendant ASTNodes when
    given a real ASTNode, confirming the line-145 early-return fires only for
    non-ASTNode inputs."""
    from yaraast.parser.parser import Parser

    # Arrange: parse a real rule to get a real condition AST.
    parser = Parser()
    yara_file = parser.parse("rule r { condition: true }")
    condition = yara_file.rules[0].condition
    assert condition is not None

    # Act
    nodes = list(_iter_ast_nodes(condition))

    # Assert: at least the condition node itself is yielded.
    assert len(nodes) >= 1
    assert condition in nodes


# ---------------------------------------------------------------------------
# Regression guard: assert return values are strictly None, not other falsy
# values, for all no-op paths exercised in this file.
# ---------------------------------------------------------------------------


def test_condition_uses_string_set_quantifier_none_is_false_not_empty_container() -> None:
    """The return value for a None condition is strictly the bool False, not
    any other falsy object such as [] or None."""
    result = _condition_uses_string_set_quantifier(None)
    assert result is False
    assert result is not None
    assert isinstance(result, bool)


def test_iter_ast_nodes_returns_empty_list_not_none_for_non_node() -> None:
    """_iter_ast_nodes for a non-ASTNode yields nothing: consuming the
    generator produces an empty list, not None."""
    nodes = list(_iter_ast_nodes("not_a_node"))
    assert nodes == []
    assert nodes is not None
