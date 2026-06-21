# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""Regression tests for in-place string renaming inside compound expressions.

``_rename_strings_in_expression`` renames string identifiers in place and
always returns the same node it was given. The Binary/Unary/Parentheses
branches previously reconstructed a new node when a child "changed identity",
but that never happened (the recursion mutates and returns the same object),
so those branches were dead. These tests pin that the rename still propagates
into binary, unary, and parenthesized sub-expressions.
"""

from __future__ import annotations

from yaraast.builder.ast_transformer import RuleTransformer
from yaraast.codegen.generator import CodeGenerator
from yaraast.parser.parser import Parser


def _rename_condition(condition: str, mapping: dict[str, str]) -> str:
    ast = Parser(f'rule t {{ strings: $a = "x" condition: {condition} }}').parse()
    transformer = RuleTransformer(ast.rules[0])
    transformer.rename_strings(mapping)
    return CodeGenerator().generate(transformer.build())


def test_rename_inside_binary_expression() -> None:
    out = _rename_condition("$a and $a", {"$a": "$z"})
    assert "$z" in out
    assert "$a " not in out


def test_rename_inside_unary_expression() -> None:
    out = _rename_condition("not $a", {"$a": "$z"})
    assert "$z" in out
    assert "$a " not in out


def test_rename_inside_parentheses_expression() -> None:
    out = _rename_condition("($a)", {"$a": "$z"})
    assert "$z" in out
    assert "$a " not in out


def test_rename_inside_nested_compound_expression() -> None:
    out = _rename_condition("$a and (not $a)", {"$a": "$z"})
    assert "$z" in out
    assert "$a " not in out
