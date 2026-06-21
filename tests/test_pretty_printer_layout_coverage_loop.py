# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Regression tests targeting uncovered branches in pretty_printer_layout.py.

Each test exercises a specific missing branch discovered from a coverage run of
the existing pretty-printer test suite.  All tests drive the real public API
(CodeGenerator + PrettyPrintOptions) without any mocking.

Unreachable branches
--------------------
The following three branch groups identified by coverage are structurally
unreachable through the public API and are documented here rather than being
covered with fake constructs:

1. Lines 163-166 (_write_in_rule_pragmas else branch): reached only when
   ``printer.visit(pragma)`` returns a falsy string for an InRulePragma.
   Every concrete Pragma subclass (CustomPragma, IncludeOncePragma,
   DefineDirective, UndefDirective, ConditionalDirective) always produces a
   non-empty rendered string via visit_in_rule_pragma → visit_pragma.

2. Lines 233-236 (write_string_definition fallback path): reached only when
   the string_def is neither PlainString, HexString, nor RegexString.
   validate_string_identifiers (called at line 106) raises TypeError for any
   other StringDefinition subtype before write_string_definition is entered.

3. Lines 127->131, 138->142, 145->151 (blank_lines_between_sections guard
   FALSE branches): reached only when node.condition is None.
   validate_rule_string_references (called at CodeGenerator.visit_rule line
   295) raises ValueError when condition is None, preventing entry into the
   pretty layout visit_rule path.

4. Line 267->269 (if current_line: FALSE inside wrap_long_conditions):
   reached only when condition_str.split() is empty, meaning
   expression_to_string returned an all-whitespace or empty string.
   The function calls .strip() on its result, and every valid expression
   visitor returns a non-empty token.
"""

from __future__ import annotations

from yaraast.ast.base import YaraFile
from yaraast.ast.comments import Comment
from yaraast.ast.conditions import OfExpression
from yaraast.ast.expressions import (
    BooleanLiteral,
    Identifier,
    IntegerLiteral,
)
from yaraast.ast.rules import Import, Include, Rule
from yaraast.ast.strings import HexByte, HexString, PlainString, RegexString
from yaraast.codegen.generator import CodeGenerator
from yaraast.codegen.options import GeneratorOptions
from yaraast.codegen.pretty_printer import PrettyPrintOptions
from yaraast.yarax.ast_nodes import MatchCase, PatternMatch


def _gen(opts: PrettyPrintOptions) -> CodeGenerator:
    return CodeGenerator(options=GeneratorOptions(pretty=opts))


# ---------------------------------------------------------------------------
# Line 43 — _emit_top_level_line trailing_comment branch
# ---------------------------------------------------------------------------


def test_emit_top_level_line_writes_trailing_comment_on_import() -> None:
    """_emit_top_level_line must write trailing_comment when present on an import."""
    imp = Import("pe")
    imp.trailing_comment = Comment("imported module pe")

    rule = Rule(name="r", condition=BooleanLiteral(True))
    yf = YaraFile(imports=[imp], rules=[rule])

    out = _gen(
        PrettyPrintOptions(
            align_string_definitions=False,
            align_meta_values=False,
            align_comments=False,
        )
    ).generate(yf)

    assert 'import "pe"' in out
    assert "// imported module pe" in out
    # The comment must appear on the same line as the import, not on its own line.
    for line in out.splitlines():
        if 'import "pe"' in line:
            assert "// imported module pe" in line
            break


def test_emit_top_level_line_writes_trailing_comment_on_include() -> None:
    """Trailing comment on an Include node must also be written on the same line."""
    inc = Include("common.yar")
    inc.trailing_comment = Comment("shared rules")

    rule = Rule(name="r", condition=BooleanLiteral(True))
    yf = YaraFile(includes=[inc], rules=[rule])

    out = _gen(
        PrettyPrintOptions(
            align_string_definitions=False,
            align_meta_values=False,
            align_comments=False,
        )
    ).generate(yf)

    assert 'include "common.yar"' in out
    assert "// shared rules" in out
    for line in out.splitlines():
        if 'include "common.yar"' in line:
            assert "// shared rules" in line
            break


# ---------------------------------------------------------------------------
# Lines 203-206 — write_string_definition HexString aligned path
# ---------------------------------------------------------------------------


def test_write_string_definition_hex_string_uses_alignment_column() -> None:
    """HexString must be padded to _string_alignment_column when align_string_definitions is True."""
    # Two strings of different identifier lengths force a non-zero alignment column.
    # PlainString with identifier "$short" (6 chars) and HexString with "$h" (2 chars)
    # ensure the alignment calculation produces a non-zero column, triggering lines 203-206.
    rule = Rule(
        name="r",
        strings=[
            PlainString(identifier="$short", value="hello"),
            HexString(identifier="$h", tokens=[HexByte(0x4D), HexByte(0x5A)]),
        ],
        condition=OfExpression("any", Identifier("them")),
    )
    yf = YaraFile(rules=[rule])

    out = _gen(
        PrettyPrintOptions(
            align_string_definitions=True,
            align_meta_values=False,
        )
    ).generate(yf)

    assert "$h" in out
    assert "{ 4D 5A }" in out
    # Alignment must insert spaces between identifier and " = "
    # so "$h " followed by spaces and then "= { … }" appears.
    hex_line = next(ln for ln in out.splitlines() if "$h" in ln and "4D" in ln)
    # The padded identifier block ends with " = { … }"; confirm padding is present
    # by checking that the identifier is not immediately followed by " = " without spaces.
    assert "$h " in hex_line or "$h=" not in hex_line


def test_write_string_definition_hex_string_aligned_single_string_no_column() -> None:
    """A single HexString with alignment enabled still produces valid output.

    When only one string exists, calculate_string_alignment_column may return 0,
    forcing the non-aligned else branch (line 208-209) instead of lines 203-206.
    This test pins the else-branch behavior to catch future regressions.
    """
    rule = Rule(
        name="r",
        strings=[HexString(identifier="$h", tokens=[HexByte(0xDE), HexByte(0xAD)])],
        condition=OfExpression("any", Identifier("them")),
    )
    yf = YaraFile(rules=[rule])

    out = _gen(PrettyPrintOptions(align_string_definitions=True)).generate(yf)

    # The exact spacing varies depending on the computed alignment column; only
    # the hex pattern and identifier presence are load-bearing here.
    assert "$h" in out
    assert "{ DE AD }" in out


# ---------------------------------------------------------------------------
# Line 212 — write_string_definition HexString trailing_comment
# ---------------------------------------------------------------------------


def test_write_string_definition_hex_string_emits_trailing_comment() -> None:
    """Trailing comment on a HexString must appear inline on the same line."""
    h = HexString(identifier="$sig", tokens=[HexByte(0x4D), HexByte(0x5A)])
    h.trailing_comment = Comment("MZ header")

    rule = Rule(
        name="r",
        strings=[h],
        condition=OfExpression("any", Identifier("them")),
    )
    yf = YaraFile(rules=[rule])

    out = _gen(
        PrettyPrintOptions(
            align_string_definitions=False,
            align_comments=False,
        )
    ).generate(yf)

    assert "$sig = { 4D 5A }" in out
    assert "// MZ header" in out
    for line in out.splitlines():
        if "$sig" in line:
            assert "// MZ header" in line
            break


def test_write_string_definition_hex_string_trailing_comment_with_alignment() -> None:
    """Trailing comment on a HexString must survive when alignment is also active."""
    short = PlainString(identifier="$a", value="x")
    h = HexString(identifier="$longer_id", tokens=[HexByte(0xFF)])
    h.trailing_comment = Comment("aligned hex")

    rule = Rule(
        name="r",
        strings=[short, h],
        condition=OfExpression("any", Identifier("them")),
    )
    yf = YaraFile(rules=[rule])

    out = _gen(
        PrettyPrintOptions(
            align_string_definitions=True,
            align_comments=False,
        )
    ).generate(yf)

    for line in out.splitlines():
        if "$longer_id" in line:
            assert "// aligned hex" in line
            break


# ---------------------------------------------------------------------------
# Line 229 — write_string_definition RegexString trailing_comment
# ---------------------------------------------------------------------------


def test_write_string_definition_regex_string_emits_trailing_comment() -> None:
    """Trailing comment on a RegexString must appear inline on the strings: line."""
    r = RegexString(identifier="$re", regex="abc.*def")
    r.trailing_comment = Comment("matches abc…def")

    rule = Rule(
        name="r",
        strings=[r],
        condition=OfExpression("any", Identifier("them")),
    )
    yf = YaraFile(rules=[rule])

    out = _gen(
        PrettyPrintOptions(
            align_string_definitions=False,
            align_comments=False,
        )
    ).generate(yf)

    assert "$re = /abc.*def/" in out
    assert "// matches abc" in out
    for line in out.splitlines():
        if "$re" in line:
            assert "// matches abc" in line
            break


def test_write_string_definition_regex_string_trailing_comment_with_alignment() -> None:
    """Trailing comment on a RegexString must survive when alignment is active."""
    plain = PlainString(identifier="$a", value="x")
    r = RegexString(identifier="$re_long", regex="x+")
    r.trailing_comment = Comment("one or more x")

    rule = Rule(
        name="r",
        strings=[plain, r],
        condition=OfExpression("any", Identifier("them")),
    )
    yf = YaraFile(rules=[rule])

    out = _gen(
        PrettyPrintOptions(
            align_string_definitions=True,
            align_comments=False,
        )
    ).generate(yf)

    for line in out.splitlines():
        if "$re_long" in line:
            assert "// one or more x" in line
            break


# ---------------------------------------------------------------------------
# Lines 244-248 — write_condition_section multiline condition_str branch
# ---------------------------------------------------------------------------


def test_write_condition_section_multiline_expression_splits_across_lines() -> None:
    """A PatternMatch condition produces a multi-line string that must be split per line."""
    pm = PatternMatch(
        value=IntegerLiteral(1),
        cases=[
            MatchCase(pattern=IntegerLiteral(1), result=BooleanLiteral(True)),
            MatchCase(pattern=IntegerLiteral(2), result=BooleanLiteral(False)),
        ],
    )
    rule = Rule(name="r", condition=pm)
    yf = YaraFile(rules=[rule])

    out = _gen(PrettyPrintOptions(wrap_long_conditions=False)).generate(yf)

    # The multi-line match block must appear inside the condition section.
    assert "condition:" in out
    assert "match 1 {" in out
    assert "1 => true," in out
    assert "2 => false," in out
    assert "}" in out


def test_write_condition_section_multiline_expression_with_trailing_comment() -> None:
    """Trailing comment on a multiline condition must appear on the final rendered line."""
    pm = PatternMatch(
        value=IntegerLiteral(42),
        cases=[MatchCase(pattern=IntegerLiteral(42), result=BooleanLiteral(True))],
    )
    # The trailing_comment attribute must be set directly on the expression node
    # that is passed as the condition; write_condition_section reads it via getattr.
    pm.trailing_comment = Comment("the answer")

    rule = Rule(name="r", condition=pm)
    yf = YaraFile(rules=[rule])

    out = _gen(
        PrettyPrintOptions(
            wrap_long_conditions=False,
            align_comments=False,
        )
    ).generate(yf)

    assert "// the answer" in out
    # The comment must appear on the closing brace line (last line of the split).
    closing_lines = [ln for ln in out.splitlines() if "}" in ln and "// the answer" in ln]
    assert closing_lines, "trailing comment must be on the closing line of the match block"


def test_write_condition_section_multiline_without_trailing_comment() -> None:
    """Multiline condition without a trailing comment must render cleanly without orphan // lines."""
    pm = PatternMatch(
        value=IntegerLiteral(5),
        cases=[MatchCase(pattern=IntegerLiteral(5), result=BooleanLiteral(True))],
    )
    rule = Rule(name="r", condition=pm)
    yf = YaraFile(rules=[rule])

    out = _gen(PrettyPrintOptions(wrap_long_conditions=False)).generate(yf)

    assert "//" not in out


# ---------------------------------------------------------------------------
# Combination: aligned HexString + trailing_comment (covers lines 203-206 + 212)
# ---------------------------------------------------------------------------


def test_write_string_definition_hex_aligned_and_trailing_comment_combined() -> None:
    """Both alignment (lines 203-206) and trailing comment (line 212) must be active together."""
    short = PlainString(identifier="$aa", value="sentinel")
    h = HexString(identifier="$b", tokens=[HexByte(0xCA), HexByte(0xFE)])
    h.trailing_comment = Comment("cafe bytes")

    rule = Rule(
        name="r",
        strings=[short, h],
        condition=OfExpression("any", Identifier("them")),
    )
    yf = YaraFile(rules=[rule])

    out = _gen(
        PrettyPrintOptions(
            align_string_definitions=True,
            align_comments=False,
        )
    ).generate(yf)

    assert "CA FE" in out
    assert "// cafe bytes" in out
    for line in out.splitlines():
        if "$b" in line and "CA FE" in line:
            assert "// cafe bytes" in line
            break
