"""
Copyright (c) 2026 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.

Regression tests for yaraast.codegen.generator_comment_sections covering
the lines and branches that remain uncovered after the baseline test suite.

Missing coverage targeted here (as reported by pytest-cov term-missing):
  - Lines 49-52  : _top_level_end_line with and without end_line set
  - Lines 56-58  : _write_source_gap body
  - Line  67     : _write_ordered_top_level_nodes gap between successive nodes
  - Line  71     : _write_ordered_top_level_nodes else-branch (non-Rule node)
  - Lines 86-87  : comment_visit_yara_file trailing_comment in ordered path
  - Lines 152-160: _write_rule_pragmas with leading + trailing comments
  - Line  177    : _write_meta_section elif hasattr(meta, "key") branch
  - Line  210    : _write_condition_section early return when condition is None
  - Branch 216->219: condition without leading_comments attribute
  - Line  229    : multi-line condition_str with trailing comment on last line
  - Line  238    : elif trailing path when condition_str is empty

Strategy: build AST nodes directly, attach location objects where the
source-order path requires them, and drive generation through
CodeGenerator.generate() with preserve_comments=True.  No mocks or stubs.
"""

from __future__ import annotations

from types import SimpleNamespace

from yaraast.ast.base import Location, YaraFile
from yaraast.ast.comments import Comment
from yaraast.ast.conditions import Condition
from yaraast.ast.expressions import BooleanLiteral, IntegerLiteral
from yaraast.ast.pragmas import IncludeOncePragma, InRulePragma
from yaraast.ast.rules import Import, Rule
from yaraast.codegen.generator import CodeGenerator
from yaraast.codegen.options import GeneratorOptions
from yaraast.yarax.ast_nodes import MatchCase, PatternMatch

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _comment_gen() -> CodeGenerator:
    """Return a comment-aware generator ready to accept a YaraFile."""
    return CodeGenerator(options=GeneratorOptions.comment_aware())


def _loc(line: int, col: int = 1, *, end_line: int | None = None) -> Location:
    """Create a Location with optional end_line."""
    return Location(line=line, column=col, end_line=end_line)


# ---------------------------------------------------------------------------
# Tests: _top_level_end_line — lines 49-52
#
# The function returns end_line when it is not None, otherwise falls back
# to location.line.  Both branches are exercised below through the
# source-order path of comment_visit_yara_file.
# ---------------------------------------------------------------------------


def test_source_order_uses_end_line_when_set() -> None:
    """_top_level_end_line returns end_line (line 51) when it is populated.

    Two imports are given locations so that the ordered path is chosen.
    The first import has end_line set, which forces _top_level_end_line
    to take the end_line branch.  The gap calculation between the two nodes
    then uses that value, producing no blank lines when end_line == line.
    """
    imp1 = Import("pe")
    imp1.location = _loc(1, end_line=1)

    imp2 = Import("math")
    imp2.location = _loc(2)

    yara_file = YaraFile(imports=[imp1, imp2])

    out = _comment_gen().generate(yara_file)

    assert 'import "pe"' in out
    assert 'import "math"' in out


def test_source_order_uses_location_line_when_end_line_absent() -> None:
    """_top_level_end_line falls back to location.line (line 52) when
    end_line is None.

    Same two-import setup but without end_line, so the fallback path is
    exercised.
    """
    imp1 = Import("pe")
    imp1.location = _loc(1)  # end_line defaults to None

    imp2 = Import("math")
    imp2.location = _loc(3)

    yara_file = YaraFile(imports=[imp1, imp2])

    out = _comment_gen().generate(yara_file)

    assert 'import "pe"' in out
    assert 'import "math"' in out
    # One blank line between the two imports because gap_lines == 1
    assert 'import "pe"\n\nimport "math"' in out


# ---------------------------------------------------------------------------
# Tests: _write_source_gap and gap between successive ordered nodes
# Lines 56-58 and line 67
# ---------------------------------------------------------------------------


def test_source_gap_inserts_blank_lines_between_ordered_nodes() -> None:
    """_write_source_gap (lines 56-58) and the gap call in
    _write_ordered_top_level_nodes (line 67) run whenever there are at
    least two top-level nodes with locations and a gap between them.

    Three imports spread across lines 1, 3, and 6 produce two gaps of
    one and two blank lines respectively.
    """
    imp1 = Import("pe")
    imp1.location = _loc(1, end_line=1)

    imp2 = Import("math")
    imp2.location = _loc(3)

    imp3 = Import("elf")
    imp3.location = _loc(6)

    yara_file = YaraFile(imports=[imp1, imp2, imp3])

    out = _comment_gen().generate(yara_file)

    # Gap of 1 between imp1 (line 1) and imp2 (line 3) → one blank line
    assert 'import "pe"\n\nimport "math"' in out
    # Gap of 2 between imp2 (line 3) and imp3 (line 6) → two blank lines
    assert 'import "math"\n\n\nimport "elf"' in out


# ---------------------------------------------------------------------------
# Tests: _write_ordered_top_level_nodes else-branch (non-Rule node) — line 71
# ---------------------------------------------------------------------------


def test_ordered_path_handles_non_rule_node() -> None:
    """The else-branch (line 71) in _write_ordered_top_level_nodes calls
    _write_top_level_node for any node that is not a Rule instance.

    An Import alongside a Rule (both with locations) forces the ordered
    path; the Import is the non-Rule node that hits line 71.
    """
    imp = Import("pe")
    imp.location = _loc(1, end_line=1)
    imp.leading_comments = [Comment("// before import")]
    imp.trailing_comment = Comment("import inline")

    rule = Rule(name="ordered_rule", condition=BooleanLiteral(True))
    rule.location = _loc(3)

    yara_file = YaraFile(imports=[imp], rules=[rule])

    out = _comment_gen().generate(yara_file)

    assert "// before import" in out
    assert 'import "pe"  // import inline' in out
    assert "rule ordered_rule" in out


# ---------------------------------------------------------------------------
# Tests: comment_visit_yara_file trailing_comment in ordered path — lines 86-87
# ---------------------------------------------------------------------------


def test_file_trailing_comment_written_in_ordered_path() -> None:
    """Lines 86-87 run when the ordered path is active and the YaraFile
    carries a trailing_comment.

    One import with a location triggers the ordered path; attaching a
    trailing_comment to the YaraFile ensures lines 85-87 execute.
    """
    imp = Import("pe")
    imp.location = _loc(1)

    yara_file = YaraFile(imports=[imp])
    yara_file.trailing_comment = Comment("// end of file")

    out = _comment_gen().generate(yara_file)

    assert "// end of file" in out
    assert 'import "pe"' in out


# ---------------------------------------------------------------------------
# Tests: _write_rule_pragmas with leading and trailing comments — lines 152-160
# ---------------------------------------------------------------------------


def test_rule_pragma_with_leading_and_trailing_comments() -> None:
    """Lines 152-160 in _write_rule_pragmas run when the rule has an
    InRulePragma that (a) matches the requested position, (b) has
    leading_comments, and (c) has a trailing_comment.

    IncludeOncePragma wrapped in InRulePragma at 'before_strings' position
    exercises the full comment-rendering loop inside _write_rule_pragmas.
    """
    pragma = IncludeOncePragma()
    in_rule_pragma = InRulePragma(pragma=pragma, position="before_strings")
    in_rule_pragma.leading_comments = [Comment("// pragma lead")]
    in_rule_pragma.trailing_comment = Comment("pragma trail")

    rule = Rule(
        name="pragma_rule",
        pragmas=[in_rule_pragma],
        condition=BooleanLiteral(True),
    )
    yara_file = YaraFile(rules=[rule])

    out = _comment_gen().generate(yara_file)

    assert "// pragma lead" in out
    assert "#include_once" in out
    assert "pragma trail" in out


def test_rule_pragma_with_leading_comments_only() -> None:
    """Exercises lines 154-157 without a trailing comment so that the
    trailing branch at line 158 is not taken.  Together with the test
    above, both sub-branches of _write_rule_pragmas are covered.
    """
    pragma = IncludeOncePragma()
    in_rule_pragma = InRulePragma(pragma=pragma, position="before_condition")
    in_rule_pragma.leading_comments = [Comment("// before condition pragma")]

    rule = Rule(
        name="pragma_no_trail",
        pragmas=[in_rule_pragma],
        condition=BooleanLiteral(True),
    )
    yara_file = YaraFile(rules=[rule])

    out = _comment_gen().generate(yara_file)

    assert "// before condition pragma" in out
    assert "#include_once" in out


# ---------------------------------------------------------------------------
# Tests: _write_meta_section elif hasattr(meta, "key") branch — line 177
#
# The elif branch fires for a meta-like duck-type object that exposes
# .key and .value but does not define accept().  SimpleNamespace is the
# lightest object that satisfies the condition without registering a
# visitor method.
# ---------------------------------------------------------------------------


def test_meta_section_handles_duck_type_meta_item_without_accept() -> None:
    """Line 177 is reached when a meta entry lacks accept() but has .key.

    A SimpleNamespace with key/value attributes is placed in rule.meta
    alongside a leading_comment and trailing_comment.  The generator must
    call _write_meta_item (line 178) instead of gen.visit.
    """
    duck_meta = SimpleNamespace(key="author", value="alice")
    # Satisfy leading_comments / trailing_comment protocol expected by
    # _write_meta_section
    duck_meta.leading_comments = []
    duck_meta.trailing_comment = None

    rule = Rule(name="duck_meta_rule", meta=[duck_meta], condition=BooleanLiteral(True))
    yara_file = YaraFile(rules=[rule])

    out = _comment_gen().generate(yara_file)

    assert 'author = "alice"' in out


def test_meta_section_duck_type_item_with_scope_attribute() -> None:
    """Same elif branch (line 177) with an optional scope attribute to
    confirm getattr(meta, 'scope', None) path in line 178.
    """
    duck_meta = SimpleNamespace(key="version", value=2, scope=None)
    duck_meta.leading_comments = []
    duck_meta.trailing_comment = None

    rule = Rule(name="scoped_meta_rule", meta=[duck_meta], condition=BooleanLiteral(True))
    yara_file = YaraFile(rules=[rule])

    out = _comment_gen().generate(yara_file)

    assert "version = 2" in out


# ---------------------------------------------------------------------------
# Note: _write_condition_section condition is None — line 210 is genuinely
# unreachable through the public API.
#
# validate_rule_string_references() (called from CodeGenerator.visit_rule
# before the layout's visit_rule delegates to comment_visit_rule) raises
# ValueError when condition is None.  The guard at line 210 is therefore a
# defensive check that can never be reached through CodeGenerator.generate().
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Tests: branch 216->219 — condition without leading_comments attribute
# ---------------------------------------------------------------------------


def test_condition_without_leading_comments_attribute_skips_write() -> None:
    """Branch miss 216->219: the False branch of
    'if hasattr(condition, "leading_comments")' runs when the condition
    node lacks that attribute entirely.

    A plain Condition() subclass instance stripped of its leading_comments
    attribute exercises the branch where _write_leading_comments is not
    called.
    """

    class _BareLiteralCondition(BooleanLiteral):
        """BooleanLiteral variant without leading_comments."""

        def __init__(self, value: bool) -> None:
            super().__init__(value)
            # Remove the attribute that ASTNode.__init__ populates so the
            # hasattr check on line 216 returns False.
            object.__delattr__(self, "leading_comments")

    condition = _BareLiteralCondition(True)
    rule = Rule(name="bare_cond_rule", condition=condition)
    yara_file = YaraFile(rules=[rule])

    out = _comment_gen().generate(yara_file)

    assert "condition:" in out
    assert "true" in out


# ---------------------------------------------------------------------------
# Tests: multi-line condition_str with trailing comment on last line — line 229
# ---------------------------------------------------------------------------


def test_multiline_condition_with_trailing_comment_appended_to_last_line() -> None:
    """Line 229 runs inside the multi-line branch of _write_condition_section
    when both condition_str contains '\\n' AND condition.trailing_comment is
    set.  The comment is written inline on the final line of the expression.

    PatternMatch generates a multi-line YARA expression and is the
    canonical source of '\\n' in condition_str.
    """
    condition = PatternMatch(
        value=IntegerLiteral(1),
        cases=[MatchCase(pattern=IntegerLiteral(1), result=BooleanLiteral(True))],
        default=BooleanLiteral(False),
    )
    condition.trailing_comment = Comment("match trail")

    rule = Rule(name="multiline_trail_rule", condition=condition)
    yara_file = YaraFile(rules=[rule])

    out = _comment_gen().generate(yara_file)

    # The trailing comment must appear on the last line of the match block,
    # not on a separate line.
    assert "// match trail" in out
    # Confirm the match expression itself is present
    assert "match 1 {" in out
    assert "1 => true," in out


# ---------------------------------------------------------------------------
# Tests: elif trailing when condition_str is empty — line 238
#
# visit_condition() returns "" for a bare Condition() node.  If that node
# also carries a trailing_comment, line 238 executes.
# ---------------------------------------------------------------------------


def test_condition_str_empty_with_trailing_comment_uses_elif_branch() -> None:
    """Line 238 is the elif branch reached when gen.visit(condition)
    returns an empty string and condition carries a trailing_comment.

    Condition() is the only standard node whose visitor returns "".  When
    it also carries a trailing_comment, _write_condition_section falls
    through to the elif at line 237 and calls _write_comment (line 238).
    """
    condition = Condition()
    condition.trailing_comment = Comment("empty condition trail")

    rule = Rule(name="empty_cond_trail_rule", condition=condition)
    yara_file = YaraFile(rules=[rule])

    out = _comment_gen().generate(yara_file)

    assert "condition:" in out
    assert "// empty condition trail" in out
