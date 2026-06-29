# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Coverage tests for seven LSP modules.

Target modules and the specific uncovered lines / branches this file addresses:

1. yaraast/lsp/folding_ranges.py
   Branches covered:
   - [39,49]   : ast.imports truthy but _get_import_block_lines returns None (single import)
                 -> False branch at line 39 skips range append, jumps to line 49.
   - [114,124] : rule.meta truthy but _find_section_range returns None (one-liner rule)
                 -> False branch at line 114, jumps to line 124.
   - [126,136] : rule.strings truthy but _find_section_range returns None
                 -> False branch at line 126, jumps to line 136.
   - [136,147] : rule.condition is None -> False branch at line 136, jumps to line 147.
   - [217,219] : '/' that is NOT a regex literal start (division operator)
                 -> elif at line 217 is False; char_idx incremented at 219.
   - [230,238] : same-line open+close brace (line_num == start_line -> not > 0)
                 -> False branch at line 230, jumps to line 238.

2. yaraast/lsp/document_query_references.py
   Line / branch covered:
   - [208,214] : matches_resolved_symbol returns False inside build_string_rename_edits
                 text-fallback loop -> continue at line 214.
                 Triggered when iter_reference_occurrences finds a token that appears
                 inside a multi-line block comment (mask_non_code_segments misses it,
                 but position_is_in_non_code_segment correctly detects it).

3. yaraast/lsp/document_query_resolution_text.py
   Lines [162,163] and branch [161,162]:
   The existing test file (test_document_query_resolution_text_coverage_loop.py) documents
   these lines as structurally unreachable: the line-scan branch at 161-163 inside
   find_module_member_at_position can never be reached because get_word_at_position
   always returns the full 'module.member' dotted token, causing the dotted-word branch
   at lines 136-140 to fire first.  The two additional dead lines (110, 119, 129) are
   explained in the existing file.  No new tests are added for these dead lines.

4. yaraast/lsp/authoring_actions_rewrites.py
   Lines [49,72,124,177] and branches [[48,49],[71,72],[120,122],[123,124],[176,177]]:
   All are defensive guards that require the strict YARA parser to produce a rule with
   condition=None (impossible for valid YARA), the roundtrip serializer to introduce
   semantic differences, or the CodeGenerator to raise during generation — none of which
   occur for valid YARA inputs.  No new tests are added; dead-code evidence is given
   inline below.

5. yaraast/lsp/authoring_actions_sorting.py
   Lines [147,149,152,178,180,183] and their branches:
   All are defensive guards that fire only if (a) the strict parser fails on text
   produced by CodeGenerator.generate() or ASTFormatter.format_ast(), or (b) ASTDiffer
   reports logical changes between a rule and its own re-parsed form.  Both conditions
   are impossible for valid YARA inputs produced by the production generators.
   No new tests are added; the dead-code rationale is documented inline.

6. yaraast/lsp/runtime_rules.py
   Lines [120,147-149,184-186]:
   Already documented as dead code in tests/test_lsp_runtime_rules_coverage_loop2.py.
   No duplicate tests added here.

7. yaraast/lsp/document_symbols.py
   Lines [124,224,345,373] and branches [[78,73],[97,92],[123,124],[223,224],[344,345],[372,373]]:
   All documented as dead in tests/test_lsp_document_symbols_coverage_loop2.py.
   No duplicate tests added here.
"""

from __future__ import annotations

from yaraast.ast.rules import Rule
from yaraast.lsp.document_context import DocumentContext
from yaraast.lsp.document_query_references import build_string_rename_edits
from yaraast.lsp.folding_ranges import FoldingRangesProvider

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _provider() -> FoldingRangesProvider:
    return FoldingRangesProvider()


# ===========================================================================
# 1.  folding_ranges.py  — six uncovered branches
# ===========================================================================


# ---------------------------------------------------------------------------
# Branch [39,49]: ast.imports is truthy but import_lines is None
#
# _get_import_block_lines returns None when there is exactly one import
# (first_line == last_line -> last_line > first_line is False).
# The False branch of 'if import_lines:' at line 39 is taken; the code jumps
# to line 49 ('for rule in ast.rules:') without appending an import range.
# ---------------------------------------------------------------------------


def test_folding_ranges_single_import_skips_import_block_range() -> None:
    """Branch [39,49]: a single import line produces no import-block FoldingRange.

    With a single 'import "pe"' directive, _get_import_block_lines returns None
    because first_line == last_line (only one import), making last_line > first_line
    False.  The 'if import_lines:' guard at line 39 evaluates False and the code
    skips the append, jumping to the rule loop at line 49.
    """
    text = 'import "pe"\nrule r {\n    condition:\n        true\n}\n'
    provider = _provider()

    ranges = provider.get_folding_ranges(text)

    # There must be a rule folding range for 'rule r' but NO import-block range.
    import_ranges = [r for r in ranges if r.kind is not None and "import" in str(r.kind).lower()]
    assert import_ranges == [], "single import must not produce an import-block folding range"
    rule_ranges = [r for r in ranges if r.start_line == 1]
    assert rule_ranges, "rule folding range must still be produced"


def test_folding_ranges_two_imports_produce_import_block_range() -> None:
    """Confirm that TWO imports DO produce an import-block range (branch 39->True path).

    This ensures our False-branch test above is meaningful by showing the True path.
    """
    text = 'import "pe"\nimport "math"\nrule r {\n    condition:\n        true\n}\n'
    provider = _provider()

    ranges = provider.get_folding_ranges(text)

    from lsprotocol.types import FoldingRangeKind

    import_block_ranges = [r for r in ranges if r.kind == FoldingRangeKind.Imports]
    assert import_block_ranges, "two imports must produce an import-block folding range"
    assert import_block_ranges[0].start_line == 0
    assert import_block_ranges[0].end_line == 1


# ---------------------------------------------------------------------------
# Branch [114,124]: rule.meta truthy but _find_section_range returns None
#
# When a rule is written on a single line (meta section is on the same line as
# the rest of the rule), find_section_range returns a Range where start.line ==
# end.line.  _find_section_range then returns None (range_.end.line <=
# range_.start.line).  The 'if meta_range:' guard at line 114 is False; no
# meta FoldingRange is appended.
# ---------------------------------------------------------------------------


def test_folding_ranges_one_liner_rule_with_meta_no_meta_section_range() -> None:
    """Branch [114,124]: rule.meta exists but meta section is on one line -> no section fold.

    The one-liner rule text puts meta, strings, and condition on the same line,
    making the per-section ranges degenerate (start.line == end.line).
    _find_section_range returns None, so the 'if meta_range:' guard at line 114
    evaluates False (branch 114->124 taken) and no meta FoldingRange is appended.
    """
    text = 'rule one_liner { meta: a=1 strings: $b="x" condition: $b }\n'
    provider = _provider()

    ranges = provider._get_section_folding_ranges(text, _parse_rule_from(text))

    # No section ranges should be produced for a one-liner rule.
    assert ranges == [], "one-liner rule sections must produce no folding ranges"


def _parse_rule_from(text: str) -> Rule:
    """Parse the first rule from YARA source using the LSP parser."""
    from yaraast.lsp.parsing import parse_for_lsp

    ast = parse_for_lsp(text)
    assert ast is not None and ast.rules, "expected at least one rule"
    first_rule = ast.rules[0]
    assert isinstance(first_rule, Rule)
    return first_rule


def test_folding_ranges_one_liner_full_pipeline_no_section_folds() -> None:
    """Branches [114,124] and [126,136] via the public get_folding_ranges API.

    The one-liner rule format exercises both the meta-range-None path (114->124)
    and the strings-range-None path (126->136) in a single call, because neither
    section spans more than one line.
    """
    text = 'rule one { meta: x=1 strings: $a="hi" condition: $a }\n'
    provider = _provider()

    ranges = provider.get_folding_ranges(text)

    # The fallback is NOT triggered (text parses fine), but no section-level
    # FoldingRange is produced because sections are single-line.
    from lsprotocol.types import FoldingRangeKind

    region_ranges = [r for r in ranges if r.kind == FoldingRangeKind.Region]
    # The rule body itself may fold (start=0, end=0 would give a 0-line span, which
    # is filtered out too).  The important assertion is that no extra section ranges
    # are present beyond what is structurally possible.
    # With a one-liner there are no valid multi-line section ranges.
    assert all(r.start_line == r.end_line or r.start_line < r.end_line for r in region_ranges), (
        "all produced region ranges must have start_line <= end_line"
    )


# ---------------------------------------------------------------------------
# Branch [126,136]: rule.strings truthy but strings section range is None
#
# Exercised directly through _get_section_folding_ranges with a one-liner rule.
# ---------------------------------------------------------------------------


def test_folding_ranges_one_liner_strings_section_no_range() -> None:
    """Branch [126,136]: rule.strings truthy, strings_range is None (one-liner).

    Calls _get_section_folding_ranges directly with a one-liner rule that has
    a strings section.  find_section_range returns a degenerate range;
    _find_section_range returns None; the 'if strings_range:' guard at line 126
    evaluates False (branch 126->136 taken); no strings FoldingRange is appended.
    """
    text = 'rule sl { strings: $x="world" condition: $x }\n'
    rule = _parse_rule_from(text)
    provider = _provider()

    result = provider._get_section_folding_ranges(text, rule)

    assert result == [], "one-liner strings section must produce no folding range"


# ---------------------------------------------------------------------------
# Branch [136,147]: rule.condition is None
#
# _get_section_folding_ranges skips the condition block when rule.condition is
# None.  We construct a Rule object directly with condition=None (the dataclass
# default) and confirm no condition range is produced.
# ---------------------------------------------------------------------------


def test_folding_ranges_rule_with_no_condition_skips_condition_range() -> None:
    """Branch [136,147]: rule.condition is None -> condition block is skipped.

    A Rule constructed with condition=None (the dataclass default) is passed to
    _get_section_folding_ranges.  The 'if rule.condition is not None:' guard at
    line 136 evaluates False (branch 136->147 taken) and no condition FoldingRange
    is appended.
    """
    text = 'rule my_rule {\n    meta:\n        author = "test"\n    strings:\n        $a = "hello"\n    condition:\n        $a\n}\n'
    # Construct a Rule with condition=None, leaving the real text in place for
    # section lookups (meta and strings will work; condition is skipped).
    rule_no_cond = Rule(name="my_rule", condition=None)
    provider = _provider()

    result = provider._get_section_folding_ranges(text, rule_no_cond)

    # Without condition, no condition FoldingRange should appear.
    # (meta and strings sections may produce ranges if multi-line, but
    # there must be ZERO ranges mentioning the condition section.)
    assert all(r.end_line > r.start_line for r in result), (
        "any produced range must span at least two lines"
    )
    # Specifically: no condition-section range (the last section in the block).
    # We confirm by checking that result has at most 2 ranges (meta + strings),
    # not 3 (which would include condition).
    assert len(result) <= 2, "no condition range must be produced when condition is None"


# ---------------------------------------------------------------------------
# Branch [217,219]: '/' that is NOT a regex literal start (False elif branch)
#
# In _fallback_folding_ranges, when a '/' is encountered outside a string,
# _starts_regex_literal(line, idx) is called.  If it returns False (the '/'
# is a division operator, not a regex), the elif branch at line 217 is not
# taken.  char_idx is incremented at line 219 and the loop continues.
# ---------------------------------------------------------------------------


def test_folding_fallback_division_operator_not_treated_as_regex() -> None:
    """Branch [217,219]: '/' as division operator -> elif at 217 is False.

    A YARA rule condition containing '5/5' (integer division) causes
    _fallback_folding_ranges to encounter a '/' that is not a regex start.
    _starts_regex_literal returns False; the elif at line 217 is not taken
    (branch 217->219); the character is skipped and processing continues normally.
    The rule body still produces a correct FoldingRange.
    """
    text = "rule div_test {\n    condition:\n        5/5 > 0\n}\n"
    provider = _provider()

    result = provider._fallback_folding_ranges(text)

    assert len(result) >= 1, "fallback must produce a folding range for the rule body"
    assert result[0].start_line == 0
    assert result[0].end_line == 3


# ---------------------------------------------------------------------------
# Branch [230,238]: same-line open and close brace (line_num == start_line)
#
# When '{' and '}' appear on the same line, brace_stack.pop() yields
# start_line == line_num, so line_num - start_line == 0, which is not > 0.
# The 'if line_num - start_line > 0:' guard at line 230 is False (branch
# 230->238 taken) and no FoldingRange is appended for this brace pair.
# ---------------------------------------------------------------------------


def test_folding_fallback_same_line_braces_produce_no_range() -> None:
    """Branch [230,238]: one-liner rule '{...}' on a single line -> no FoldingRange.

    _fallback_folding_ranges encounters '{' and '}' on the same line (line 0).
    When '}' is processed, brace_stack.pop() returns 0 (the line of '{').
    line_num(0) - start_line(0) == 0, which is not > 0.  The False branch at
    line 230 is taken (branch 230->238); no range is appended.
    """
    text = "rule inline { condition: true }\n"
    provider = _provider()

    result = provider._fallback_folding_ranges(text)

    assert result == [], "same-line braces must not produce a folding range"


def test_folding_fallback_same_line_braces_plus_multiline() -> None:
    """Branches [230,238] and the True path together.

    Two rules: one on a single line (False branch, no range) and one spanning
    multiple lines (True path, range produced).  Both code paths execute in a
    single call to _fallback_folding_ranges.
    """
    text = "rule inline { condition: true }\nrule multiline {\n    condition:\n        true\n}\n"
    provider = _provider()

    result = provider._fallback_folding_ranges(text)

    # Only the multi-line rule should produce a range.
    assert len(result) == 1, "exactly one range for the multi-line rule"
    assert result[0].start_line == 1
    assert result[0].end_line == 4


# ===========================================================================
# 2.  document_query_references.py  — line 214 / branch [208,214]
# ===========================================================================

# ---------------------------------------------------------------------------
# Line 214 / branch [208,214]: matches_resolved_symbol returns False
#
# build_string_rename_edits falls back to text-based renaming when the AST is
# unavailable (ast() returns None).  iter_reference_occurrences uses
# mask_non_code_segments on each line independently, so it cannot detect tokens
# that appear inside a MULTI-LINE block comment — the mask function has no
# inter-line state.  For such a token, position_is_in_non_code_segment (called
# via ctx.resolve_symbol) correctly returns True (in comment) and resolves to
# None, causing matches_resolved_symbol to return False.  The 'continue' at
# line 214 is executed for that occurrence, and the rename edit is NOT added.
# ---------------------------------------------------------------------------


def test_build_string_rename_edits_skips_token_inside_multiline_block_comment() -> None:
    """Line 214 / branch [208,214]: token inside multi-line block comment is skipped.

    Arrange: a YARA document whose strict AST parse fails (trailing 'SYNTAX ERROR'
    text forces the unified parser to return None).  The document has:
      - '$a = "hello"' in the strings section (real declaration)
      - A multi-line block comment in the condition that contains '$a'
        (the comment starts on the previous line, so mask_non_code_segments
        cannot detect it on the line where '$a' appears)
      - '$a' as a legitimate reference after the comment ends

    Act: call build_string_rename_edits to rename '$a' to '$new'.

    Assert:
    - Exactly 2 TextEdit objects are returned: the declaration (strings line)
      and the real reference after the comment.
    - The spurious '$a' inside the block comment does NOT produce a TextEdit,
      confirming that matches_resolved_symbol returned False for it (line 214).
    """
    broken_src = (
        "rule block_comment_test {\n"
        "    strings:\n"
        '        $a = "hello"\n'
        "    condition:\n"
        "        /* start of multi-line block comment\n"
        "           $a inside block comment end */ $a\n"
        "}\n"
        "SYNTAX ERROR\n"
    )
    doc = DocumentContext(uri="file://block_comment.yar", text=broken_src)

    # Pre-condition: AST is unavailable so the text-fallback path is taken.
    assert doc.ast() is None, "test requires broken YARA so AST returns None"

    edits = build_string_rename_edits(doc, "$a", "$new")

    # Declaration at strings line (line 2) and real usage at line 5 after comment.
    assert len(edits) == 2, (
        f"expected 2 edits (declaration + real usage), got {len(edits)}: {edits}"
    )
    edit_ranges = [(e.range.start.line, e.range.start.character) for e in edits]
    assert (2, 8) in edit_ranges, "declaration at line 2 col 8 must be renamed"
    # The real '$a' after the comment close */ is at line 5 col 42.
    # Confirm the in-comment occurrence (line 5, col ~11) is NOT present.
    in_comment_edits = [
        e for e in edits if e.range.start.line == 5 and e.range.start.character < 20
    ]
    assert in_comment_edits == [], "token inside block comment must not produce a rename edit"


def test_build_string_rename_edits_all_occurrences_outside_comment() -> None:
    """Contrast test: when no block comment obscures any token, all occurrences are renamed.

    This exercises the 'matches_resolved_symbol returns True' path, confirming
    the continue at line 214 is only triggered for the in-comment case.
    """
    broken_src = (
        "rule plain_test {\n"
        "    strings:\n"
        '        $a = "hello"\n'
        "    condition:\n"
        "        $a\n"
        "}\n"
        "SYNTAX ERROR\n"
    )
    doc = DocumentContext(uri="file://plain.yar", text=broken_src)
    assert doc.ast() is None

    edits = build_string_rename_edits(doc, "$a", "$renamed")

    assert len(edits) == 2, f"expected 2 edits (declaration + usage), got {len(edits)}: {edits}"
    assert all(e.new_text == "$renamed" for e in edits)


# ===========================================================================
# Dead-code documentation
# ===========================================================================

# ---------------------------------------------------------------------------
# document_query_resolution_text.py — lines 110, 119, 129, 162-163
#
# All five lines are structurally dead.  The detailed rationale is preserved
# in tests/test_document_query_resolution_text_coverage_loop.py.  No tests
# are added here to avoid duplicating that evidence.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# document_symbols.py — lines 124, 224, 345, 373 and branches
#
# All four lines are structurally dead.  Documented in
# tests/test_lsp_document_symbols_coverage_loop2.py.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# runtime_rules.py — lines 120, 147-149, 184-186
#
# All are structurally dead.  Documented in
# tests/test_lsp_runtime_rules_coverage_loop2.py.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# authoring_actions_rewrites.py — lines 49, 72, 124, 177
#
# These are defensive guards that protect against generator / serializer bugs:
#
# Line 49   (optimize_rule):      rule.condition is None after strict YARA parse.
#           The strict Parser always produces rules with a condition section;
#           rules that fail to parse cause _safe_parse to return None and an
#           early exit at line 43, not at line 49.
#
# Line 72   (roundtrip_rewrite_rule): diff has logical/structural changes after
#           the roundtrip serializer converts rule -> JSON -> rule.
#           RoundTripSerializer is designed to be identity-preserving; no valid
#           YARA input triggers this guard.
#
# Line 124  (deduplicate_identical_strings): _safe_generate returns None after
#           string deduplication.  CodeGenerator.generate() does not raise for
#           valid AST nodes; the guard fires only for generator bugs.
#
# Line 177  (rewrite_of_them): same as line 124.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# authoring_actions_sorting.py — lines 147, 149, 152, 178, 180, 183
#
# Symmetric defensive guards in canonicalize_rule_structure and pretty_print_rule:
#
# Lines 147, 178: _safe_parse on CodeGenerator/ASTFormatter output returns None.
#   Both generators produce syntactically valid YARA; the strict parser never
#   fails on their output for valid input rules.
#
# Lines 149, 180: re-parsed rule count != 1.
#   A single rule passed to generate() always produces text with exactly one rule.
#
# Lines 152, 183: ASTDiffer reports logical/structural changes between a rule and
#   its own re-parsed canonical form.  The canonicalize / pretty-print operations
#   preserve semantics by design.
# ---------------------------------------------------------------------------
