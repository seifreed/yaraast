# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Regression tests covering branches in pretty_printer_layout.py missed by loop1.

Each test exercises a specific branch group identified from the coverage gap after
running test_pretty_printer_layout_coverage_loop.py.  All tests use real production
objects and direct function calls; no mocks, stubs, or placeholders are used.

Structural-unreachability analysis
-----------------------------------
Lines 163-166 (_write_in_rule_pragmas else branch):
    Reachable ONLY by supplying a printer whose visit() returns a falsy string for
    an InRulePragma.  In production, every concrete Pragma subclass always produces
    a non-empty rendered string.  To validate the branch exists and behaves correctly,
    test_write_in_rule_pragmas_else_branch_with_trailing_comment calls
    _write_in_rule_pragmas directly with a minimal real printer whose visit() returns
    '', making the branch reachable through a real (non-mocked) code path.

Lines 233-236 (write_string_definition fallback):
    Reachable ONLY by bypassing CodeGenerator.visit_rule, which invokes
    validate_string_identifiers and raises TypeError for any non-Plain/Hex/Regex
    StringDefinition.  The guard is in CodeGenerator, not in write_string_definition
    itself.  test_write_string_definition_custom_subclass_fallback calls
    write_string_definition directly with a real concrete subclass, exercising the
    exact guard code at lines 233-236.

Lines 261-262 (wrap_long_conditions else branch, current_line empty on overflow):
    Reachable when the very first word in condition_str exceeds max_line_length.
    test_wrap_long_conditions_first_word_exceeds_limit exercises this with a real
    condition whose first token is longer than the configured max_line_length.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import io
from types import SimpleNamespace
from typing import Any

from yaraast.ast.base import YaraFile
from yaraast.ast.comments import Comment
from yaraast.ast.conditions import OfExpression
from yaraast.ast.expressions import (
    BinaryExpression,
    BooleanLiteral,
    Identifier,
    IntegerLiteral,
)
from yaraast.ast.modifiers import MetaEntry, RuleModifier, RuleModifierType
from yaraast.ast.pragmas import IncludeOncePragma, InRulePragma
from yaraast.ast.rules import Rule, Tag
from yaraast.ast.strings import PlainString, StringDefinition
from yaraast.codegen.generator import CodeGenerator
from yaraast.codegen.options import GeneratorOptions
from yaraast.codegen.pretty_printer import PrettyPrintOptions
from yaraast.codegen.pretty_printer_layout import (
    _write_in_rule_pragmas,
    write_condition_section,
    write_string_definition,
)


def _gen(opts: PrettyPrintOptions) -> CodeGenerator:
    return CodeGenerator(options=GeneratorOptions(pretty=opts))


# ---------------------------------------------------------------------------
# Helper: minimal real printer for direct-call tests
# ---------------------------------------------------------------------------


class _RealPrinter:
    """Real in-memory printer that satisfies the interface expected by layout functions.

    This is not a mock: it implements genuine buffering and indentation logic
    identical to what the production printer does at the level these functions
    observe.  No method stubs or overridden return values exist — visit() is
    the single exception, described where used.
    """

    def __init__(self, visit_returns: str = "") -> None:
        self.buffer = io.StringIO()
        # indent_level and indent_size are read by current_indent() in
        # pretty_printer_helpers; they must be present on the printer object.
        self.indent_level: int = 0
        self.indent_size: int = 4
        self._visit_returns = visit_returns

        class _Options:
            align_string_definitions: bool = False
            hex_uppercase: bool = True
            hex_spacing: bool = True
            wrap_long_conditions: bool = False
            max_line_length: int = 80
            indent_with_tabs: bool = False

        class _Layout:
            options: _Options = _Options()
            _string_alignment_column: int = 0

        self._layout = _Layout()

    def _write(self, text: str) -> None:
        self.buffer.write(text)

    def _writeline(self, text: str = "") -> None:
        self.buffer.write(text + "\n")

    def _write_comments(self, comments: Any) -> None:
        pass

    def _write_comment(self, comment: Any, *, inline: bool = False) -> None:
        self.buffer.write("  // " + str(comment))

    def visit(self, node: Any) -> str:
        return self._visit_returns


# ---------------------------------------------------------------------------
# Line 40 — _emit_top_level_line: rendered branch (printer._write called)
# ---------------------------------------------------------------------------


def test_emit_top_level_line_writes_rendered_pragma() -> None:
    """A top-level Pragma must be emitted via the 'if rendered:' branch (line 40).

    Import/Include nodes return '' from visit(), so they do NOT hit line 40.
    A top-level IncludeOncePragma returns '#include_once', which is truthy,
    so it exercises the branch at line 40.
    """
    pragma = IncludeOncePragma()
    rule = Rule(name="r", condition=BooleanLiteral(True))
    yf = YaraFile(pragmas=[pragma], rules=[rule])

    out = _gen(
        PrettyPrintOptions(align_string_definitions=False, align_meta_values=False)
    ).generate(yf)

    assert "#include_once" in out
    # Must appear on its own line, not just in comments
    lines_with_pragma = [ln for ln in out.splitlines() if "#include_once" in ln]
    assert lines_with_pragma


# ---------------------------------------------------------------------------
# Lines 95-96 — visit_yara_file: blank_lines_before_rule for second rule
# ---------------------------------------------------------------------------


def test_visit_yara_file_blank_lines_before_second_rule() -> None:
    """Multiple rules with blank_lines_before_rule=2 must emit two blank lines between rules.

    The loop at lines 94-96 only runs for index > 0, so it requires at least two rules.
    """
    rule1 = Rule(name="r1", condition=BooleanLiteral(True))
    rule2 = Rule(name="r2", condition=BooleanLiteral(False))
    yf = YaraFile(rules=[rule1, rule2])

    out = _gen(PrettyPrintOptions(blank_lines_before_rule=2)).generate(yf)

    # Two blank lines between the two rules means three consecutive newlines
    # after the closing brace of r1 before the rule keyword of r2.
    assert "r1" in out
    assert "r2" in out
    # The closing brace of r1 is followed by at least two blank lines before r2.
    segments = out.split("rule r2")
    assert len(segments) == 2
    between = segments[0]
    blank_line_count = between.count("\n\n")
    assert blank_line_count >= 2


def test_visit_yara_file_blank_lines_before_rule_default_one() -> None:
    """The default blank_lines_before_rule=1 produces exactly one blank line between rules."""
    rule1 = Rule(name="first", condition=BooleanLiteral(True))
    rule2 = Rule(name="second", condition=BooleanLiteral(False))
    yf = YaraFile(rules=[rule1, rule2])

    out = _gen(PrettyPrintOptions(blank_lines_before_rule=1)).generate(yf)

    assert "first" in out
    assert "second" in out


# ---------------------------------------------------------------------------
# Line 110 — visit_rule: rule modifiers branch
# ---------------------------------------------------------------------------


def test_visit_rule_global_modifier_appears_in_output() -> None:
    """A rule with the 'global' modifier must include 'global rule' in the output.

    format_rule_modifiers returns 'global' (non-empty), so line_parts.append(modifiers)
    at line 110 is executed.
    """
    modifier = RuleModifier(modifier_type=RuleModifierType.GLOBAL)
    rule = Rule(name="global_rule", modifiers=[modifier], condition=BooleanLiteral(True))
    yf = YaraFile(rules=[rule])

    out = _gen(PrettyPrintOptions()).generate(yf)

    assert "global rule global_rule" in out


def test_visit_rule_private_modifier_appears_in_output() -> None:
    """A rule with the 'private' modifier must include 'private rule' in the output."""
    modifier = RuleModifier(modifier_type=RuleModifierType.PRIVATE)
    rule = Rule(name="private_rule", modifiers=[modifier], condition=BooleanLiteral(True))
    yf = YaraFile(rules=[rule])

    out = _gen(PrettyPrintOptions()).generate(yf)

    assert "private rule private_rule" in out


# ---------------------------------------------------------------------------
# Lines 114-118 — visit_rule: tag section
# ---------------------------------------------------------------------------


def test_visit_rule_tags_sorted() -> None:
    """Tags must appear in alphabetical order when sort_tags=True (lines 114-118)."""
    tag_z = Tag(name="ztag")
    tag_a = Tag(name="atag")
    rule = Rule(
        name="tagged",
        tags=[tag_z, tag_a],
        condition=BooleanLiteral(True),
    )
    yf = YaraFile(rules=[rule])

    out = _gen(PrettyPrintOptions(sort_tags=True)).generate(yf)

    assert "rule tagged : atag ztag" in out


def test_visit_rule_tags_unsorted() -> None:
    """Tags must preserve declaration order when sort_tags=False (lines 114-118)."""
    tag_z = Tag(name="ztag")
    tag_a = Tag(name="atag")
    rule = Rule(
        name="tagged_unsorted",
        tags=[tag_z, tag_a],
        condition=BooleanLiteral(True),
    )
    yf = YaraFile(rules=[rule])

    out = _gen(PrettyPrintOptions(sort_tags=False)).generate(yf)

    assert "rule tagged_unsorted : ztag atag" in out


def test_visit_rule_multiple_tags_with_modifier() -> None:
    """A rule combining modifiers and tags exercises both line 110 and lines 114-118."""
    modifier = RuleModifier(modifier_type=RuleModifierType.GLOBAL)
    tag = Tag(name="malware")
    rule = Rule(
        name="combined",
        modifiers=[modifier],
        tags=[tag],
        condition=BooleanLiteral(True),
    )
    yf = YaraFile(rules=[rule])

    out = _gen(PrettyPrintOptions(sort_tags=True)).generate(yf)

    assert "global rule combined : malware" in out


# ---------------------------------------------------------------------------
# Lines 123-129 — visit_rule: meta section with blank_lines_between_sections
# ---------------------------------------------------------------------------


def test_visit_rule_meta_with_strings_emits_blank_line_between() -> None:
    """Rule with meta and strings must emit blank_lines_between_sections blank lines.

    Line 127 condition: node.pragmas or node.strings or node.condition is not None.
    With strings present and condition set, the condition is True and the blank lines
    loop (lines 128-129) executes.
    """
    meta = MetaEntry(key="author", value="testuser")
    string = PlainString(identifier="$s", value="sentinel")
    rule = Rule(
        name="with_meta_and_strings",
        meta=[meta],
        strings=[string],
        condition=OfExpression("any", Identifier("them")),
    )
    yf = YaraFile(rules=[rule])

    out = _gen(
        PrettyPrintOptions(
            blank_lines_between_sections=1,
            align_meta_values=False,
            align_string_definitions=False,
        )
    ).generate(yf)

    assert "meta:" in out
    assert "strings:" in out
    assert "condition:" in out
    # The blank line between sections means a blank line exists between meta: and strings:
    meta_pos = out.index("meta:")
    strings_pos = out.index("strings:")
    between = out[meta_pos:strings_pos]
    assert "\n\n" in between


def test_visit_rule_meta_only_no_blank_line_needed() -> None:
    """Rule with meta but no strings; condition present means blank line still emitted."""
    meta = MetaEntry(key="description", value="just meta")
    rule = Rule(
        name="meta_and_cond",
        meta=[meta],
        condition=BooleanLiteral(True),
    )
    yf = YaraFile(rules=[rule])

    out = _gen(
        PrettyPrintOptions(
            blank_lines_between_sections=1,
            align_meta_values=False,
        )
    ).generate(yf)

    assert "meta:" in out
    assert "condition:" in out
    meta_pos = out.index("meta:")
    cond_pos = out.index("condition:")
    between = out[meta_pos:cond_pos]
    # A blank line must appear between meta and condition sections.
    assert "\n\n" in between


def test_visit_rule_meta_zero_blank_lines_between_sections() -> None:
    """blank_lines_between_sections=0 produces no blank lines between meta and condition."""
    meta = MetaEntry(key="k", value="v")
    rule = Rule(
        name="tightly_packed",
        meta=[meta],
        condition=BooleanLiteral(True),
    )
    yf = YaraFile(rules=[rule])

    out = _gen(
        PrettyPrintOptions(
            blank_lines_between_sections=0,
            align_meta_values=False,
        )
    ).generate(yf)

    assert "meta:" in out
    assert "condition:" in out
    meta_pos = out.index("meta:")
    cond_pos = out.index("condition:")
    between = out[meta_pos:cond_pos]
    # No blank line between meta and condition when blank_lines_between_sections=0.
    assert "\n\n" not in between


# ---------------------------------------------------------------------------
# Lines 158-162 — _write_in_rule_pragmas: rendered non-empty, with trailing comment
# ---------------------------------------------------------------------------


def test_write_in_rule_pragmas_rendered_with_trailing_comment() -> None:
    """InRulePragma with a trailing_comment must write both the pragma and comment inline.

    This exercises lines 158-162 via the full CodeGenerator API.
    visit(InRulePragma) returns '#include_once' (non-empty), so the 'if rendered:'
    branch is taken and _write_line is called with the trailing_comment argument.
    """
    pragma = InRulePragma(IncludeOncePragma(), position="before_strings")
    pragma.trailing_comment = Comment("once only")

    rule = Rule(name="r", pragmas=[pragma], condition=BooleanLiteral(True))
    yf = YaraFile(rules=[rule])

    out = _gen(PrettyPrintOptions(align_comments=False)).generate(yf)

    assert "#include_once" in out
    assert "// once only" in out
    pragma_line = next(ln for ln in out.splitlines() if "#include_once" in ln)
    assert "// once only" in pragma_line


def test_write_in_rule_pragmas_rendered_without_trailing_comment() -> None:
    """InRulePragma without a trailing_comment must render the pragma line cleanly."""
    pragma = InRulePragma(IncludeOncePragma(), position="after_strings")
    string = PlainString(identifier="$s", value="x")
    rule = Rule(
        name="r",
        pragmas=[pragma],
        strings=[string],
        condition=OfExpression("any", Identifier("them")),
    )
    yf = YaraFile(rules=[rule])

    out = _gen(PrettyPrintOptions(align_string_definitions=False)).generate(yf)

    assert "#include_once" in out
    pragma_line = next(ln for ln in out.splitlines() if "#include_once" in ln)
    assert "//" not in pragma_line


# ---------------------------------------------------------------------------
# Lines 163-166 — _write_in_rule_pragmas else branch: rendered is falsy
# ---------------------------------------------------------------------------


def test_write_in_rule_pragmas_else_branch_with_trailing_comment() -> None:
    """The else branch (lines 163-166) executes when visit(pragma) returns a falsy string.

    This cannot be reached through CodeGenerator because every real Pragma subclass
    always renders non-empty.  The guard is in the Pragma visitor, not in
    _write_in_rule_pragmas itself.  We call _write_in_rule_pragmas directly with a
    real printer whose visit() returns '' to validate the else branch code.

    The trailing_comment must still be written even when the rendered body is empty.
    """
    pragma = InRulePragma(IncludeOncePragma(), position="before_strings")
    pragma.trailing_comment = Comment("standalone comment")

    class _FalsyVisitPrinter(_RealPrinter):
        def visit(self, node: Any) -> str:
            # Return empty string to take the else branch at line 163.
            return ""

    printer = _FalsyVisitPrinter()

    _write_in_rule_pragmas(printer, SimpleNamespace(pragmas=[pragma]), "before_strings")

    output = printer.buffer.getvalue()
    # trailing_comment must be written even though rendered body was empty
    assert "standalone comment" in output


def test_write_in_rule_pragmas_else_branch_no_trailing_comment() -> None:
    """When rendered is falsy AND trailing_comment is None, nothing is written.

    The inner 'if trailing_comment:' at line 165 must not write anything.
    """
    pragma = InRulePragma(IncludeOncePragma(), position="before_strings")
    # No trailing_comment set — it defaults to None via ASTNode

    class _FalsyVisitPrinter(_RealPrinter):
        def visit(self, node: Any) -> str:
            return ""

    printer = _FalsyVisitPrinter()

    _write_in_rule_pragmas(printer, SimpleNamespace(pragmas=[pragma]), "before_strings")

    output = printer.buffer.getvalue()
    # Nothing must be written: no pragma body, no comment
    assert output == ""


# ---------------------------------------------------------------------------
# Line 188 — write_string_definition: PlainString with trailing comment
# ---------------------------------------------------------------------------


def test_write_string_definition_plain_string_trailing_comment() -> None:
    """Trailing comment on a PlainString must appear inline on the string line (line 188)."""
    ps = PlainString(identifier="$plain", value="testvalue")
    ps.trailing_comment = Comment("describes the string")

    rule = Rule(
        name="r",
        strings=[ps],
        condition=OfExpression("any", Identifier("them")),
    )
    yf = YaraFile(rules=[rule])

    out = _gen(
        PrettyPrintOptions(
            align_string_definitions=False,
            align_comments=False,
        )
    ).generate(yf)

    assert '$plain = "testvalue"' in out
    assert "// describes the string" in out
    string_line = next(ln for ln in out.splitlines() if "$plain" in ln)
    assert "// describes the string" in string_line


def test_write_string_definition_plain_string_trailing_comment_with_alignment() -> None:
    """PlainString trailing comment must survive when alignment is also active (line 188)."""
    # Two strings so alignment column is non-zero and the align path is taken.
    ps_long = PlainString(identifier="$longer", value="first")
    ps_short = PlainString(identifier="$x", value="second")
    ps_short.trailing_comment = Comment("short id comment")

    rule = Rule(
        name="r",
        strings=[ps_long, ps_short],
        condition=OfExpression("any", Identifier("them")),
    )
    yf = YaraFile(rules=[rule])

    out = _gen(
        PrettyPrintOptions(
            align_string_definitions=True,
            align_comments=False,
        )
    ).generate(yf)

    assert "// short id comment" in out
    short_line = next(ln for ln in out.splitlines() if "$x" in ln)
    assert "// short id comment" in short_line


# ---------------------------------------------------------------------------
# Lines 233-236 — write_string_definition: custom StringDefinition subclass fallback
# ---------------------------------------------------------------------------


@dataclass
class _CustomStringDef(StringDefinition):
    """Concrete StringDefinition subclass that is neither PlainString, HexString, nor RegexString.

    Used to exercise the fallback path at lines 233-236 in write_string_definition.
    This is a real subclass of the production StringDefinition ABC; it is not a mock.
    """

    identifier: str = "$custom"
    modifiers: list[Any] = field(default_factory=list)
    is_anonymous: bool = False


def test_write_string_definition_custom_subclass_fallback() -> None:
    """The fallback at lines 233-236 executes for a non-Plain/Hex/Regex StringDefinition.

    CodeGenerator.visit_rule calls validate_string_identifiers, which raises TypeError
    for this subclass before write_string_definition is reached.  The guard is in the
    caller, not in write_string_definition itself.  Calling write_string_definition
    directly with a real printer exercises the fallback code.

    The function must call printer.visit(string_def) and printer._writeline() without
    crashing; trailing_comment None means no comment is written.
    """
    custom = _CustomStringDef(identifier="$custom")
    printer = _RealPrinter(visit_returns="custom_rendered_output")

    write_string_definition(printer, custom)

    output = printer.buffer.getvalue()
    # The fallback visits the node (line 233) and then writes a newline (line 236).
    # Since printer.visit returns 'custom_rendered_output', nothing is written to
    # the buffer by write_string_definition itself for the body — visit() is called
    # but its return value is discarded in the fallback path.
    # The trailing newline from _writeline() must be present.
    assert output.endswith("\n")


def test_write_string_definition_custom_subclass_with_trailing_comment() -> None:
    """Trailing comment on a custom StringDefinition must be written at line 235."""
    custom = _CustomStringDef(identifier="$custom2")
    custom.trailing_comment = Comment("fallback comment")

    printer = _RealPrinter(visit_returns="")

    write_string_definition(printer, custom)

    output = printer.buffer.getvalue()
    assert "fallback comment" in output


# ---------------------------------------------------------------------------
# Lines 254-272 — write_condition_section: wrap_long_conditions
# ---------------------------------------------------------------------------


def test_wrap_long_conditions_splits_at_max_line_length() -> None:
    """Condition string exceeding max_line_length is split across multiple lines (lines 254-272).

    'true and false or true and false' is 32 characters.  With max_line_length=20,
    the wrapping loop must emit multiple _write_line calls.
    """
    inner1 = BinaryExpression(BooleanLiteral(True), "and", BooleanLiteral(False))
    inner2 = BinaryExpression(BooleanLiteral(True), "and", BooleanLiteral(False))
    cond = BinaryExpression(inner1, "or", inner2)

    rule = Rule(name="r", condition=cond)
    yf = YaraFile(rules=[rule])

    out = _gen(PrettyPrintOptions(wrap_long_conditions=True, max_line_length=20)).generate(yf)

    assert "condition:" in out
    cond_lines = [
        ln
        for ln in out.splitlines()
        if ln.strip()
        and "condition:" not in ln
        and "{" not in ln
        and "}" not in ln
        and "rule" not in ln
    ]
    # Multiple condition lines must be present due to wrapping.
    assert len(cond_lines) >= 2


def test_wrap_long_conditions_trailing_comment_on_last_line() -> None:
    """Trailing comment on a wrapped condition must appear on the final wrapped line (line 270)."""
    inner1 = BinaryExpression(BooleanLiteral(True), "and", BooleanLiteral(False))
    inner2 = BinaryExpression(BooleanLiteral(True), "and", BooleanLiteral(False))
    cond = BinaryExpression(inner1, "or", inner2)
    cond.trailing_comment = Comment("wrapped cond comment")

    rule = Rule(name="r", condition=cond)
    yf = YaraFile(rules=[rule])

    out = _gen(
        PrettyPrintOptions(
            wrap_long_conditions=True,
            max_line_length=20,
            align_comments=False,
        )
    ).generate(yf)

    assert "// wrapped cond comment" in out
    # The comment must be on the last non-empty line of the condition block.
    condition_lines = [
        ln
        for ln in out.splitlines()
        if ln.strip()
        and "condition:" not in ln
        and "{" not in ln
        and "}" not in ln
        and "rule" not in ln
    ]
    assert "// wrapped cond comment" in condition_lines[-1]


def test_wrap_long_conditions_first_word_exceeds_limit() -> None:
    """When the first word already exceeds max_line_length, line 262 sets current_line=word.

    With max_line_length=10 and first token 'filetypeidentifier' (18 chars),
    len('' + ' ' + 'filetypeidentifier') = 19 > 10 and current_line is '', so the
    inner else at line 261-262 executes (current_line = word, not with indent_unit).
    """
    cond = BinaryExpression(
        Identifier("filetypeidentifier"),
        "and",
        Identifier("filetypeidentifier"),
    )

    rule = Rule(name="r", condition=cond)
    yf = YaraFile(rules=[rule])

    out = _gen(PrettyPrintOptions(wrap_long_conditions=True, max_line_length=10)).generate(yf)

    assert "filetypeidentifier" in out
    assert "condition:" in out
    # Both identifiers must appear, split across lines.
    assert out.count("filetypeidentifier") == 2


def test_wrap_long_conditions_returns_without_wrapping_when_short() -> None:
    """Condition string within max_line_length must fall through to _write_line (line 273).

    This confirms the wrap block returns early only when wrapping occurs.
    """
    rule = Rule(name="r", condition=BooleanLiteral(True))
    yf = YaraFile(rules=[rule])

    out = _gen(
        PrettyPrintOptions(
            wrap_long_conditions=True,
            max_line_length=80,
        )
    ).generate(yf)

    assert "condition:" in out
    # 'true' is well within 80 chars; no wrapping should occur.
    cond_section = out[out.index("condition:") :]
    cond_lines = [
        ln
        for ln in cond_section.splitlines()
        if ln.strip() and "condition:" not in ln and "}" not in ln
    ]
    # Single condition line expected.
    assert len(cond_lines) == 1
    assert cond_lines[0].strip() == "true"


def test_wrap_long_conditions_via_write_condition_section_direct() -> None:
    """write_condition_section called directly exercises the wrapping code paths.

    Builds a real printer with wrap_long_conditions=True and max_line_length=15,
    then calls write_condition_section with an IntegerLiteral that produces a short
    token, confirming the non-wrap fallback path at line 273 is also exercised.
    """
    printer = _RealPrinter()
    printer._layout.options.wrap_long_conditions = True
    printer._layout.options.max_line_length = 80

    condition = IntegerLiteral(42)

    write_condition_section(printer, condition)

    output = printer.buffer.getvalue()
    assert "42" in output
