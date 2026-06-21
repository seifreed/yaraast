# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Regression tests raising coverage of pretty_layout and generator_sections to 100%.

Each test exercises a real code path through the production API — no mocks, no
test doubles, no ``# pragma: no cover`` directives.  The fixtures are minimal
YARA AST nodes constructed directly from the public AST types; the generator is
the real ``CodeGenerator`` wired to real layout objects.
"""

from __future__ import annotations

import pytest

from yaraast.ast.base import YaraFile
from yaraast.ast.comments import Comment
from yaraast.ast.expressions import BooleanLiteral, StringIdentifier
from yaraast.ast.meta import Meta
from yaraast.ast.rules import Rule
from yaraast.ast.strings import HexByte, HexString, PlainString
from yaraast.codegen.generator import CodeGenerator
from yaraast.codegen.generator_sections import write_meta_section, write_strings_section
from yaraast.codegen.options import GeneratorOptions
from yaraast.codegen.pretty_layout import PrettyLayout
from yaraast.codegen.pretty_printer import PrettyPrintOptions

# ---------------------------------------------------------------------------
# pretty_layout.py — PrettyLayout.prepare()
# ---------------------------------------------------------------------------


def test_prepare_with_non_yara_file_returns_early() -> None:
    """pretty_layout line 55: the early-return guard for a non-YaraFile node.

    ``CodeGenerator.generate()`` always calls ``layout.prepare(gen, node)``
    where ``node`` is whatever the caller passes.  Calling ``prepare`` directly
    with a ``Rule`` (not a ``YaraFile``) exercises the ``if not isinstance``
    branch and the ``return`` on line 55 without touching the alignment
    calculation that follows.
    """
    opts = PrettyPrintOptions(
        align_string_definitions=True,
        align_meta_values=True,
    )
    gen = CodeGenerator(options=GeneratorOptions(pretty=opts))
    layout = gen._layout
    assert isinstance(layout, PrettyLayout)

    # Columns start at zero; they must remain zero after a non-YaraFile prepare.
    rule = Rule(name="dummy", condition=BooleanLiteral(True))
    layout.prepare(gen, rule)

    assert layout._string_alignment_column == 0
    assert layout._meta_alignment_column == 0


def test_prepare_with_yara_file_computes_string_alignment_column() -> None:
    """pretty_layout lines 56-58: align_string_definitions=True branch.

    When the node IS a ``YaraFile`` and ``align_string_definitions`` is
    enabled, ``prepare`` must invoke ``calculate_string_alignment_column`` and
    store the result on the layout instance.
    """
    opts = PrettyPrintOptions(
        align_string_definitions=True,
        align_meta_values=False,
    )
    gen = CodeGenerator(options=GeneratorOptions(pretty=opts))
    layout = gen._layout
    assert isinstance(layout, PrettyLayout)

    rule = Rule(
        name="r",
        strings=[PlainString("$longidentifier", value="abc")],
        condition=StringIdentifier("$longidentifier"),
    )
    yf = YaraFile(rules=[rule])

    layout.prepare(gen, yf)

    # $longidentifier is 15 chars; column must be > 0.
    assert layout._string_alignment_column > 0
    assert layout._meta_alignment_column == 0


def test_prepare_with_yara_file_computes_meta_alignment_column() -> None:
    """pretty_layout lines 59-63: align_meta_values=True branch.

    When ``align_meta_values`` is enabled, ``prepare`` must invoke
    ``calculate_meta_alignment_column`` and store the result.
    """
    opts = PrettyPrintOptions(
        align_string_definitions=False,
        align_meta_values=True,
        min_alignment_column=40,
    )
    gen = CodeGenerator(options=GeneratorOptions(pretty=opts))
    layout = gen._layout
    assert isinstance(layout, PrettyLayout)

    rule = Rule(
        name="r",
        meta=[Meta("author", "alice"), Meta("version", 1)],
        condition=BooleanLiteral(True),
    )
    yf = YaraFile(rules=[rule])

    layout.prepare(gen, yf)

    assert layout._string_alignment_column == 0
    assert layout._meta_alignment_column >= 40


def test_prepare_with_yara_file_and_both_alignment_flags() -> None:
    """pretty_layout lines 56-63: both alignment branches active in one call."""
    opts = PrettyPrintOptions(
        align_string_definitions=True,
        align_meta_values=True,
        min_alignment_column=40,
    )
    gen = CodeGenerator(options=GeneratorOptions(pretty=opts))
    layout = gen._layout
    assert isinstance(layout, PrettyLayout)

    rule = Rule(
        name="r",
        meta=[Meta("author", "alice")],
        strings=[PlainString("$s", value="x")],
        condition=StringIdentifier("$s"),
    )
    yf = YaraFile(rules=[rule])

    layout.prepare(gen, yf)

    assert layout._string_alignment_column > 0
    assert layout._meta_alignment_column >= 40


# ---------------------------------------------------------------------------
# pretty_layout.py — PrettyLayout.visit_meta()
# ---------------------------------------------------------------------------


def test_visit_meta_writes_key_value_with_indent() -> None:
    """pretty_layout lines 74-78: PrettyLayout.visit_meta via gen.visit(Meta).

    ``CodeGenerator.visit_meta`` delegates directly to
    ``layout.visit_meta(gen, node)``.  Calling ``gen.visit(meta_node)``
    exercises lines 74-78, which write the indented key, the separator, and
    the formatted value into the generator buffer.
    """
    opts = PrettyPrintOptions(
        align_meta_values=False,
        align_string_definitions=False,
    )
    gen = CodeGenerator(options=GeneratorOptions(pretty=opts))
    gen.indent_level = 2

    meta = Meta("author", "alice")
    result = gen.visit(meta)

    assert result == ""
    buf = gen.buffer.getvalue()
    assert 'author = "alice"' in buf
    # Indented at two levels (default indent_size=4 → 8 spaces).
    assert buf.startswith("        ")


def test_visit_meta_writes_integer_value() -> None:
    """pretty_layout line 77: format_meta_literal for an integer value."""
    opts = PrettyPrintOptions(
        align_meta_values=False,
        align_string_definitions=False,
    )
    gen = CodeGenerator(options=GeneratorOptions(pretty=opts))
    gen.indent_level = 1

    meta = Meta("count", 42)
    gen.visit(meta)

    assert "count = 42" in gen.buffer.getvalue()


def test_visit_meta_writes_boolean_value() -> None:
    """pretty_layout line 77: format_meta_literal for a boolean value."""
    opts = PrettyPrintOptions(
        align_meta_values=False,
        align_string_definitions=False,
    )
    gen = CodeGenerator(options=GeneratorOptions(pretty=opts))
    gen.indent_level = 1

    meta = Meta("is_valid", True)
    gen.visit(meta)

    assert "is_valid = true" in gen.buffer.getvalue()


# ---------------------------------------------------------------------------
# pretty_layout.py — PrettyLayout.write_single_comment() — non-inline path
# ---------------------------------------------------------------------------


def test_write_single_comment_non_inline_delegates_to_super() -> None:
    """pretty_layout lines 94-95: inline=False delegates to GeneratorLayout.

    When ``inline=False``, ``PrettyLayout.write_single_comment`` must call
    ``super().write_single_comment(gen, comment, inline=False)`` and return
    without executing any of the inline-specific alignment logic below.
    """
    opts = PrettyPrintOptions(preserve_comments=True)
    gen = CodeGenerator(options=GeneratorOptions(pretty=opts))
    layout = gen._layout
    assert isinstance(layout, PrettyLayout)

    comment = Comment("// standalone leading comment")
    layout.write_single_comment(gen, comment, inline=False)

    buf = gen.buffer.getvalue()
    # The base class emits '// <stripped text>\n'.
    assert buf == "// standalone leading comment\n"


def test_write_single_comment_non_inline_long_text_emits_block() -> None:
    """pretty_layout line 95: super() handles a long comment as a block comment."""
    opts = PrettyPrintOptions(preserve_comments=True)
    gen = CodeGenerator(options=GeneratorOptions(pretty=opts))

    long_text = "// " + "a" * 85
    comment = Comment(long_text)
    gen._layout.write_single_comment(gen, comment, inline=False)

    buf = gen.buffer.getvalue()
    assert buf.startswith("/*\n")
    assert " */\n" in buf


# ---------------------------------------------------------------------------
# pretty_layout.py — PrettyLayout.write_single_comment() — inline paths
# ---------------------------------------------------------------------------


def test_write_single_comment_inline_strips_double_slash_prefix() -> None:
    """pretty_layout lines 98-100: inline comment strips // prefix."""
    opts = PrettyPrintOptions(
        preserve_comments=True,
        align_comments=False,
        inline_comment_spacing=2,
    )
    gen = CodeGenerator(options=GeneratorOptions(pretty=opts))
    layout = gen._layout
    assert isinstance(layout, PrettyLayout)

    # Write some content to the buffer so the comment follows it.
    gen._write('        key = "value"')
    comment = Comment("// trailing note")
    layout.write_single_comment(gen, comment, inline=True)

    buf = gen.buffer.getvalue()
    # The // prefix is stripped and the comment is re-emitted with spacing.
    assert "// trailing note" in buf
    assert buf == '        key = "value"  // trailing note'


def test_write_single_comment_inline_strips_block_comment_delimiters() -> None:
    """pretty_layout lines 101-102: inline comment strips /* ... */ delimiters."""
    opts = PrettyPrintOptions(
        preserve_comments=True,
        align_comments=False,
        inline_comment_spacing=2,
    )
    gen = CodeGenerator(options=GeneratorOptions(pretty=opts))

    gen._write("    $s = /abc/")
    comment = Comment("/* inline block note */")
    gen._layout.write_single_comment(gen, comment, inline=True)

    buf = gen.buffer.getvalue()
    assert "// inline block note" in buf
    assert "/*" not in buf


def test_write_single_comment_inline_rejects_newlines_in_comment_text() -> None:
    """pretty_layout lines 104-106: ValueError on newline inside inline comment.

    A comment text that contains a newline cannot be rendered as a single
    inline suffix.  The guard on line 104 must raise ``ValueError`` before
    writing anything.
    """
    opts = PrettyPrintOptions(preserve_comments=True, align_comments=False)
    gen = CodeGenerator(options=GeneratorOptions(pretty=opts))

    comment = Comment("first line\nsecond line")
    with pytest.raises(ValueError, match="Inline comment text must not contain newlines"):
        gen._layout.write_single_comment(gen, comment, inline=True)


def test_write_single_comment_inline_rejects_carriage_return() -> None:
    """pretty_layout line 104: \\r also triggers the newline rejection guard."""
    opts = PrettyPrintOptions(preserve_comments=True, align_comments=False)
    gen = CodeGenerator(options=GeneratorOptions(pretty=opts))

    comment = Comment("part1\rpart2")
    with pytest.raises(ValueError, match="Inline comment text must not contain newlines"):
        gen._layout.write_single_comment(gen, comment, inline=True)


def test_write_single_comment_inline_spacing_is_enforced() -> None:
    """pretty_layout lines 108: max(0, spacing) ensures non-negative padding."""
    opts = PrettyPrintOptions(
        preserve_comments=True,
        align_comments=False,
        inline_comment_spacing=-5,  # negative — must be clamped to 0
    )
    gen = CodeGenerator(options=GeneratorOptions(pretty=opts))

    gen._write("x")
    comment = Comment("// note")
    gen._layout.write_single_comment(gen, comment, inline=True)

    buf = gen.buffer.getvalue()
    # Zero spacing: comment immediately follows the text.
    assert buf == "x// note"


def test_write_single_comment_inline_align_comments_pads_to_column() -> None:
    """pretty_layout lines 109-111: align_comments pads to comment_column.

    When ``align_comments=True``, the inline suffix must start at
    ``comment_column`` regardless of the inline_comment_spacing default.
    """
    column = 40
    opts = PrettyPrintOptions(
        preserve_comments=True,
        align_comments=True,
        comment_column=column,
        inline_comment_spacing=2,
    )
    gen = CodeGenerator(options=GeneratorOptions(pretty=opts))

    prefix = "    key = 1"  # 11 chars
    gen._write(prefix)
    comment = Comment("// note")
    gen._layout.write_single_comment(gen, comment, inline=True)

    buf = gen.buffer.getvalue()
    # The // should start exactly at position 40.
    assert buf.index("//") == column


def test_write_single_comment_inline_align_comments_honours_minimum_spacing() -> None:
    """pretty_layout lines 109-111: spacing is at least inline_comment_spacing.

    When the current line is already beyond comment_column, the spacing must
    not go negative — it falls back to inline_comment_spacing.
    """
    column = 10
    opts = PrettyPrintOptions(
        preserve_comments=True,
        align_comments=True,
        comment_column=column,
        inline_comment_spacing=3,
    )
    gen = CodeGenerator(options=GeneratorOptions(pretty=opts))

    # Write 20 chars — far beyond comment_column=10.
    gen._write("a" * 20)
    comment = Comment("// note")
    gen._layout.write_single_comment(gen, comment, inline=True)

    buf = gen.buffer.getvalue()
    # spacing = max(3, 10 - 20) = max(3, -10) = 3 spaces before "//".
    assert buf == "a" * 20 + "   // note"


# ---------------------------------------------------------------------------
# pretty_layout.py — end-to-end generation covering prepare() + visit_meta()
# ---------------------------------------------------------------------------


def test_generate_yara_file_with_pretty_layout_aligns_strings() -> None:
    """End-to-end: prepare→generate covers lines 56-58 via CodeGenerator.generate."""
    from yaraast.ast.expressions import BinaryExpression

    rule = Rule(
        name="aligned_rule",
        strings=[
            PlainString("$a", value="short"),
            PlainString("$long_id", value="longer"),
        ],
        condition=BinaryExpression(StringIdentifier("$a"), "or", StringIdentifier("$long_id")),
    )
    yf = YaraFile(rules=[rule])

    out = CodeGenerator(
        options=GeneratorOptions(
            pretty=PrettyPrintOptions(
                align_string_definitions=True,
                align_meta_values=False,
            )
        )
    ).generate(yf)

    # Both identifiers should be padded so that the '=' sign appears at the
    # same column.  Filter to definition lines only (they contain ' = ').
    def_lines = [line for line in out.splitlines() if "$" in line and " = " in line]
    assert len(def_lines) == 2
    eq_positions = [line.index("=") for line in def_lines]
    assert eq_positions[0] == eq_positions[1]


def test_generate_yara_file_with_pretty_layout_aligns_meta_values() -> None:
    """End-to-end: prepare→generate covers lines 59-63 via CodeGenerator.generate.

    Meta value alignment pads the text that follows '=', not the '=' itself.
    The key ``author`` (6 chars) and ``version`` (7 chars) produce '=' signs
    at different columns, but both values start at the same column.
    """
    rule = Rule(
        name="meta_aligned",
        meta=[Meta("author", "alice"), Meta("version", 2)],
        condition=BooleanLiteral(True),
    )
    yf = YaraFile(rules=[rule])

    out = CodeGenerator(
        options=GeneratorOptions(
            pretty=PrettyPrintOptions(
                align_string_definitions=False,
                align_meta_values=True,
                min_alignment_column=30,
            )
        )
    ).generate(yf)

    meta_lines = [line for line in out.splitlines() if "=" in line and "rule" not in line]
    assert len(meta_lines) == 2

    def _value_column(line: str) -> int:
        """Return the column at which the value starts (after '= ' padding)."""
        after_eq = line[line.index("=") + 1 :].lstrip()
        return line.index(after_eq)

    val_positions = [_value_column(line) for line in meta_lines]
    assert val_positions[0] == val_positions[1]


# ---------------------------------------------------------------------------
# generator_sections.py — _emit_comments()
# ---------------------------------------------------------------------------


def test_emit_comments_via_write_meta_section_plain_layout() -> None:
    """generator_sections lines 24-26: _emit_comments when a meta item has
    leading_comments.

    The plain layout (no ``pretty``, no ``advanced``) routes
    ``_write_meta_section`` through ``generator_sections.write_meta_section``
    (imported in layouts.py as ``_plain_write_meta_section``).  That function
    calls ``_emit_comments(gen, item)`` for each list-type meta entry.
    Attaching a ``leading_comments`` list to a ``Meta`` node and generating
    through the plain layout exercises lines 24-26.
    """
    gen = CodeGenerator(options=GeneratorOptions(blank_line_between_sections=True))

    meta_item = Meta("author", "alice")
    meta_item.leading_comments = [Comment("// meta leading comment")]

    rule = Rule(name="r", meta=[meta_item], condition=BooleanLiteral(True))
    yf = YaraFile(rules=[rule])

    out = gen.generate(yf)

    assert "// meta leading comment" in out
    assert 'author = "alice"' in out
    # Comment must precede the meta entry.
    assert out.index("// meta leading comment") < out.index('author = "alice"')


def test_emit_comments_via_write_strings_section_plain_layout() -> None:
    """generator_sections lines 24-26: _emit_comments when a string node has
    leading_comments.

    ``write_strings_section`` also calls ``_emit_comments(gen, string)`` for
    each string entry before visiting it.
    """
    gen = CodeGenerator(options=GeneratorOptions(blank_line_between_sections=True))

    string_node = PlainString("$s", value="test")
    string_node.leading_comments = [Comment("// string leading comment")]

    rule = Rule(
        name="r",
        strings=[string_node],
        condition=StringIdentifier("$s"),
    )
    yf = YaraFile(rules=[rule])

    out = gen.generate(yf)

    assert "// string leading comment" in out
    assert '$s = "test"' in out
    assert out.index("// string leading comment") < out.index('$s = "test"')


def test_emit_comments_multiple_leading_comments_all_emitted() -> None:
    """generator_sections line 25: the for-loop emits every leading comment."""
    gen = CodeGenerator(options=GeneratorOptions(blank_line_between_sections=True))

    meta_item = Meta("key", "val")
    meta_item.leading_comments = [
        Comment("// first comment"),
        Comment("// second comment"),
    ]

    rule = Rule(name="r", meta=[meta_item], condition=BooleanLiteral(True))
    out = gen.generate(YaraFile(rules=[rule]))

    assert "// first comment" in out
    assert "// second comment" in out
    assert out.index("// first comment") < out.index("// second comment")


# ---------------------------------------------------------------------------
# generator_sections.py — write_meta_section() dict branch (line 42)
# ---------------------------------------------------------------------------


def test_write_meta_section_dict_branch_directly() -> None:
    """generator_sections line 41-42: dict meta routes to gen._write_meta_dict.

    ``Rule.__init__`` normalises dict meta into ``list[MetaEntry]`` before the
    generator ever sees it, so the dict branch in ``write_meta_section`` is
    only reachable by calling the function directly.  This test does exactly
    that: it calls ``write_meta_section(gen, dict)`` with a real
    ``CodeGenerator`` and a raw Python dict to exercise lines 41-42.
    """
    gen = CodeGenerator(options=GeneratorOptions(blank_line_between_sections=True))
    gen._indent()

    write_meta_section(gen, {"author": "alice", "version": 1})

    buf = gen.buffer.getvalue()
    assert "meta:" in buf
    assert 'author = "alice"' in buf
    assert "version = 1" in buf


def test_write_meta_section_dict_empty_skips_output() -> None:
    """generator_sections line 35-36: empty dict triggers the early return.

    An empty dict is falsy in Python, so ``if not meta: return`` fires on
    line 35-36 before any output is written.  ``validate_rule_meta`` accepts
    an empty dict, so the early return is legitimately reachable.
    """
    gen = CodeGenerator(options=GeneratorOptions(blank_line_between_sections=True))

    write_meta_section(gen, {})

    assert gen.buffer.getvalue() == ""


def test_write_meta_section_dict_multiple_entries_directly() -> None:
    """generator_sections line 42: _write_meta_dict iterates all dict entries.

    Direct call with a multi-key dict verifies that every key-value pair is
    written when the dict branch fires.
    """
    gen = CodeGenerator(options=GeneratorOptions(blank_line_between_sections=True))
    gen._indent()

    write_meta_section(gen, {"a": "x", "b": 2, "c": True})

    buf = gen.buffer.getvalue()
    assert 'a = "x"' in buf
    assert "b = 2" in buf
    assert "c = true" in buf


# ---------------------------------------------------------------------------
# generator_sections.py — write_meta_section() line 38 (dead-code guard)
# ---------------------------------------------------------------------------


def test_write_meta_section_non_collection_meta_raises_before_line_38() -> None:
    """generator_sections line 38 is a defensive guard that is structurally
    unreachable through the validated public API.

    ``validate_rule_meta`` (called on line 34) raises ``TypeError`` for any
    meta that is not ``None``, ``dict``, ``list``, or ``tuple`` — so the
    ``isinstance`` check on line 38 can never evaluate True via the normal
    call path.  This test documents that fact by confirming the TypeError is
    raised before execution reaches line 38.
    """
    gen = CodeGenerator(options=GeneratorOptions(blank_line_between_sections=True))

    class UnsupportedMetaType:
        """Not a dict, list, or tuple — but truthy."""

        def __bool__(self) -> bool:
            return True

    with pytest.raises(TypeError, match="Rule meta must be a dictionary, list, or tuple"):
        write_meta_section(gen, UnsupportedMetaType())


# ---------------------------------------------------------------------------
# generator_sections.py — write_strings_section() has_condition branch
# ---------------------------------------------------------------------------


def test_write_strings_section_has_condition_emits_trailing_blank_line() -> None:
    """generator_sections line 70-71: has_condition=True appends a blank line."""
    gen = CodeGenerator(options=GeneratorOptions(blank_line_between_sections=True))

    string_node = PlainString("$s", value="abc")
    rule = Rule(
        name="r",
        strings=[string_node],
        condition=StringIdentifier("$s"),
    )
    yf = YaraFile(rules=[rule])
    out = gen.generate(yf)

    # Between the strings section and the condition section there must be a
    # blank line when has_condition is True.
    assert "\n\n    condition:" in out


def test_write_strings_section_no_condition_omits_trailing_blank_line() -> None:
    """generator_sections line 70: has_condition=False omits the trailing blank.

    ``write_strings_section`` writes a ``strings:`` header and then each
    string definition.  When ``has_condition=False``, it must NOT emit an
    extra blank line after the last definition — the buffer must end with a
    single ``\n``, not ``\n\n``.
    """
    gen = CodeGenerator(options=GeneratorOptions(blank_line_between_sections=True))
    gen._indent()  # simulate being inside a rule body

    string_node = HexString("$h", tokens=[HexByte(0x4D)])
    write_strings_section(gen, [string_node], has_condition=False)

    buf = gen.buffer.getvalue()
    assert "strings:" in buf
    assert "$h = { 4D }" in buf
    # No trailing blank line when has_condition=False.
    assert not buf.endswith("\n\n")


# ---------------------------------------------------------------------------
# generator_sections.py — write_meta_section() dict branch (line 42)
# via plain layout end-to-end
# ---------------------------------------------------------------------------


def test_write_meta_section_list_via_plain_layout_end_to_end() -> None:
    """generator_sections line 43-48: list meta through a full generate() call.

    ``Rule.__init__`` normalises dict meta into ``list[MetaEntry]``, so the
    full ``generate()`` path always exercises the list branch (line 44-48),
    not the dict branch.  This end-to-end test validates that the plain layout
    correctly renders meta from list[MetaEntry] nodes.
    """
    from yaraast.codegen.layouts import PlainLayout

    gen = CodeGenerator(options=GeneratorOptions(blank_line_between_sections=True))
    assert isinstance(gen._layout, PlainLayout)

    rule = Rule(
        name="list_meta_rule",
        meta=[Meta("author", "alice"), Meta("count", 42), Meta("flag", True)],
        condition=BooleanLiteral(True),
    )
    out = gen.generate(YaraFile(rules=[rule]))

    assert "meta:" in out
    assert 'author = "alice"' in out
    assert "count = 42" in out
    assert "flag = true" in out


# ---------------------------------------------------------------------------
# generator_sections.py — write_condition_section() (lines 74-86)
# ---------------------------------------------------------------------------


def test_write_condition_section_single_line_condition() -> None:
    """generator_sections lines 74-79, 84-86: single-line condition path."""
    from yaraast.codegen.generator_sections import write_condition_section

    gen = CodeGenerator(options=GeneratorOptions(blank_line_between_sections=True))
    gen._indent()  # simulate being inside a rule body

    write_condition_section(gen, BooleanLiteral(True))

    buf = gen.buffer.getvalue()
    assert "condition:\n" in buf
    assert "true\n" in buf


def test_write_condition_section_none_is_noop() -> None:
    """generator_sections line 76: None condition returns without writing."""
    from yaraast.codegen.generator_sections import write_condition_section

    gen = CodeGenerator(options=GeneratorOptions(blank_line_between_sections=True))
    write_condition_section(gen, None)

    assert gen.buffer.getvalue() == ""


def test_write_condition_section_multiline_condition_each_line_indented() -> None:
    """generator_sections lines 81-83: multiline condition split and re-indented.

    A ``CommentGroup`` node, when visited by the plain ``CodeGenerator``,
    returns a newline-joined string of comment lines.  Passing it as the
    condition argument to ``write_condition_section`` directly drives the
    ``if '\\n' in condition_code`` branch (lines 81-83), which splits the
    text and writes each sub-line with proper indentation.
    """
    from yaraast.ast.comments import CommentGroup
    from yaraast.codegen.generator_sections import write_condition_section

    gen = CodeGenerator(options=GeneratorOptions(blank_line_between_sections=True))
    gen._indent()

    multiline_node = CommentGroup(comments=[Comment("// branch one"), Comment("// branch two")])
    write_condition_section(gen, multiline_node)

    buf = gen.buffer.getvalue()
    assert "condition:" in buf
    assert "// branch one" in buf
    assert "// branch two" in buf
    # Both sub-lines must appear on separate indented lines.
    buf_lines = buf.splitlines()
    content_lines = [ln for ln in buf_lines if "branch" in ln]
    assert len(content_lines) == 2
    assert all(ln.startswith("    ") for ln in content_lines)


# ---------------------------------------------------------------------------
# generator_sections.py — write_plain_string() (lines 89-100)
# ---------------------------------------------------------------------------


def test_write_plain_string_returns_empty_string() -> None:
    """generator_sections line 99: write_plain_string always returns ''.

    The function writes its output directly to the generator buffer and
    returns an empty string (not the rendered content).  The test confirms
    both the side effect and the return value.
    """
    from yaraast.codegen.generator_sections import write_plain_string

    gen = CodeGenerator(options=GeneratorOptions(blank_line_between_sections=True))
    gen._indent()

    result = write_plain_string(gen, PlainString("$plain", value="hello world"))

    assert result == ""
    assert '$plain = "hello world"' in gen.buffer.getvalue()


def test_write_plain_string_with_modifiers() -> None:
    """generator_sections lines 98-99: modifier branch in write_plain_string."""
    from yaraast.ast.modifiers import StringModifier
    from yaraast.codegen.generator_sections import write_plain_string

    gen = CodeGenerator(options=GeneratorOptions(blank_line_between_sections=True))
    gen._indent()

    node = PlainString(
        "$wide_str",
        value="test",
        modifiers=[StringModifier.from_name_value("wide")],
    )
    result = write_plain_string(gen, node)

    assert result == ""
    buf = gen.buffer.getvalue()
    assert '$wide_str = "test"' in buf
    assert "wide" in buf


# ---------------------------------------------------------------------------
# generator_sections.py — write_hex_string() (lines 103-116)
# ---------------------------------------------------------------------------


def test_write_hex_string_returns_empty_string() -> None:
    """generator_sections line 116: write_hex_string always returns ''.

    The function writes its output directly to the generator buffer and
    returns an empty string.
    """
    from yaraast.codegen.generator_sections import write_hex_string

    gen = CodeGenerator(options=GeneratorOptions(blank_line_between_sections=True))
    gen._indent()

    result = write_hex_string(gen, HexString("$hex", tokens=[HexByte(0x4D), HexByte(0x5A)]))

    assert result == ""
    assert "$hex = { 4D 5A }" in gen.buffer.getvalue()


def test_write_hex_string_with_private_modifier() -> None:
    """generator_sections line 115: modifier branch in write_hex_string.

    The only modifier that ``validate_hex_string_modifiers`` accepts for hex
    strings is ``private``.  Passing a ``HexString`` with that modifier
    exercises line 115 (``gen._write_modifiers``).
    """
    from yaraast.ast.modifiers import StringModifier
    from yaraast.codegen.generator_sections import write_hex_string

    gen = CodeGenerator(options=GeneratorOptions(blank_line_between_sections=True))
    gen._indent()

    node = HexString(
        "$hex_priv",
        tokens=[HexByte(0x4D)],
        modifiers=[StringModifier.from_name_value("private")],
    )
    result = write_hex_string(gen, node)

    assert result == ""
    buf = gen.buffer.getvalue()
    assert "$hex_priv = { 4D }" in buf
    assert "private" in buf


# ---------------------------------------------------------------------------
# generator_sections.py — write_regex_string() (lines 119-128)
# ---------------------------------------------------------------------------


def test_write_regex_string_simple_pattern() -> None:
    """generator_sections lines 119-128: write_regex_string with a plain pattern."""
    from yaraast.ast.strings import RegexString
    from yaraast.codegen.generator_sections import write_regex_string

    gen = CodeGenerator(options=GeneratorOptions(blank_line_between_sections=True))
    gen._indent()

    result = write_regex_string(gen, RegexString("$re", regex="hello.*world"))

    assert result == ""
    assert "$re = /hello.*world/" in gen.buffer.getvalue()


def test_write_regex_string_with_modifiers() -> None:
    """generator_sections lines 126-127: modifier branch in write_regex_string."""
    from yaraast.ast.strings import RegexString
    from yaraast.codegen.generator_sections import write_regex_string

    gen = CodeGenerator(options=GeneratorOptions(blank_line_between_sections=True))
    gen._indent()

    node = RegexString(
        "$re_mod",
        regex="abc+",
        modifiers=["i", "s"],
    )
    result = write_regex_string(gen, node)

    assert result == ""
    buf = gen.buffer.getvalue()
    assert "$re_mod = /abc+/is" in buf


def test_write_regex_string_escapes_forward_slash_delimiter() -> None:
    """generator_sections line 124: escape_regex_delimiter is applied."""
    from yaraast.ast.strings import RegexString
    from yaraast.codegen.generator_sections import write_regex_string

    gen = CodeGenerator(options=GeneratorOptions(blank_line_between_sections=True))
    gen._indent()

    node = RegexString("$re_slash", regex="a/b")
    write_regex_string(gen, node)

    buf = gen.buffer.getvalue()
    # The forward slash in the pattern must be escaped with a backslash.
    assert r"a\/b" in buf
