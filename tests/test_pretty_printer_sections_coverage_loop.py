# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Regression tests targeting uncovered branches in pretty_printer_sections.py.

Missing lines identified from a coverage run of the existing pretty-printer
test suite:

    38->37  write_meta_section — meta passed as a dict whose keys are plain
            strings; strings lack .key/.value so the hasattr guard is False
            for every entry and the loop body is silently skipped.

    92      write_plain_string_aligned — else branch when
            _string_alignment_column is 0 (no alignment applied).

    96      write_plain_string_aligned — trailing_comment written inline when
            a PlainString carries a trailing_comment attribute.

    118     write_hex_string_aligned — else branch when
            _string_alignment_column is 0 (no alignment applied).

    122     write_hex_string_aligned — trailing_comment written inline when a
            HexString carries a trailing_comment attribute.

    140     write_regex_string_aligned — else branch when
            _string_alignment_column is 0 (no alignment applied).

    144     write_regex_string_aligned — trailing_comment written inline when a
            RegexString carries a trailing_comment attribute.

All tests drive real production code through the public CodeGenerator API or
through the module-level helper functions called directly (the same entry
points that the existing tests already use in
test_codegen_pretty_printer_paths.py).  No mocks are used.
"""

from __future__ import annotations

from yaraast.ast.comments import Comment
from yaraast.ast.strings import HexByte, HexString, PlainString, RegexString
from yaraast.codegen.generator import CodeGenerator
from yaraast.codegen.options import GeneratorOptions
from yaraast.codegen.pretty_layout import PrettyLayout
from yaraast.codegen.pretty_printer import PrettyPrintOptions
from yaraast.codegen.pretty_printer_sections import (
    write_hex_string_aligned,
    write_plain_string_aligned,
    write_regex_string_aligned,
)

# ---------------------------------------------------------------------------
# Shared printer factory
# ---------------------------------------------------------------------------


def _aligned_printer(string_alignment_column: int = 0) -> CodeGenerator:
    """Return a CodeGenerator whose PrettyLayout has a pre-set string
    alignment column.

    This replicates the pattern used in test_codegen_pretty_printer_paths.py
    (test_pretty_printer_direct_remaining_helper_paths) where the layout
    column is written directly to force a specific branch.  The isinstance
    assertion narrows the type from GeneratorLayout to PrettyLayout so that
    mypy accepts the attribute write.
    """
    gen = CodeGenerator(
        options=GeneratorOptions(
            pretty=PrettyPrintOptions(
                align_string_definitions=True,
                align_meta_values=False,
            )
        )
    )
    assert isinstance(gen._layout, PrettyLayout)
    gen._layout._string_alignment_column = string_alignment_column
    return gen


# ---------------------------------------------------------------------------
# Branch 38->37 — write_meta_section skips entries that lack .key/.value
# ---------------------------------------------------------------------------


def test_write_meta_section_dict_input_skips_entries_without_key_value() -> None:
    """write_meta_section with a dict iterates its keys (plain strings).

    Plain strings have no .key or .value attribute, so the hasattr guard on
    line 38 evaluates to False for every entry.  The loop body is not entered
    and the printer buffer remains empty.

    This is a documented semantic of the function: dict meta is accepted by
    validate_rule_meta, but the iteration then yields the dict *keys*, which
    are bare strings that do not carry the required attributes.  The function
    silently produces no output for such entries rather than raising.
    """
    gen = CodeGenerator(
        options=GeneratorOptions(
            pretty=PrettyPrintOptions(
                align_meta_values=False,
                align_string_definitions=False,
            )
        )
    )
    # _write_meta_section delegates to PrettyLayout.write_meta_section which
    # calls write_meta_section from pretty_printer_sections.
    gen._write_meta_section({"author": "alice", "version": "1.0"})

    output = gen.buffer.getvalue()
    # No meta entry is written; the buffer must be empty.
    assert output == ""


# ---------------------------------------------------------------------------
# Line 92 — write_plain_string_aligned else branch (no alignment column)
# ---------------------------------------------------------------------------


def test_write_plain_string_aligned_without_alignment_column() -> None:
    """write_plain_string_aligned takes the else path when the alignment
    column is 0, regardless of align_string_definitions being True.

    The function must write the string in unpadded form and end with a newline.
    """
    gen = _aligned_printer(string_alignment_column=0)
    node = PlainString(identifier="$s", value="hello")

    write_plain_string_aligned(gen, node)

    output = gen.buffer.getvalue()
    # Unpadded: identifier followed immediately by = and quoted value.
    assert '$s = "hello"' in output
    assert output.endswith("\n")


def test_write_plain_string_aligned_without_alignment_column_value_is_exact() -> None:
    """write_plain_string_aligned must produce exactly the unpadded line with
    no extra whitespace between the identifier and the equals sign when
    _string_alignment_column is 0.
    """
    gen = _aligned_printer(string_alignment_column=0)
    node = PlainString(identifier="$abc", value="test")

    write_plain_string_aligned(gen, node)

    output = gen.buffer.getvalue()
    # With indent_level=0 the indent is empty; padding must be absent.
    assert output == '$abc = "test"\n'


# ---------------------------------------------------------------------------
# Line 96 — write_plain_string_aligned trailing comment branch
# ---------------------------------------------------------------------------


def test_write_plain_string_aligned_writes_trailing_comment() -> None:
    """write_plain_string_aligned must append an inline comment when
    trailing_comment is set on the PlainString node.

    The comment must appear on the same line as the string definition, after
    the value (and after modifiers if any are present).
    """
    gen = _aligned_printer(string_alignment_column=0)
    node = PlainString(identifier="$t", value="trigger")
    node.trailing_comment = Comment("detects trigger bytes")

    write_plain_string_aligned(gen, node)

    output = gen.buffer.getvalue()
    assert '$t = "trigger"' in output
    assert "detects trigger bytes" in output
    # Trailing comment must appear on the same line as the value.
    lines = output.splitlines()
    assert len(lines) == 1
    assert "detects trigger bytes" in lines[0]


def test_write_plain_string_aligned_trailing_comment_with_alignment() -> None:
    """write_plain_string_aligned with a non-zero alignment column and a
    trailing comment must write both the padded identifier and the inline
    comment on the same line.
    """
    gen = _aligned_printer(string_alignment_column=6)
    node = PlainString(identifier="$s", value="x")
    node.trailing_comment = Comment("packed")

    write_plain_string_aligned(gen, node)

    output = gen.buffer.getvalue()
    assert "$s" in output
    assert '"x"' in output
    assert "packed" in output
    lines = output.splitlines()
    assert len(lines) == 1


# ---------------------------------------------------------------------------
# Line 118 — write_hex_string_aligned else branch (no alignment column)
# ---------------------------------------------------------------------------


def test_write_hex_string_aligned_without_alignment_column() -> None:
    """write_hex_string_aligned takes the else path when the alignment
    column is 0.

    The identifier must be written without padding, followed immediately by
    the hex pattern in braces.
    """
    gen = _aligned_printer(string_alignment_column=0)
    node = HexString(identifier="$h", tokens=[HexByte(0x4D), HexByte(0x5A)])

    write_hex_string_aligned(gen, node)

    output = gen.buffer.getvalue()
    assert "$h = { 4D 5A }" in output
    assert output.endswith("\n")


def test_write_hex_string_aligned_without_alignment_column_value_is_exact() -> None:
    """write_hex_string_aligned must produce the unpadded hex pattern line
    when _string_alignment_column is 0.
    """
    gen = _aligned_printer(string_alignment_column=0)
    node = HexString(identifier="$mz", tokens=[HexByte(0x4D), HexByte(0x5A)])

    write_hex_string_aligned(gen, node)

    output = gen.buffer.getvalue()
    assert output == "$mz = { 4D 5A }\n"


# ---------------------------------------------------------------------------
# Line 122 — write_hex_string_aligned trailing comment branch
# ---------------------------------------------------------------------------


def test_write_hex_string_aligned_writes_trailing_comment() -> None:
    """write_hex_string_aligned must append an inline comment when
    trailing_comment is set on the HexString node.
    """
    gen = _aligned_printer(string_alignment_column=0)
    node = HexString(identifier="$h", tokens=[HexByte(0x4D)])
    node.trailing_comment = Comment("MZ header")

    write_hex_string_aligned(gen, node)

    output = gen.buffer.getvalue()
    assert "$h = { 4D }" in output
    assert "MZ header" in output
    lines = output.splitlines()
    assert len(lines) == 1
    assert "MZ header" in lines[0]


def test_write_hex_string_aligned_trailing_comment_with_alignment() -> None:
    """write_hex_string_aligned with alignment and a trailing comment must
    write the padded hex line with the inline comment on the same line.
    """
    gen = _aligned_printer(string_alignment_column=6)
    node = HexString(identifier="$h", tokens=[HexByte(0xFF)])
    node.trailing_comment = Comment("opcode")

    write_hex_string_aligned(gen, node)

    output = gen.buffer.getvalue()
    assert "$h" in output
    assert "FF" in output
    assert "opcode" in output
    lines = output.splitlines()
    assert len(lines) == 1


# ---------------------------------------------------------------------------
# Line 140 — write_regex_string_aligned else branch (no alignment column)
# ---------------------------------------------------------------------------


def test_write_regex_string_aligned_without_alignment_column() -> None:
    """write_regex_string_aligned takes the else path when the alignment
    column is 0.

    The identifier must be written without padding followed immediately by
    the regex pattern in slashes.
    """
    gen = _aligned_printer(string_alignment_column=0)
    node = RegexString(identifier="$r", regex="ab.*")

    write_regex_string_aligned(gen, node)

    output = gen.buffer.getvalue()
    assert "$r = /ab.*/" in output
    assert output.endswith("\n")


def test_write_regex_string_aligned_without_alignment_column_value_is_exact() -> None:
    """write_regex_string_aligned must produce the unpadded regex line when
    _string_alignment_column is 0.
    """
    gen = _aligned_printer(string_alignment_column=0)
    node = RegexString(identifier="$re", regex="[0-9]+")

    write_regex_string_aligned(gen, node)

    output = gen.buffer.getvalue()
    assert output == "$re = /[0-9]+/\n"


# ---------------------------------------------------------------------------
# Line 144 — write_regex_string_aligned trailing comment branch
# ---------------------------------------------------------------------------


def test_write_regex_string_aligned_writes_trailing_comment() -> None:
    """write_regex_string_aligned must append an inline comment when
    trailing_comment is set on the RegexString node.
    """
    gen = _aligned_printer(string_alignment_column=0)
    node = RegexString(identifier="$r", regex="evil.*")
    node.trailing_comment = Comment("malicious pattern")

    write_regex_string_aligned(gen, node)

    output = gen.buffer.getvalue()
    assert "$r = /evil.*/" in output
    assert "malicious pattern" in output
    lines = output.splitlines()
    assert len(lines) == 1
    assert "malicious pattern" in lines[0]


def test_write_regex_string_aligned_trailing_comment_with_alignment() -> None:
    """write_regex_string_aligned with alignment and a trailing comment must
    write the padded regex line with the inline comment on the same line.
    """
    gen = _aligned_printer(string_alignment_column=6)
    node = RegexString(identifier="$r", regex="x+")
    node.trailing_comment = Comment("repetition")

    write_regex_string_aligned(gen, node)

    output = gen.buffer.getvalue()
    assert "$r" in output
    assert "/x+/" in output
    assert "repetition" in output
    lines = output.splitlines()
    assert len(lines) == 1
