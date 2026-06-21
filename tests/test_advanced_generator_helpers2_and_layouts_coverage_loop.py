# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Regression tests covering uncovered lines in:

  - yaraast/codegen/advanced_generator_helpers2.py  (baseline 0% from this suite)
  - yaraast/codegen/layouts.py                       (baseline ~46%)

Every test uses real AST nodes, real layout objects, and real CodeGenerator
instances.  No mocks, stubs, or artificial scaffolding.
"""

from __future__ import annotations

import io

import pytest

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import (
    BinaryExpression,
    BooleanLiteral,
    Identifier,
    IntegerLiteral,
    SetExpression,
    StringIdentifier,
)
from yaraast.ast.meta import Meta
from yaraast.ast.rules import Import, Rule
from yaraast.ast.strings import (
    HexByte,
    HexString,
    PlainString,
    RegexString,
)
from yaraast.codegen.advanced_generator_helpers2 import (
    get_max_key_length,
    get_sorted_meta,
    process_meta_data,
    render_advanced_hex_string,
    render_advanced_plain_string,
    render_advanced_regex_string,
    write_meta_key,
    write_meta_value,
)
from yaraast.codegen.formatting import FormattingConfig, StringStyle
from yaraast.codegen.generator import CodeGenerator
from yaraast.codegen.layouts import (
    CommentLayout,
    PlainLayout,
    select_layout,
)
from yaraast.codegen.options import GeneratorOptions
from yaraast.codegen.pretty_printer import PrettyPrintOptions

# ---------------------------------------------------------------------------
# Helpers shared across tests
# ---------------------------------------------------------------------------


class _SimpleMetaItem:
    """Minimal object carrying a ``key`` attribute — no mocks, just a plain class."""

    def __init__(self, key: str, value: object = "v") -> None:
        self.key = key
        self.value = value


class _MetaItemNoValue:
    """Carries a key but no ``value`` attribute — exercises the no-value guard."""

    def __init__(self, key: str) -> None:
        self.key = key


class _NoKeyItem:
    """No ``key`` attribute at all — used to probe the hasattr guard in process_meta_data."""


def _make_advanced_gen(style: StringStyle = StringStyle.ALIGNED) -> CodeGenerator:
    """Build a CodeGenerator whose layout is an AdvancedLayout with the given StringStyle."""
    config = FormattingConfig(string_style=style)
    return CodeGenerator(options=GeneratorOptions(advanced=config))


# ===========================================================================
# process_meta_data
# ===========================================================================


def test_process_meta_data_dict_returns_empty_list() -> None:
    """Line 24: dict input triggers the early-return branch yielding []."""
    result = process_meta_data({"author": "x"})
    assert result == []


def test_process_meta_data_list_with_key_items_keeps_them() -> None:
    """Lines 27-30: list items that carry .key are collected into the output list."""
    items = [_SimpleMetaItem("author"), _SimpleMetaItem("version")]
    result = process_meta_data(items)
    assert len(result) == 2
    assert result[0].key == "author"
    assert result[1].key == "version"


def test_process_meta_data_list_without_key_items_excluded() -> None:
    """Lines 27-30 (hasattr False branch): items lacking .key are skipped."""
    items: list[object] = [_NoKeyItem(), _SimpleMetaItem("keep")]
    result = process_meta_data(items)
    assert len(result) == 1
    assert result[0].key == "keep"


def test_process_meta_data_empty_list_returns_empty() -> None:
    """Lines 26-30: iterating an empty list yields an empty result."""
    result = process_meta_data([])
    assert result == []


def test_process_meta_data_tuple_input_is_iterated() -> None:
    """Lines 27-30: tuple input is accepted and iterated like a list."""
    items = (_SimpleMetaItem("k1"), _SimpleMetaItem("k2"))
    result = process_meta_data(items)
    assert [m.key for m in result] == ["k1", "k2"]


# ===========================================================================
# get_sorted_meta
# ===========================================================================


def test_get_sorted_meta_sort_enabled_sorts_by_key() -> None:
    """Lines 35-36: sort_meta=True sorts alphabetically by .key."""
    items = [_SimpleMetaItem("zebra"), _SimpleMetaItem("alpha"), _SimpleMetaItem("mid")]
    result = get_sorted_meta(items, sort_meta=True)
    assert [m.key for m in result] == ["alpha", "mid", "zebra"]


def test_get_sorted_meta_sort_disabled_preserves_order() -> None:
    """Line 37: sort_meta=False returns the list unchanged."""
    items = [_SimpleMetaItem("b"), _SimpleMetaItem("a")]
    result = get_sorted_meta(items, sort_meta=False)
    assert [m.key for m in result] == ["b", "a"]


def test_get_sorted_meta_empty_list_sort_enabled_returns_empty() -> None:
    """Lines 35-37: empty list with sort_meta=True still returns empty (short-circuit)."""
    result = get_sorted_meta([], sort_meta=True)
    assert result == []


# ===========================================================================
# get_max_key_length
# ===========================================================================


def test_get_max_key_length_empty_list_returns_zero() -> None:
    """Lines 41-43: empty list returns 0 without calling max()."""
    assert get_max_key_length([]) == 0


def test_get_max_key_length_single_item_returns_its_length() -> None:
    """Lines 41-47: a single-item list returns the formatted key length."""
    items = [_SimpleMetaItem("author")]
    result = get_max_key_length(items)
    # format_meta_key("author", None) == "author" → length 6
    assert result == 6


def test_get_max_key_length_multiple_items_returns_maximum() -> None:
    """Lines 41-47: multiple items — the longest formatted key wins."""
    items = [_SimpleMetaItem("a"), _SimpleMetaItem("longer_key"), _SimpleMetaItem("mid")]
    result = get_max_key_length(items)
    assert result == len("longer_key")


def test_get_max_key_length_items_without_key_use_str_fallback() -> None:
    """Lines 44-46: items lacking .key fall back to str(m) for length computation."""
    no_key = _NoKeyItem()
    with_key = _SimpleMetaItem("ab")
    result = get_max_key_length([no_key, with_key])
    # str(no_key) is longer than "ab" on CPython (e.g. "<...NoKeyItem object at 0x...>")
    assert result >= 2


# ===========================================================================
# write_meta_key — TABULAR vs non-TABULAR
# ===========================================================================


def test_write_meta_key_tabular_style_pads_to_max_length() -> None:
    """Lines 53-56: TABULAR StringStyle writes the key left-justified to max_key_len."""
    gen = _make_advanced_gen(StringStyle.TABULAR)
    meta = _SimpleMetaItem("ab")

    write_meta_key(gen, meta, max_key_len=10)

    output = gen.buffer.getvalue()
    # Key "ab" must be padded to width 10 and followed by " = "
    assert "ab" in output
    assert output.count(" ") >= 10  # padded + " = "


def test_write_meta_key_non_tabular_style_writes_inline() -> None:
    """Lines 57-59: non-TABULAR style writes 'key = ' without padding."""
    gen = _make_advanced_gen(StringStyle.ALIGNED)
    meta = _SimpleMetaItem("mykey")

    write_meta_key(gen, meta, max_key_len=20)

    output = gen.buffer.getvalue()
    assert "mykey = " in output
    # must NOT have padding spaces between "mykey" and "="
    assert "mykey  " not in output


def test_write_meta_key_compact_style_writes_inline() -> None:
    """Lines 57-59: COMPACT also takes the non-TABULAR branch."""
    gen = _make_advanced_gen(StringStyle.COMPACT)
    meta = _SimpleMetaItem("k")

    write_meta_key(gen, meta, max_key_len=5)

    output = gen.buffer.getvalue()
    assert "k = " in output


# ===========================================================================
# write_meta_value — with and without .value attribute
# ===========================================================================


def test_write_meta_value_item_without_value_writes_empty_string() -> None:
    """Lines 63-65: item lacking .value triggers the defensive '""' fallback."""
    gen = _make_advanced_gen()
    item = _MetaItemNoValue("k")

    write_meta_value(gen, item)

    assert gen.buffer.getvalue() == '""'


def test_write_meta_value_string_value_writes_quoted() -> None:
    """Lines 67-68: normal item with a string .value is formatted by format_meta_literal."""
    gen = _make_advanced_gen()
    item = _SimpleMetaItem("author", "Alice")

    write_meta_value(gen, item)

    output = gen.buffer.getvalue()
    assert '"Alice"' in output


def test_write_meta_value_integer_value_writes_number() -> None:
    """Lines 67-68: integer .value is rendered without quotes."""
    gen = _make_advanced_gen()
    item = _SimpleMetaItem("count", 42)

    write_meta_value(gen, item)

    assert "42" in gen.buffer.getvalue()


def test_write_meta_value_bool_value_writes_lowercase() -> None:
    """Lines 67-68: bool .value is rendered as 'true'/'false'."""
    gen = _make_advanced_gen()
    item = _SimpleMetaItem("flag", True)

    write_meta_value(gen, item)

    assert "true" in gen.buffer.getvalue()


# ===========================================================================
# render_advanced_plain_string — COMPACT vs non-COMPACT
# ===========================================================================


def test_render_advanced_plain_string_compact_no_spaces_around_equals() -> None:
    """Lines 84-85: COMPACT style writes '$id="value"' without spaces."""
    gen = _make_advanced_gen(StringStyle.COMPACT)
    node = PlainString("$a", value="hello")

    render_advanced_plain_string(gen, node)

    output = gen.buffer.getvalue()
    assert '$a="hello"' in output


def test_render_advanced_plain_string_aligned_has_spaces_around_equals() -> None:
    """Lines 86-87: non-COMPACT style writes '$id = "value"' with spaces."""
    gen = _make_advanced_gen(StringStyle.ALIGNED)
    node = PlainString("$b", value="world")

    render_advanced_plain_string(gen, node)

    output = gen.buffer.getvalue()
    assert '$b = "world"' in output


def test_render_advanced_plain_string_returns_empty_string() -> None:
    """Line 89: the function always returns ''."""
    gen = _make_advanced_gen()
    node = PlainString("$c", value="x")
    result = render_advanced_plain_string(gen, node)
    assert result == ""


# ===========================================================================
# render_advanced_hex_string — COMPACT vs non-COMPACT
# ===========================================================================


def test_render_advanced_hex_string_compact_no_spaces_around_equals() -> None:
    """Lines 97-98: COMPACT style writes '$id={...}' without spaces."""
    gen = _make_advanced_gen(StringStyle.COMPACT)
    node = HexString("$h", tokens=[HexByte(0x4D), HexByte(0x5A)])

    render_advanced_hex_string(gen, node)

    output = gen.buffer.getvalue()
    assert output.startswith("$h={")


def test_render_advanced_hex_string_aligned_has_spaces_around_equals() -> None:
    """Lines 99-100: non-COMPACT style writes '$id = {...}' with spaces."""
    gen = _make_advanced_gen(StringStyle.ALIGNED)
    node = HexString("$h", tokens=[HexByte(0x4D)])

    render_advanced_hex_string(gen, node)

    output = gen.buffer.getvalue()
    assert "$h = {" in output


def test_render_advanced_hex_string_returns_empty_string() -> None:
    """Line 102: the function always returns ''."""
    gen = _make_advanced_gen()
    node = HexString("$h", tokens=[HexByte(0xFF)])
    result = render_advanced_hex_string(gen, node)
    assert result == ""


# ===========================================================================
# render_advanced_regex_string — COMPACT vs non-COMPACT
# ===========================================================================


def test_render_advanced_regex_string_compact_no_spaces_around_equals() -> None:
    """Lines 110-111: COMPACT style writes '$id=/pattern/' without spaces."""
    gen = _make_advanced_gen(StringStyle.COMPACT)
    node = RegexString("$r", regex="abc")

    render_advanced_regex_string(gen, node)

    output = gen.buffer.getvalue()
    assert "$r=/abc/" in output


def test_render_advanced_regex_string_aligned_has_spaces_around_equals() -> None:
    """Lines 112-113: non-COMPACT style writes '$id = /pattern/' with spaces."""
    gen = _make_advanced_gen(StringStyle.ALIGNED)
    node = RegexString("$r", regex="foo")

    render_advanced_regex_string(gen, node)

    output = gen.buffer.getvalue()
    assert "$r = /foo/" in output


def test_render_advanced_regex_string_returns_empty_string() -> None:
    """Line 115: the function always returns ''."""
    gen = _make_advanced_gen()
    node = RegexString("$r", regex="bar")
    result = render_advanced_regex_string(gen, node)
    assert result == ""


# ===========================================================================
# Integration: advanced_generator_helpers2 through the full AdvancedLayout
# pipeline to confirm end-to-end wiring.
# ===========================================================================


def test_advanced_layout_meta_section_compact_style_end_to_end() -> None:
    """All helpers (process_meta_data, get_sorted_meta, get_max_key_length,
    write_meta_key, write_meta_value) exercised via the real AdvancedLayout
    write_meta_section through a full CodeGenerator.generate() call.
    """
    yara_file = YaraFile(
        rules=[
            Rule(
                name="meta_test",
                meta=[Meta("author", "Alice"), Meta("version", 1)],
                condition=BooleanLiteral(True),
            )
        ]
    )
    config = FormattingConfig(string_style=StringStyle.ALIGNED, sort_meta=True)
    gen = CodeGenerator(options=GeneratorOptions(advanced=config))
    output = gen.generate(yara_file)

    assert "meta:" in output
    assert 'author = "Alice"' in output
    assert "version = 1" in output
    # sort_meta=True: "author" < "version" alphabetically
    assert output.index("author") < output.index("version")


def test_advanced_layout_string_section_compact_style_end_to_end() -> None:
    """render_advanced_plain_string and render_advanced_hex_string exercised via
    a real generate() call using COMPACT StringStyle.
    """
    from yaraast.ast.conditions import OfExpression

    yara_file = YaraFile(
        rules=[
            Rule(
                name="strings_test",
                strings=[PlainString("$a", value="hello"), HexString("$h", tokens=[HexByte(0x4D)])],
                condition=OfExpression("any", Identifier("them")),
            )
        ]
    )
    config = FormattingConfig(string_style=StringStyle.COMPACT)
    gen = CodeGenerator(options=GeneratorOptions(advanced=config))
    output = gen.generate(yara_file)

    assert '$a="hello"' in output
    assert "$h={" in output


# ===========================================================================
# layouts.py — GeneratorLayout base methods (via PlainLayout which inherits them)
# ===========================================================================


def test_plain_layout_visit_yara_file_generates_full_output() -> None:
    """Line 153 (PlainLayout.visit_yara_file): exercises render_yara_file."""
    yara_file = YaraFile(
        imports=[Import(module="pe")],
        rules=[Rule(name="pl_file_test", condition=BooleanLiteral(True))],
    )
    gen = CodeGenerator(options=GeneratorOptions())
    output = gen.generate(yara_file)

    assert 'import "pe"' in output
    assert "rule pl_file_test" in output


def test_plain_layout_visit_rule_generates_rule_block() -> None:
    """Line 160 (PlainLayout.visit_rule): exercises render_rule."""
    yara_file = YaraFile(rules=[Rule(name="pl_rule_test", condition=IntegerLiteral(1))])
    gen = CodeGenerator(options=GeneratorOptions())
    output = gen.generate(yara_file)

    assert "rule pl_rule_test" in output
    assert "condition:" in output
    assert "1" in output


def test_plain_layout_visit_meta_renders_meta_entry() -> None:
    """Line 163 (PlainLayout.visit_meta): exercises render_meta for a Meta node.

    PlainLayout.visit_meta delegates to generator_leaf_visitors.visit_meta which
    returns the formatted 'key = value' string.
    """
    layout = PlainLayout()
    # We need a real CodeGenerator to pass as gen but visit_meta on PlainLayout
    # ignores gen and operates only on the node.
    gen = CodeGenerator(options=GeneratorOptions())
    result = layout.visit_meta(gen, Meta("mykey", "myval"))
    assert result == 'mykey = "myval"'


def test_plain_layout_hex_string_delegate_renders_hex() -> None:
    """Line 137 (GeneratorLayout.hex_string default): PlainLayout inherits and
    delegates to _plain_write_hex_string.  Exercised via generate() with a hex
    string in a plain-layout CodeGenerator.
    """
    yara_file = YaraFile(
        rules=[
            Rule(
                name="hex_test",
                strings=[HexString("$h", tokens=[HexByte(0x4D), HexByte(0x5A)])],
                condition=StringIdentifier("$h"),
            )
        ]
    )
    gen = CodeGenerator(options=GeneratorOptions())
    output = gen.generate(yara_file)

    assert "$h = {" in output
    assert "}" in output


def test_plain_layout_regex_string_delegate_renders_regex() -> None:
    """Line 140 (GeneratorLayout.regex_string default): PlainLayout inherits and
    delegates to _plain_write_regex_string.  Exercised via generate().
    """
    yara_file = YaraFile(
        rules=[
            Rule(
                name="regex_test",
                strings=[RegexString("$r", regex="hello")],
                condition=StringIdentifier("$r"),
            )
        ]
    )
    gen = CodeGenerator(options=GeneratorOptions())
    output = gen.generate(yara_file)

    assert "$r = /hello/" in output


# ===========================================================================
# layouts.py — GeneratorLayout.binary_expression, set_expression, yarax_expression
# base implementations (lines 57-74)
#
# These are inherited by PlainLayout.  CodeGenerator routes expression nodes
# through gen.visit() which calls gen._layout.binary_expression() only when
# custom_expressions is True.  PlainLayout has custom_expressions = False, so
# the base methods are NOT called via generate().
#
# However, we can call the base methods directly on a PlainLayout instance —
# that is still real execution of the production code path.
# ===========================================================================


def test_layout_base_binary_expression_delegates_to_generator_expression_visitors() -> None:
    """Lines 57-61: GeneratorLayout.binary_expression delegates to
    visit_binary_expression from generator_expression_visitors.
    """
    layout = PlainLayout()
    gen = CodeGenerator(options=GeneratorOptions())
    node = BinaryExpression(left=IntegerLiteral(2), operator="+", right=IntegerLiteral(3))

    result = layout.binary_expression(gen, node)

    assert "2" in result
    assert "3" in result
    assert "+" in result


def test_layout_base_set_expression_delegates_to_generator_expression_visitors() -> None:
    """Lines 64-68: GeneratorLayout.set_expression delegates to
    visit_set_expression from generator_expression_visitors.
    """
    layout = PlainLayout()
    gen = CodeGenerator(options=GeneratorOptions())
    node = SetExpression(elements=[IntegerLiteral(1), IntegerLiteral(2)])

    result = layout.set_expression(gen, node)

    assert "1" in result
    assert "2" in result


def test_layout_base_yarax_expression_uses_generate_condition_string() -> None:
    """Lines 71-74: GeneratorLayout.yarax_expression calls
    generate_condition_string with a default FormattingConfig.
    """
    layout = PlainLayout()
    gen = CodeGenerator(options=GeneratorOptions())
    node = IntegerLiteral(99)

    result = layout.yarax_expression(gen, node)

    assert "99" in result


# ===========================================================================
# layouts.py — GeneratorLayout.write_single_comment (lines 113-130)
# ===========================================================================


class _MinimalGen:
    """Minimal write-capture object for write_single_comment tests.

    Uses a real PlainLayout for the method under test — no mocks.
    """

    def __init__(self) -> None:
        self._buf = io.StringIO()

    def _write(self, text: str) -> None:
        self._buf.write(text)

    def _writeline(self, text: str = "") -> None:
        self._buf.write(text + "\n")

    def getvalue(self) -> str:
        return self._buf.getvalue()


def test_write_single_comment_inline_single_line_writes_inline_prefix() -> None:
    """Lines 119-123: inline=True with single-line text writes '  // <text>'."""

    class _FakeComment:
        text = "// relevant note"

    layout = PlainLayout()
    cap = _MinimalGen()
    layout.write_single_comment(cap, _FakeComment(), inline=True)  # type: ignore[arg-type]
    assert cap.getvalue() == "  // relevant note"


def test_write_single_comment_inline_raises_for_multiline_text() -> None:
    """Lines 120-122: inline=True with newline in the stripped text raises ValueError."""

    class _FakeComment:
        text = "// line1"

    # Inject a newline into the stripped text by overriding strip() via subclass.
    class _MultilineComment:
        text = "// line1\nline2"

    layout = PlainLayout()
    cap = _MinimalGen()
    with pytest.raises(ValueError, match="Inline comment text must not contain newlines"):
        layout.write_single_comment(cap, _MultilineComment(), inline=True)  # type: ignore[arg-type]


def test_write_single_comment_non_inline_long_text_uses_block_style() -> None:
    """Lines 124-128: inline=False, text > 80 chars uses /* ... */ block style."""
    long_text = "x" * 90

    class _FakeComment:
        text = f"// {long_text}"

    layout = PlainLayout()
    cap = _MinimalGen()
    layout.write_single_comment(cap, _FakeComment(), inline=False)  # type: ignore[arg-type]
    result = cap.getvalue()
    assert "/*" in result
    assert " * " in result
    assert "*/" in result


def test_write_single_comment_non_inline_multiline_text_uses_block_style() -> None:
    """Lines 124-128: inline=False, text with \\n uses /* ... */ block style."""

    class _FakeComment:
        text = "/* line1\nline2 */"

    layout = PlainLayout()
    cap = _MinimalGen()
    layout.write_single_comment(cap, _FakeComment(), inline=False)  # type: ignore[arg-type]
    result = cap.getvalue()
    assert "/*" in result
    assert " * line1" in result
    assert " * line2" in result
    assert "*/" in result


def test_write_single_comment_non_inline_short_single_line_writes_double_slash() -> None:
    """Line 130: inline=False, short text, no \\n → '// <text>\\n'."""

    class _FakeComment:
        text = "// short"

    layout = PlainLayout()
    cap = _MinimalGen()
    layout.write_single_comment(cap, _FakeComment(), inline=False)  # type: ignore[arg-type]
    assert cap.getvalue() == "// short\n"


def test_write_single_comment_block_comment_stripped_of_delimiters() -> None:
    """Lines 116-117: /* ... */ style comment has delimiters stripped before rendering."""

    class _FakeComment:
        text = "/* block content */"

    layout = PlainLayout()
    cap = _MinimalGen()
    layout.write_single_comment(cap, _FakeComment(), inline=False)  # type: ignore[arg-type]
    result = cap.getvalue()
    # The stripped text "block content" is short (< 80 chars, no newline) → // style
    assert result == "// block content\n"


# ===========================================================================
# layouts.py — CommentLayout (lines 156-170, 176-184)
# ===========================================================================


def test_comment_layout_visit_yara_file_generates_output() -> None:
    """Lines 160-161 (CommentLayout.visit_yara_file): routed via comment_visit_yara_file."""
    yara_file = YaraFile(
        imports=[Import(module="math")],
        rules=[Rule(name="cl_file_test", condition=BooleanLiteral(True))],
    )
    opts = GeneratorOptions(preserve_comments=True, blank_line_between_sections=False)
    gen = CodeGenerator(options=opts)
    output = gen.generate(yara_file)

    assert 'import "math"' in output
    assert "rule cl_file_test" in output


def test_comment_layout_visit_rule_generates_rule_block() -> None:
    """Lines 163-164 (CommentLayout.visit_rule): routed via comment_visit_rule."""
    yara_file = YaraFile(rules=[Rule(name="cl_rule_test", condition=IntegerLiteral(7))])
    opts = GeneratorOptions(preserve_comments=True, blank_line_between_sections=False)
    gen = CodeGenerator(options=opts)
    output = gen.generate(yara_file)

    assert "rule cl_rule_test" in output
    assert "condition:" in output
    assert "7" in output


def test_comment_layout_visit_meta_writes_key_equals_value() -> None:
    """Lines 166-170 (CommentLayout.visit_meta): writes 'key = value' directly."""
    opts = GeneratorOptions(preserve_comments=True, blank_line_between_sections=False)
    gen = CodeGenerator(options=opts)
    layout = CommentLayout()

    # visit_meta on CommentLayout writes to gen.buffer and returns ""
    result = layout.visit_meta(gen, Meta("author", "Bob"))

    output = gen.buffer.getvalue()
    assert "author" in output
    assert '"Bob"' in output
    assert result == ""


def test_comment_layout_visit_meta_integer_value() -> None:
    """Lines 166-170 (CommentLayout.visit_meta): integer meta value renders without quotes."""
    opts = GeneratorOptions(preserve_comments=True, blank_line_between_sections=False)
    gen = CodeGenerator(options=opts)
    layout = CommentLayout()

    result = layout.visit_meta(gen, Meta("score", 99))

    output = gen.buffer.getvalue()
    assert "score" in output
    assert "99" in output
    assert result == ""


def test_comment_layout_full_pipeline_with_meta() -> None:
    """CommentLayout exercised end-to-end through CodeGenerator.generate() with meta."""
    yara_file = YaraFile(
        rules=[
            Rule(
                name="cl_meta_test",
                meta=[Meta("author", "Dave"), Meta("rev", 2)],
                condition=BooleanLiteral(False),
            )
        ]
    )
    opts = GeneratorOptions(preserve_comments=True, blank_line_between_sections=False)
    gen = CodeGenerator(options=opts)
    output = gen.generate(yara_file)

    assert "meta:" in output
    assert 'author = "Dave"' in output
    assert "rev = 2" in output


# ===========================================================================
# layouts.py — select_layout (lines 173-185)
# ===========================================================================


def test_select_layout_advanced_returns_advanced_layout() -> None:
    """Lines 175-178: when options.advanced is set, AdvancedLayout is returned."""
    from yaraast.codegen.advanced_layout import AdvancedLayout

    opts = GeneratorOptions(advanced=FormattingConfig())
    layout = select_layout(opts)
    assert isinstance(layout, AdvancedLayout)


def test_select_layout_pretty_returns_pretty_layout() -> None:
    """Lines 179-182 (line 184 — pretty branch): PrettyLayout selected when options.pretty set."""
    from yaraast.codegen.pretty_layout import PrettyLayout

    opts = GeneratorOptions(pretty=PrettyPrintOptions())
    layout = select_layout(opts)
    assert isinstance(layout, PrettyLayout)


def test_select_layout_no_blank_line_returns_comment_layout() -> None:
    """Lines 183-184: blank_line_between_sections=False yields CommentLayout."""
    opts = GeneratorOptions(blank_line_between_sections=False)
    layout = select_layout(opts)
    assert isinstance(layout, CommentLayout)


def test_select_layout_default_returns_plain_layout() -> None:
    """Line 185: default options yield PlainLayout."""
    opts = GeneratorOptions()
    layout = select_layout(opts)
    assert isinstance(layout, PlainLayout)


# ===========================================================================
# Integration: advanced_generator_helpers2 through AdvancedLayout — TABULAR
# meta key alignment exercised end-to-end.
# ===========================================================================


def test_advanced_layout_tabular_meta_alignment_end_to_end() -> None:
    """write_meta_key TABULAR branch exercised via AdvancedLayout.write_meta_section
    through a real CodeGenerator.generate() call.
    """
    yara_file = YaraFile(
        rules=[
            Rule(
                name="tabular_test",
                meta=[
                    Meta("author", "Alice"),
                    Meta("long_key_name", "value"),
                ],
                condition=BooleanLiteral(True),
            )
        ]
    )
    config = FormattingConfig(string_style=StringStyle.TABULAR)
    gen = CodeGenerator(options=GeneratorOptions(advanced=config))
    output = gen.generate(yara_file)

    assert "meta:" in output
    assert "author" in output
    assert "long_key_name" in output


def test_advanced_layout_regex_string_compact_end_to_end() -> None:
    """render_advanced_regex_string COMPACT branch exercised via generate()."""
    yara_file = YaraFile(
        rules=[
            Rule(
                name="regex_compact",
                strings=[RegexString("$r", regex="test")],
                condition=StringIdentifier("$r"),
            )
        ]
    )
    config = FormattingConfig(string_style=StringStyle.COMPACT)
    gen = CodeGenerator(options=GeneratorOptions(advanced=config))
    output = gen.generate(yara_file)

    assert "$r=/test/" in output


def test_advanced_layout_hex_string_compact_end_to_end() -> None:
    """render_advanced_hex_string COMPACT branch exercised via generate()."""
    yara_file = YaraFile(
        rules=[
            Rule(
                name="hex_compact",
                strings=[HexString("$h", tokens=[HexByte(0x90)])],
                condition=StringIdentifier("$h"),
            )
        ]
    )
    config = FormattingConfig(string_style=StringStyle.COMPACT)
    gen = CodeGenerator(options=GeneratorOptions(advanced=config))
    output = gen.generate(yara_file)

    # COMPACT: $h={...} with no spaces around equals
    assert "$h={" in output


def test_advanced_layout_plain_string_compact_modifiers_end_to_end() -> None:
    """render_advanced_plain_string COMPACT branch — format_modifiers is called
    after the identifier write when modifiers are present.
    """
    from yaraast.ast.modifiers import StringModifier

    yara_file = YaraFile(
        rules=[
            Rule(
                name="mod_test",
                strings=[
                    PlainString(
                        "$a", value="test", modifiers=[StringModifier.from_name_value("ascii")]
                    )
                ],
                condition=StringIdentifier("$a"),
            )
        ]
    )
    config = FormattingConfig(string_style=StringStyle.COMPACT)
    gen = CodeGenerator(options=GeneratorOptions(advanced=config))
    output = gen.generate(yara_file)

    assert '$a="test"' in output
    assert "ascii" in output


def test_process_meta_data_mixed_list_filters_correctly() -> None:
    """Lines 27-30: mixed list of items with and without .key — only keyed items pass."""
    items: list[object] = [
        _SimpleMetaItem("keep1"),
        _NoKeyItem(),
        _SimpleMetaItem("keep2"),
        _NoKeyItem(),
    ]
    result = process_meta_data(items)
    assert len(result) == 2
    assert result[0].key == "keep1"
    assert result[1].key == "keep2"


# ===========================================================================
# layouts.py — remaining missed lines after first pass
# ===========================================================================


def test_write_single_comment_block_comment_inline_strips_delimiters_and_writes_inline() -> None:
    """Lines 116-117 then 119-123: a /* ... */ comment passed with inline=True strips
    the block delimiters, then takes the inline branch writing '  // <text>'.
    """

    class _BlockComment:
        text = "/* inline note */"

    layout = PlainLayout()
    cap = _MinimalGen()
    layout.write_single_comment(cap, _BlockComment(), inline=True)  # type: ignore[arg-type]
    assert cap.getvalue() == "  // inline note"


def test_write_single_comment_raw_text_not_prefixed_inline_writes_directly() -> None:
    """Lines 116->119 (False branch of the elif): when comment text neither starts
    with '//' nor with '/*...*/'-delimited form, the elif at line 116 evaluates
    False and execution falls straight through to line 119 (if inline).

    This covers the branch 116->119: elif is False, so we jump directly to the
    inline test without stripping any delimiters.
    """

    class _RawComment:
        # Neither starts with '//' nor enclosed in '/* ... */'
        text = "plain comment text"

    layout = PlainLayout()
    cap = _MinimalGen()
    layout.write_single_comment(cap, _RawComment(), inline=True)  # type: ignore[arg-type]
    # The raw text is written unchanged because no stripping happened.
    assert cap.getvalue() == "  // plain comment text"


def test_plain_layout_plain_string_delegate_renders_plain_string() -> None:
    """Line 134 (GeneratorLayout.plain_string default): PlainLayout inherits and
    delegates to _plain_write_plain_string.  Exercised via generate() with a plain
    string in a plain-layout CodeGenerator.
    """
    yara_file = YaraFile(
        rules=[
            Rule(
                name="plain_str_test",
                strings=[PlainString("$p", value="needle")],
                condition=StringIdentifier("$p"),
            )
        ]
    )
    gen = CodeGenerator(options=GeneratorOptions())
    output = gen.generate(yara_file)

    assert '$p = "needle"' in output
