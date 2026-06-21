# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Coverage-loop tests for yaraast.lsp.authoring_support.

Missing-line analysis (83.61% before this file):

COVERABLE missing lines (addressed here):

  56  -- diff_preview: style_only_changes branch (style count > 0)
  58  -- diff_preview: structural_changes branch (structural count > 0)
  60  -- diff_preview: logical_changes branch (logical count > 0)
 103  -- string_signature: isinstance(string_def, RegexString) is True -> return
         ('regex', string_def.regex, modifiers)
 104  -- string_signature: the return statement on line 104 (same branch as 103)
 105  -- string_signature: isinstance(string_def, HexString) is True
 106  -- string_signature: the return statement on line 106 (same branch as 105)
 107  -- string_signature: fallback for an object that is neither Plain, Regex
         nor HexString
 121  -- impact_title: style-only branch fires (style_only_changes is truthy
         and logical_changes and structural_changes are both falsy)
 124  -- impact_title: fallback return base (not style-only, and new_text is
         empty or all three change lists are non-empty together)

STRUCTURALLY UNREACHABLE (documented, not testable via real API):

  None — all missing lines in this module are reachable through the public
  helper API without any structural precondition that the parser or generator
  can never satisfy.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from yaraast.ast.strings import HexByte, HexString, PlainString, RegexString
from yaraast.lsp.authoring_support import (
    canonical_config,
    diff_preview,
    get_rule_context,
    impact_title,
    modifier_start,
    normalize_modifiers,
    string_signature,
)

# ---------------------------------------------------------------------------
# Minimal diff stand-in  (no mocking framework — plain dataclass carrying the
# same attribute names the production code reads via attribute access)
# ---------------------------------------------------------------------------


@dataclass
class _Diff:
    """Minimal diff object matching the attribute contract of authoring_support."""

    style_only_changes: list[str] = field(default_factory=list)
    structural_changes: list[str] = field(default_factory=list)
    logical_changes: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# diff_preview — lines 56, 58, 60
# ---------------------------------------------------------------------------


def test_diff_preview_base_only_when_no_changes() -> None:
    """diff_preview returns just the base label when all change lists are empty."""
    diff = _Diff()

    result = diff_preview(diff, "Round-trip rewrite")

    assert result == "Round-trip rewrite"


def test_diff_preview_appends_style_count() -> None:
    """diff_preview appends '<n> style' when style_only_changes is non-empty (line 56)."""
    diff = _Diff(style_only_changes=["indent", "trailing-space"])

    result = diff_preview(diff, "Base")

    assert result == "Base | 2 style"


def test_diff_preview_appends_structural_count() -> None:
    """diff_preview appends '<n> structural' when structural_changes is non-empty (line 58)."""
    diff = _Diff(structural_changes=["section-reorder"])

    result = diff_preview(diff, "Base")

    assert result == "Base | 1 structural"


def test_diff_preview_appends_logical_count() -> None:
    """diff_preview appends '<n> logical' when logical_changes is non-empty (line 60)."""
    diff = _Diff(logical_changes=["condition-edit"])

    result = diff_preview(diff, "Base")

    assert result == "Base | 1 logical"


def test_diff_preview_all_three_change_types() -> None:
    """diff_preview concatenates all three change-count labels in order."""
    diff = _Diff(
        style_only_changes=["indent"],
        structural_changes=["reorder", "add-section"],
        logical_changes=["condition-edit", "string-added", "modifier-changed"],
    )

    result = diff_preview(diff, "Base")

    assert result == "Base | 1 style | 2 structural | 3 logical"


# ---------------------------------------------------------------------------
# string_signature — lines 103-107
# ---------------------------------------------------------------------------


def test_string_signature_plain_string() -> None:
    """string_signature returns ('plain', value, modifiers) for PlainString."""
    ps = PlainString("$p", "malware payload")

    sig = string_signature(ps)

    assert sig == ("plain", "malware payload", ())


def test_string_signature_plain_string_with_modifiers() -> None:
    """string_signature includes sorted modifier names for PlainString."""
    ps = PlainString("$p", "hello", ["wide", "ascii", "nocase"])

    sig = string_signature(ps)

    assert sig[0] == "plain"
    assert sig[1] == "hello"
    assert sig[2] == ("ascii", "nocase", "wide")


def test_string_signature_regex_string_returns_regex_tuple() -> None:
    """string_signature returns ('regex', pattern, modifiers) for RegexString (lines 103-104)."""
    rs = RegexString("$r", r"mal\w+ware")

    sig = string_signature(rs)

    assert sig == ("regex", r"mal\w+ware", ())


def test_string_signature_regex_string_with_modifier() -> None:
    """string_signature includes modifier tuple for RegexString."""
    rs = RegexString("$r", r"[a-z]+", ["nocase"])

    sig = string_signature(rs)

    assert sig[0] == "regex"
    assert sig[1] == r"[a-z]+"
    assert sig[2] == ("nocase",)


def test_string_signature_hex_string_returns_token_reprs() -> None:
    """string_signature returns ('hex', token-reprs, modifiers) for HexString (lines 105-106)."""
    hs = HexString("$h", [HexByte(0xDE), HexByte(0xAD)])

    sig = string_signature(hs)

    assert sig[0] == "hex"
    # tokens tuple is built from str(token) for each token
    tokens = sig[1]
    assert isinstance(tokens, tuple)
    assert len(tokens) == 2
    assert "222" in str(tokens[0])  # 0xDE == 222
    assert "173" in str(tokens[1])  # 0xAD == 173
    assert sig[2] == ()


def test_string_signature_hex_string_no_tokens() -> None:
    """string_signature handles an empty HexString token list (lines 105-106)."""
    hs = HexString("$h", [])

    sig = string_signature(hs)

    assert sig == ("hex", (), ())


def test_string_signature_unknown_type_returns_classname_fallback() -> None:
    """string_signature falls through to the classname fallback for an unrecognised
    string type (line 107)."""

    class SomeExoticString:
        """Stands in for a future string subclass not yet handled by the switch."""

        identifier = "$exotic"
        modifiers: list[str] = []

    obj = SomeExoticString()
    sig = string_signature(obj)

    assert sig == ("SomeExoticString", "$exotic", ())


def test_string_signature_unknown_type_without_identifier_attr() -> None:
    """string_signature fallback uses empty string when 'identifier' attr is absent
    (line 107, getattr fallback)."""

    class Bare:
        modifiers: list[str] = []

    sig = string_signature(Bare())

    assert sig[0] == "Bare"
    assert sig[1] == ""
    assert sig[2] == ()


# ---------------------------------------------------------------------------
# impact_title — lines 121, 124
# ---------------------------------------------------------------------------


def test_impact_title_style_only_branch() -> None:
    """impact_title returns '<base> (style-only)' when only style changes exist (line 121)."""
    diff = _Diff(style_only_changes=["whitespace"])

    result = impact_title("Normalize rule", diff, "rule r { condition: true }")

    assert result == "Normalize rule (style-only)"


def test_impact_title_safe_rewrite_branch() -> None:
    """impact_title returns '<base> (safe rewrite)' when no logical/structural changes
    exist and new_text is non-empty (line 123)."""
    diff = _Diff()

    result = impact_title("Normalize rule", diff, "rule r { condition: true }")

    assert result == "Normalize rule (safe rewrite)"


def test_impact_title_fallback_empty_new_text() -> None:
    """impact_title returns the bare base string when new_text is empty and no
    style-only branch fires (line 124)."""
    diff = _Diff()

    result = impact_title("Normalize rule", diff, "")

    assert result == "Normalize rule"


def test_impact_title_fallback_logical_and_structural_changes() -> None:
    """impact_title returns the bare base string when logical and structural changes
    both exist alongside style changes — the style-only branch condition requires the
    other two lists to be empty (line 124)."""
    diff = _Diff(
        style_only_changes=["indent"],
        structural_changes=["reorder"],
        logical_changes=["condition-mutated"],
    )

    result = impact_title("Normalize rule", diff, "new text")

    assert result == "Normalize rule"


# ---------------------------------------------------------------------------
# get_rule_context — covered for completeness; confirms real delegation
# ---------------------------------------------------------------------------


def test_get_rule_context_returns_none_outside_rule() -> None:
    """get_rule_context returns None when the cursor is on a line outside any rule."""
    text = 'import "pe"\n\nrule r {\n    condition:\n        true\n}\n'

    result = get_rule_context(text, 0)

    assert result is None


def test_get_rule_context_returns_rule_context_inside_rule() -> None:
    """get_rule_context returns a RuleContext with valid bounds when cursor is
    inside a rule block."""
    text = "rule r {\n    condition:\n        true\n}\n"

    result = get_rule_context(text, 2)

    assert result is not None
    assert result.text != ""
    assert isinstance(result.lines, list)
    assert len(result.lines) > 0


# ---------------------------------------------------------------------------
# modifier_start — already partly covered; exercise remaining branch paths
# ---------------------------------------------------------------------------


def test_modifier_start_returns_none_for_bare_identifier_no_space() -> None:
    """modifier_start returns None when the body has no whitespace after the
    string definition (no modifiers present)."""
    result = modifier_start('"hello"')

    assert result is None


def test_modifier_start_finds_space_after_plain_string() -> None:
    """modifier_start returns the index of the first modifier character when
    the string body is a plain string followed by a space."""
    body = '"hello" ascii'

    result = modifier_start(body)

    assert result == 8


def test_modifier_start_skips_escaped_chars_in_quoted_string() -> None:
    """modifier_start correctly skips backslash-escaped characters inside a
    quoted string, so an escaped quote does not terminate the string early."""
    body = r'"he\"llo" wide'

    result = modifier_start(body)

    assert result == 10


def test_modifier_start_handles_regex_body() -> None:
    """modifier_start treats regex bodies (delimited by /) correctly and
    returns position after the closing delimiter space."""
    body = "/abc/ nocase"

    result = modifier_start(body)

    assert result == 6


def test_modifier_start_handles_hex_brace_body() -> None:
    """modifier_start skips over a hex string body in braces and returns the
    position after the closing brace space."""
    body = "{ DE AD BE EF } private"

    result = modifier_start(body)

    assert result == 16


# ---------------------------------------------------------------------------
# normalize_modifiers
# ---------------------------------------------------------------------------


def test_normalize_modifiers_deduplicates_and_sorts_by_preferred_order() -> None:
    """normalize_modifiers removes duplicates and orders modifiers according to
    PREFERRED_MODIFIER_ORDER."""
    modifiers = ["wide", "ascii", "nocase", "ascii"]

    result = normalize_modifiers(modifiers)

    assert result == ["ascii", "wide", "nocase"]


def test_normalize_modifiers_unknown_modifier_sorted_alphabetically_after_known() -> None:
    """Modifiers not in PREFERRED_MODIFIER_ORDER sort alphabetically after all
    known modifiers."""
    modifiers = ["wide", "custom_mod", "ascii"]

    result = normalize_modifiers(modifiers)

    assert result[0] == "ascii"
    assert result[1] == "wide"
    assert result[-1] == "custom_mod"


def test_normalize_modifiers_empty_list() -> None:
    """normalize_modifiers returns an empty list for empty input."""
    assert normalize_modifiers([]) == []


# ---------------------------------------------------------------------------
# canonical_config
# ---------------------------------------------------------------------------


def test_canonical_config_returns_expected_settings() -> None:
    """canonical_config returns a FormattingConfig with the documented canonical
    sort and section settings."""
    cfg = canonical_config()

    assert cfg.sort_meta is True
    assert cfg.sort_strings is True
    assert cfg.blank_lines_between_sections == 1
    assert cfg.section_order == ["meta", "strings", "condition"]
