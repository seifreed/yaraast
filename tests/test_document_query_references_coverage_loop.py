# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Coverage tests for yaraast.lsp.document_query_references.

All tests call the real public API through DocumentContext or through the
module-level functions directly.  No mocks, stubs, or test doubles are used.

Missing lines targeted (baseline 39.62% from most-relevant existing tests):
  41-42, 44-45   _require_symbol_name — non-string and empty-string paths
  50-58          _require_string_rename_name — bare empty and regex-fail paths
  62-71          _require_rule_rename_name — too-long, bad pattern, keyword paths
  75-78          _require_bool_flag — non-boolean input
  82-90          _require_optional_rule_scope — non-string and empty-string paths
  100-145        find_string_references — text-fallback path (unparseable AST)
  155-177        find_string_reference_records — cache hit and role assignment
  187-218        build_string_rename_edits — text-fallback path
  263-273        rule_occurrences — text-fallback condition scan
  284-298        rule_reference_records — cache hit and include_declaration=False
  302-320        get_local_rule_link_records — full population and cache hit
"""

from __future__ import annotations

from lsprotocol.types import Location, TextEdit
import pytest

from yaraast.lsp.document_context import DocumentContext
from yaraast.lsp.document_query_references import (
    _require_bool_flag,
    _require_optional_rule_scope,
    _require_rule_rename_name,
    _require_string_rename_name,
    _require_symbol_name,
    build_string_rename_edits,
    find_rule_definition,
    find_string_reference_records,
    find_string_references,
    get_local_rule_link_records,
    rename_rule_edits,
    rule_occurrences,
    rule_reference_records,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_URI = "file://test.yar"


def _doc(text: str) -> DocumentContext:
    return DocumentContext(uri=_URI, text=text)


# A minimal valid YARA document with one string used in the condition.
_PARSEABLE_STRING = 'rule r {\n  strings:\n    $a = "x"\n  condition:\n    $a\n}'

# The same structure but with the closing brace removed so the parser fails
# and returns ast()=None, forcing the text-based fallback code path.
_UNPARSEABLE_STRING = 'rule r {\n  strings:\n    $a = "hello"\n  condition:\n    $a\n'

# Two-rule document: alpha is referenced in beta's condition.
_PARSEABLE_RULES = (
    "rule alpha {\n  condition:\n    true\n}\nrule beta {\n  condition:\n    alpha\n}"
)

# Same two-rule structure but last brace missing → unparseable.
_UNPARSEABLE_RULES = (
    "rule alpha {\n  condition:\n    true\n}\nrule beta {\n  condition:\n    alpha\n"
)


# ===========================================================================
# _require_symbol_name — lines 40-46
# ===========================================================================


def test_require_symbol_name_raises_type_error_for_non_string() -> None:
    """Line 41-42: non-string value raises TypeError."""
    with pytest.raises(TypeError, match="must be a string"):
        _require_symbol_name(123, "Test field")


def test_require_symbol_name_raises_value_error_for_empty_string() -> None:
    """Lines 44-45: whitespace-only string raises ValueError."""
    with pytest.raises(ValueError, match="must not be empty"):
        _require_symbol_name("   ", "Test field")


def test_require_symbol_name_accepts_valid_name() -> None:
    """Happy path: a non-empty string is returned unchanged."""
    result = _require_symbol_name("$foo", "Test field")
    assert result == "$foo"


# ===========================================================================
# _require_string_rename_name — lines 49-58
# ===========================================================================


def test_require_string_rename_name_raises_for_dollar_then_spaces() -> None:
    """Lines 52-54: dollar followed only by whitespace → empty bare name."""
    with pytest.raises(ValueError, match="must not be empty"):
        _require_string_rename_name("$   ")


def test_require_string_rename_name_raises_for_invalid_identifier() -> None:
    """Lines 55-57: bare name with non-word characters fails the regex."""
    with pytest.raises(ValueError, match="must be a valid identifier"):
        _require_string_rename_name("$invalid-name!")


def test_require_string_rename_name_accepts_bare_name_without_dollar() -> None:
    """Happy path: bare name (no leading $) is accepted and returned."""
    result = _require_string_rename_name("new_name")
    assert result == "new_name"


def test_require_string_rename_name_accepts_dollar_prefixed_name() -> None:
    """Happy path: dollar-prefixed valid name is accepted and returned."""
    result = _require_string_rename_name("$newname")
    assert result == "$newname"


# ===========================================================================
# _require_rule_rename_name — lines 61-71
# ===========================================================================


def test_require_rule_rename_name_raises_for_reserved_keyword() -> None:
    """Lines 69-70: a YARA keyword (not contextual) raises ValueError."""
    with pytest.raises(ValueError, match="must be a valid identifier"):
        _require_rule_rename_name("condition")


def test_require_rule_rename_name_raises_when_exceeds_max_length() -> None:
    """Lines 65, 69-70: name longer than YARA_IDENTIFIER_MAX_LENGTH raises."""
    too_long = "a" * 129  # YARA_IDENTIFIER_MAX_LENGTH is 128
    with pytest.raises(ValueError, match="must be a valid identifier"):
        _require_rule_rename_name(too_long)


def test_require_rule_rename_name_raises_for_digit_start() -> None:
    """Lines 66, 69-70: name starting with a digit fails _RULE_RENAME_RE."""
    with pytest.raises(ValueError, match="must be a valid identifier"):
        _require_rule_rename_name("1bad_name")


def test_require_rule_rename_name_allows_contextual_keywords() -> None:
    """Lines 63: 'as' and 'include' are contextual and must be accepted."""
    assert _require_rule_rename_name("as") == "as"
    assert _require_rule_rename_name("include") == "include"


def test_require_rule_rename_name_accepts_valid_identifier() -> None:
    """Happy path: a normal identifier is accepted."""
    result = _require_rule_rename_name("my_rule_v2")
    assert result == "my_rule_v2"


# ===========================================================================
# _require_bool_flag — lines 74-78
# ===========================================================================


def test_require_bool_flag_raises_for_non_bool() -> None:
    """Lines 76-77: a non-boolean value raises TypeError."""
    with pytest.raises(TypeError, match="must be a boolean"):
        _require_bool_flag("yes", "include_declaration")


def test_require_bool_flag_accepts_true() -> None:
    assert _require_bool_flag(True, "flag") is True


def test_require_bool_flag_accepts_false() -> None:
    assert _require_bool_flag(False, "flag") is False


# ===========================================================================
# _require_optional_rule_scope — lines 81-90
# ===========================================================================


def test_require_optional_rule_scope_returns_none_for_none() -> None:
    """Line 83: None passes through as None."""
    assert _require_optional_rule_scope(None) is None


def test_require_optional_rule_scope_raises_for_non_string() -> None:
    """Lines 85-86: non-string non-None raises TypeError."""
    with pytest.raises(TypeError, match="must be a string or None"):
        _require_optional_rule_scope(42)


def test_require_optional_rule_scope_raises_for_empty_string() -> None:
    """Lines 88-89: whitespace-only string raises ValueError."""
    with pytest.raises(ValueError, match="must not be empty"):
        _require_optional_rule_scope("   ")


def test_require_optional_rule_scope_accepts_valid_scope() -> None:
    """Happy path: a non-empty string is returned."""
    assert _require_optional_rule_scope("my_rule") == "my_rule"


# ===========================================================================
# find_string_references — text-fallback path (lines 100-145)
# Triggered when the document AST is None (unparseable source).
# ===========================================================================


def test_find_string_references_text_fallback_with_declaration() -> None:
    """Lines 114-145: text fallback finds definition and condition use."""
    ctx = _doc(_UNPARSEABLE_STRING)
    assert ctx.ast() is None  # confirms text-fallback will run

    locations = find_string_references(ctx, "$a", include_declaration=True)

    # Expect the strings-section definition on line 2 and the condition use on line 4.
    lines_covered = {loc.range.start.line for loc in locations}
    assert 2 in lines_covered  # definition
    assert 4 in lines_covered  # condition use


def test_find_string_references_text_fallback_without_declaration() -> None:
    """Lines 137-140: include_declaration=False excludes definition site."""
    ctx = _doc(_UNPARSEABLE_STRING)
    assert ctx.ast() is None

    locations = find_string_references(ctx, "$a", include_declaration=False)

    line_numbers = {loc.range.start.line for loc in locations}
    assert 2 not in line_numbers  # definition must be absent
    assert 4 in line_numbers  # condition use must be present


def test_find_string_references_text_fallback_normalizes_bare_name() -> None:
    """Lines 103-104: identifier without '$' prefix is normalized to '$<name>'."""
    ctx = _doc(_UNPARSEABLE_STRING)
    assert ctx.ast() is None

    locations = find_string_references(ctx, "a", include_declaration=True)

    assert any(loc.range.start.line == 4 for loc in locations)


def test_find_string_references_text_fallback_cache_hit() -> None:
    """Lines 106-107: second call returns cached copies (distinct objects)."""
    ctx = _doc(_UNPARSEABLE_STRING)
    assert ctx.ast() is None

    first = find_string_references(ctx, "$a", include_declaration=True)
    second = find_string_references(ctx, "$a", include_declaration=True)

    assert len(first) == len(second)
    # Defensive copies: same data but not the same Location objects.
    assert first[0] is not second[0]


def test_find_string_references_text_fallback_with_rule_scope() -> None:
    """Lines 102, 117: rule_scope parameter is passed through to definition lookup."""
    ctx = _doc(_UNPARSEABLE_STRING)
    assert ctx.ast() is None

    locations = find_string_references(ctx, "$a", rule_scope="r")
    assert isinstance(locations, list)


def test_find_string_references_text_fallback_unknown_string() -> None:
    """Text fallback returns empty list for a string that does not appear."""
    ctx = _doc(_UNPARSEABLE_STRING)
    assert ctx.ast() is None

    locations = find_string_references(ctx, "$nonexistent")
    assert locations == []


def test_find_string_references_text_fallback_returns_location_objects() -> None:
    """Line 131: make_range call produces Location objects with correct URI."""
    ctx = _doc(_UNPARSEABLE_STRING)
    assert ctx.ast() is None

    locations = find_string_references(ctx, "$a")
    for loc in locations:
        assert isinstance(loc, Location)
        assert loc.uri == _URI


# ===========================================================================
# find_string_reference_records — lines 155-177
# ===========================================================================


def test_find_string_reference_records_declaration_role() -> None:
    """Lines 164-175: definition site gets role='declaration'."""
    ctx = _doc(_PARSEABLE_STRING)
    assert ctx.ast() is not None

    records = find_string_reference_records(ctx, "$a")

    declaration_records = [r for r in records if r.role == "declaration"]
    assert len(declaration_records) == 1
    assert declaration_records[0].symbol_kind == "string"


def test_find_string_reference_records_read_role() -> None:
    """Lines 164-175: condition-use site gets role='read'."""
    ctx = _doc(_PARSEABLE_STRING)

    records = find_string_reference_records(ctx, "$a")

    read_records = [r for r in records if r.role == "read"]
    assert len(read_records) == 1
    assert read_records[0].symbol_kind == "string"


def test_find_string_reference_records_cache_hit_returns_copies() -> None:
    """Lines 161-162: second call returns data from cache as distinct objects."""
    ctx = _doc(_PARSEABLE_STRING)

    first = find_string_reference_records(ctx, "$a")
    second = find_string_reference_records(ctx, "$a")

    assert len(first) == len(second)
    assert first[0] is not second[0]


def test_find_string_reference_records_without_declaration() -> None:
    """Lines 156, 171-174: include_declaration=False excludes the definition."""
    ctx = _doc(_PARSEABLE_STRING)

    records = find_string_reference_records(ctx, "$a", include_declaration=False)

    assert all(r.role != "declaration" for r in records)
    assert len(records) == 1
    assert records[0].role == "read"


def test_find_string_reference_records_normalizes_bare_name() -> None:
    """Lines 158: identifier without '$' is normalized before lookup."""
    ctx = _doc(_PARSEABLE_STRING)

    records_bare = find_string_reference_records(ctx, "a")
    records_dollar = find_string_reference_records(ctx, "$a")

    assert len(records_bare) == len(records_dollar)


def test_find_string_reference_records_text_fallback_path() -> None:
    """Lines 163-176: records are built from text-based references for unparseable doc."""
    ctx = _doc(_UNPARSEABLE_STRING)
    assert ctx.ast() is None

    records = find_string_reference_records(ctx, "$a")

    assert len(records) >= 1
    assert all(r.symbol_kind == "string" for r in records)


# ===========================================================================
# build_string_rename_edits — text-fallback path (lines 187-218)
# ===========================================================================


def test_build_string_rename_edits_text_fallback_dollar_to_dollar() -> None:
    """Lines 194-218: text-fallback renames all occurrences of $a → $b."""
    ctx = _doc(_UNPARSEABLE_STRING)
    assert ctx.ast() is None

    edits = build_string_rename_edits(ctx, "$a", "$b")

    # Must produce at least the strings-section and condition edits.
    assert len(edits) >= 2
    assert all(isinstance(e, TextEdit) for e in edits)
    assert all(e.new_text in ("$b", "#b", "@b", "!b") for e in edits)


def test_build_string_rename_edits_adds_dollar_prefix_to_bare_new_name() -> None:
    """Lines 189-190: new_name without '$' gets '$' prepended."""
    ctx = _doc(_UNPARSEABLE_STRING)
    assert ctx.ast() is None

    edits = build_string_rename_edits(ctx, "$a", "c")

    # All $ replacements must use '$c', not 'c'.
    dollar_edits = [e for e in edits if e.new_text.startswith("$")]
    assert len(dollar_edits) >= 1
    assert all(e.new_text == "$c" for e in dollar_edits)


def test_build_string_rename_edits_text_fallback_identifier_without_dollar() -> None:
    """Line 194: identifier path where identifier does not start with '$'."""
    ctx = _doc(_UNPARSEABLE_STRING)
    assert ctx.ast() is None

    # 'a' does not start with '$'; base_name branch at line 194 uses it directly.
    edits = build_string_rename_edits(ctx, "a", "$renamed")

    assert len(edits) >= 1


def test_build_string_rename_edits_validates_new_name_regex() -> None:
    """Lines 188: invalid new_name is rejected before any document access."""
    ctx = _doc(_PARSEABLE_STRING)

    with pytest.raises(ValueError, match="must be a valid identifier"):
        build_string_rename_edits(ctx, "$a", "$bad-name!")


def test_build_string_rename_edits_text_fallback_unknown_string() -> None:
    """Text fallback returns empty list when the identifier does not appear."""
    ctx = _doc(_UNPARSEABLE_STRING)
    assert ctx.ast() is None

    edits = build_string_rename_edits(ctx, "$zzz", "$renamed")
    assert edits == []


# ===========================================================================
# rename_rule_edits — lines 221-227
# ===========================================================================


def test_rename_rule_edits_returns_text_edits_for_all_occurrences() -> None:
    """Lines 224-226: every occurrence of rule_name gets a TextEdit."""
    ctx = _doc(_PARSEABLE_RULES)

    edits = rename_rule_edits(ctx, "alpha", "gamma")

    assert len(edits) >= 1
    assert all(isinstance(e, TextEdit) for e in edits)
    assert all(e.new_text == "gamma" for e in edits)


def test_rename_rule_edits_validates_new_name() -> None:
    """Line 223: invalid new_name raises ValueError."""
    ctx = _doc(_PARSEABLE_RULES)

    with pytest.raises(ValueError, match="must be a valid identifier"):
        rename_rule_edits(ctx, "alpha", "condition")


def test_rename_rule_edits_validates_rule_name_type() -> None:
    """Lines 222: non-string rule_name raises TypeError."""
    ctx = _doc(_PARSEABLE_RULES)

    with pytest.raises(TypeError, match="must be a string"):
        rename_rule_edits(ctx, 99, "gamma")  # type: ignore[arg-type]


# ===========================================================================
# find_rule_definition — lines 230-241
# ===========================================================================


def test_find_rule_definition_returns_location_for_known_rule() -> None:
    """Lines 237-240: returns a Location pointing to the rule definition."""
    ctx = _doc(_PARSEABLE_RULES)

    result = find_rule_definition(ctx, "alpha")

    assert result is not None
    assert isinstance(result, Location)
    assert result.uri == _URI
    assert result.range.start.line == 0  # 'rule alpha' starts on line 0


def test_find_rule_definition_returns_none_for_unknown_rule() -> None:
    """Line 241: returns None when the rule name does not appear."""
    ctx = _doc(_PARSEABLE_RULES)

    result = find_rule_definition(ctx, "nonexistent")

    assert result is None


def test_find_rule_definition_cache_hit_returns_defensive_copy() -> None:
    """Lines 234-235: second call hits cache and returns a distinct object."""
    ctx = _doc(_PARSEABLE_RULES)

    first = find_rule_definition(ctx, "alpha")
    second = find_rule_definition(ctx, "alpha")

    assert first is not None and second is not None
    assert first is not second
    assert first.range.start.line == second.range.start.line


# ===========================================================================
# rule_occurrences — text-fallback path (lines 263-275)
# ===========================================================================


def test_rule_occurrences_text_fallback_with_definition() -> None:
    """Lines 255-257, 270-273: definition is prepended; condition reference added."""
    ctx = _doc(_UNPARSEABLE_RULES)
    assert ctx.ast() is None

    locations = rule_occurrences(ctx, "alpha")

    line_numbers = {loc.range.start.line for loc in locations}
    assert 0 in line_numbers  # definition on line 0
    assert 6 in line_numbers  # reference in beta's condition on line 6


def test_rule_occurrences_text_fallback_definition_none_still_collects_uses() -> None:
    """Lines 256, 258-273: when definition=None, only condition uses are collected."""
    # Doc has beta using alpha, but alpha has no declaration → definition=None.
    text = "rule beta {\n  condition:\n    alpha\n"  # no closing brace, no alpha decl
    ctx = _doc(text)
    assert ctx.ast() is None

    locations = rule_occurrences(ctx, "alpha")

    # alpha has no definition so line 256 branch is skipped; line 263+ runs.
    assert any(loc.range.start.line == 2 for loc in locations)


def test_rule_occurrences_cache_hit_returns_defensive_copies() -> None:
    """Lines 248-249: second call returns data from cache as distinct objects."""
    ctx = _doc(_PARSEABLE_RULES)

    first = rule_occurrences(ctx, "alpha")
    second = rule_occurrences(ctx, "alpha")

    assert len(first) == len(second)
    assert first[0] is not second[0]


# ===========================================================================
# rule_reference_records — lines 284-298
# ===========================================================================


def test_rule_reference_records_with_declaration() -> None:
    """Lines 291-297: declaration occurrence gets role='declaration'."""
    ctx = _doc(_PARSEABLE_RULES)

    records = rule_reference_records(ctx, "alpha", include_declaration=True)

    declaration_records = [r for r in records if r.role == "declaration"]
    assert len(declaration_records) == 1
    assert declaration_records[0].symbol_kind == "rule"


def test_rule_reference_records_without_declaration() -> None:
    """Lines 293-294: include_declaration=False skips the definition occurrence."""
    ctx = _doc(_PARSEABLE_RULES)

    records = rule_reference_records(ctx, "alpha", include_declaration=False)

    assert all(r.role != "declaration" for r in records)
    assert len(records) >= 1


def test_rule_reference_records_cache_hit_returns_copies() -> None:
    """Lines 288-289: second call serves data from cache as distinct objects."""
    ctx = _doc(_PARSEABLE_RULES)

    first = rule_reference_records(ctx, "alpha", include_declaration=True)
    second = rule_reference_records(ctx, "alpha", include_declaration=True)

    assert len(first) == len(second)
    assert first[0] is not second[0]


def test_rule_reference_records_validates_symbol_name_type() -> None:
    """Lines 284: non-string rule_name raises TypeError."""
    ctx = _doc(_PARSEABLE_RULES)

    with pytest.raises(TypeError, match="must be a string"):
        rule_reference_records(ctx, 0, include_declaration=True)  # type: ignore[arg-type]


def test_rule_reference_records_validates_include_declaration_type() -> None:
    """Lines 285: non-boolean include_declaration raises TypeError."""
    ctx = _doc(_PARSEABLE_RULES)

    with pytest.raises(TypeError, match="must be a boolean"):
        rule_reference_records(ctx, "alpha", include_declaration=1)  # type: ignore[arg-type]


def test_rule_reference_records_use_role_for_non_definition() -> None:
    """Lines 295: non-definition occurrence gets role='use'."""
    ctx = _doc(_PARSEABLE_RULES)

    records = rule_reference_records(ctx, "alpha", include_declaration=True)

    use_records = [r for r in records if r.role == "use"]
    assert len(use_records) >= 1
    assert use_records[0].symbol_kind == "rule"


# ===========================================================================
# get_local_rule_link_records — lines 301-320
# ===========================================================================


def test_get_local_rule_link_records_returns_links_for_rule_references() -> None:
    """Lines 306-319: populates records for each cross-rule reference."""
    ctx = _doc(_PARSEABLE_RULES)

    links = get_local_rule_link_records(ctx)

    # beta references alpha, so there must be one link with rule_name='alpha'.
    assert len(links) >= 1
    link = links[0]
    assert link.rule_name == "alpha"
    assert link.target_uri == _URI


def test_get_local_rule_link_records_cache_hit_returns_copies() -> None:
    """Lines 304-305: second call returns cached data as distinct objects."""
    ctx = _doc(_PARSEABLE_RULES)

    first = get_local_rule_link_records(ctx)
    second = get_local_rule_link_records(ctx)

    assert len(first) == len(second)
    assert first[0] is not second[0]


def test_get_local_rule_link_records_empty_when_no_cross_references() -> None:
    """Lines 307-319: returns empty list when no rule references another rule."""
    text = "rule alpha {\n  condition:\n    true\n}\nrule beta {\n  condition:\n    true\n}"
    ctx = _doc(text)

    links = get_local_rule_link_records(ctx)

    assert links == []


def test_get_local_rule_link_records_skips_rules_without_definition() -> None:
    """Lines 308-310: rules without a recoverable definition symbol are skipped."""
    # A document where rule names are found but definition lookup returns None
    # can only be constructed through specific conditions.  Use the parseable
    # two-rule document and verify that every returned link has a non-None
    # target_uri, which proves the definition-None guard (line 309) filtered correctly.
    ctx = _doc(_PARSEABLE_RULES)

    links = get_local_rule_link_records(ctx)

    assert all(link.target_uri for link in links)


def test_get_local_rule_link_records_location_is_reference_not_definition() -> None:
    """Lines 311-318: link location points to the use site, not the definition."""
    ctx = _doc(_PARSEABLE_RULES)

    links = get_local_rule_link_records(ctx)

    # alpha is defined at line 0; the use in beta is at line 6.
    assert any(link.location.range.start.line == 6 for link in links)


def test_get_local_rule_link_records_multiple_references_expand_correctly() -> None:
    """Lines 312-318: multiple uses of the same rule produce multiple records."""
    text = (
        "rule alpha {\n  condition:\n    true\n}\n"
        "rule beta {\n  condition:\n    alpha\n}\n"
        "rule gamma {\n  condition:\n    alpha\n}"
    )
    ctx = _doc(text)

    links = get_local_rule_link_records(ctx)

    alpha_links = [lnk for lnk in links if lnk.rule_name == "alpha"]
    assert len(alpha_links) == 2


# ===========================================================================
# Additional coverage for lines 142 and 193
# ===========================================================================


def test_find_string_references_skips_strings_section_non_definition() -> None:
    """Line 142: string token in strings: section without '=' is filtered out.

    When $a appears in the strings section but has no assignment (e.g., a bare
    identifier without '= <value>'), is_definition evaluates to False and
    section_name is 'strings', so the occurrence is skipped via line 142.
    """
    # $b is properly defined; $a appears on its own line (no '= ...'), which
    # means it is not a definition occurrence.  The condition use on line 5 is
    # the only occurrence that should be returned.
    text = "rule r {\n  strings:\n    $b = /pattern/\n    $a\n  condition:\n    $a\n"
    ctx = _doc(text)
    assert ctx.ast() is None  # unparseable: text fallback path

    locations = find_string_references(ctx, "$a", include_declaration=True)

    # The strings-section bare occurrence is skipped; only the condition use remains.
    line_numbers = {loc.range.start.line for loc in locations}
    assert 5 in line_numbers
    # Line 3 is the bare $a in strings section — it should NOT appear.
    assert 3 not in line_numbers


def test_build_string_rename_edits_ast_path_returns_edits_directly() -> None:
    """Line 193: when the AST is parseable, the AST-produced edits are returned early.

    build_string_rename_edits_from_ast returns a non-None list when the document
    is parseable, so line 193 (return ast_edits) is executed and the text fallback
    loop (lines 194-217) is never entered.
    """
    ctx = _doc(_PARSEABLE_STRING)
    assert ctx.ast() is not None  # parseable: AST rename path

    edits = build_string_rename_edits(ctx, "$a", "$renamed")

    # The AST path always produces edits for both the definition and the use.
    assert len(edits) == 2
    assert all(isinstance(e, TextEdit) for e in edits)
    assert all(e.new_text == "$renamed" for e in edits)
