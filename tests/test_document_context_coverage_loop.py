# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""Regression tests targeting uncovered lines in yaraast/lsp/document_context.py.

Missing-line targets (module baseline 82.37% from the combined targeted run):

  62-63   _require_document_string: TypeError branch (non-str URI or text)
  69      _range_contains_position: position.line outside [start, end] -> False
  71      _range_contains_position: same line as start, character before start -> False
  144-145 DocumentContext.__init__: version is a bool (bool is int but invalid) -> TypeError
  147-148 DocumentContext.__init__: is_open not bool -> TypeError
  150-151 DocumentContext.__init__: backed_by_file not bool -> TypeError
  153-154 DocumentContext.__init__: language_mode not LanguageMode -> TypeError
  178-179 get_cached: stale revision evicts entry and returns None
  198-199 update(): version is a bool -> TypeError
  201-204 update(): is_open provided as non-bool -> TypeError
  215-216 set_language_mode(): non-LanguageMode arg -> TypeError
  263     find_string_definition: same name but wrong rule_scope -> continue
  265     find_string_definition: no match in loop -> return None
  267     find_string_definition: identifier not found at all -> None
  272     rule_name_at_position: ast() is None -> return None immediately
  279     rule_name_at_position: position falls inside a rule -> return rule name
  281-283 rule_name_at_position: no rule contains position -> return None
  295     get_rule: loop exhausted, no matching name -> return None
  307->306 _unique_symbol_names: dedup branch blocks repeated symbol name
  334     get_module_info: module_name not in MODULE_DOCS -> return None
  349     get_include_target_uri: delegates to lookup helper
  355     get_dotted_symbol_at_position: delegates to lookup helper

Unreachable lines (documented, not tested):
  Line 249 (dialect() fallback `or self.language_mode.to_dialect(self.text)`):
    this expression can only evaluate the right-hand side when _dialect is None
    after ast() runs. When ast() fails with ParserError or LexerError, it still sets
    self._dialect before reaching the except block (the assignment on line 231 runs
    before parse(), so it is always set even if parse() fails immediately after).
    Therefore line 249 is unreachable through real document processing.

All tests parse real YARA documents through the public DocumentContext API.
No mocking, stubbing, or artificial scaffolding is used.
"""

from __future__ import annotations

import os
import tempfile

from lsprotocol.types import Position, Range
import pytest

from yaraast.lsp.document_context import (
    DocumentContext,
    _range_contains_position,
    _require_document_string,
)
from yaraast.lsp.document_types import LanguageMode

# ---------------------------------------------------------------------------
# Reusable YARA source text
# ---------------------------------------------------------------------------

_SINGLE_RULE = 'rule alpha {\n    strings:\n        $a = "hello"\n    condition:\n        $a\n}\n'

_TWO_RULES_SAME_STRING = (
    "rule alpha {\n"
    "    strings:\n"
    '        $a = "hello"\n'
    "    condition:\n"
    "        $a\n"
    "}\n"
    "rule beta {\n"
    "    strings:\n"
    '        $a = "world"\n'
    "    condition:\n"
    "        $a\n"
    "}\n"
)

_DOUBLE_IMPORT = 'import "pe"\nimport "pe"\nrule x {\n    condition:\n        true\n}\n'

_MODULE_USE = "rule x { condition: pe.is_dll }\n"

_BROKEN_YARA = "this is not valid yara }{"


def _doc(text: str, uri: str = "file://test.yar") -> DocumentContext:
    return DocumentContext(uri=uri, text=text)


# ---------------------------------------------------------------------------
# _require_document_string: TypeError on non-str inputs (lines 62-63)
# ---------------------------------------------------------------------------


def test_require_document_string_raises_for_non_str_uri() -> None:
    """Passing a non-string URI raises TypeError (line 62-63 via constructor)."""
    with pytest.raises(TypeError, match="Document URI must be a string"):
        DocumentContext(uri=123, text="rule x { condition: true }")  # type: ignore[arg-type]


def test_require_document_string_raises_for_none_text() -> None:
    """Passing None as text raises TypeError (line 62-63 via constructor)."""
    with pytest.raises(TypeError, match="Document text must be a string"):
        DocumentContext(uri="file://x.yar", text=None)  # type: ignore[arg-type]


def test_require_document_string_update_raises_for_non_str_text() -> None:
    """update() propagates TypeError via _require_document_string (line 62-63)."""
    doc = _doc(_SINGLE_RULE)
    with pytest.raises(TypeError, match="Document text must be a string"):
        doc.update(text=42)  # type: ignore[arg-type]


def test_require_document_string_function_directly() -> None:
    """_require_document_string returns the value unchanged for valid strings."""
    assert _require_document_string("hello", "field") == "hello"


def test_require_document_string_function_raises_for_int() -> None:
    """_require_document_string raises TypeError for non-str values."""
    with pytest.raises(TypeError, match="field must be a string"):
        _require_document_string(99, "field")


# ---------------------------------------------------------------------------
# _range_contains_position: branch coverage (lines 69, 71, 72)
# ---------------------------------------------------------------------------


def test_range_contains_position_before_start_line_returns_false() -> None:
    """Position before range.start.line -> False (line 69 branch)."""
    r = Range(start=Position(line=5, character=0), end=Position(line=10, character=10))
    assert not _range_contains_position(r, Position(line=4, character=0))


def test_range_contains_position_after_end_line_returns_false() -> None:
    """Position after range.end.line -> False (line 69 branch)."""
    r = Range(start=Position(line=5, character=0), end=Position(line=10, character=10))
    assert not _range_contains_position(r, Position(line=11, character=0))


def test_range_contains_position_same_as_start_line_before_start_char_returns_false() -> None:
    """Position on start line but before start.character -> False (line 71 branch)."""
    r = Range(start=Position(line=3, character=5), end=Position(line=3, character=15))
    assert not _range_contains_position(r, Position(line=3, character=2))


def test_range_contains_position_at_end_character_returns_false() -> None:
    """Position at end.character (>= end) on end line -> False (line 72 branch)."""
    r = Range(start=Position(line=3, character=0), end=Position(line=3, character=10))
    assert not _range_contains_position(r, Position(line=3, character=10))


def test_range_contains_position_inside_returns_true() -> None:
    """Position strictly inside range -> True (line 72 returns True)."""
    r = Range(start=Position(line=3, character=4), end=Position(line=3, character=12))
    assert _range_contains_position(r, Position(line=3, character=6))


# ---------------------------------------------------------------------------
# DocumentContext.__init__: type validation branches (lines 143-154)
# ---------------------------------------------------------------------------


def test_init_version_as_bool_raises_type_error() -> None:
    """version=True raises TypeError because bool is excluded (lines 144-145)."""
    with pytest.raises(TypeError, match="Document version must be an integer or None"):
        DocumentContext(uri="file://x.yar", text="rule x { condition: true }", version=True)


def test_init_is_open_as_non_bool_raises_type_error() -> None:
    """is_open='yes' raises TypeError (lines 147-148)."""
    with pytest.raises(TypeError, match="Document is_open flag must be a boolean"):
        DocumentContext(uri="file://x.yar", text="rule x { condition: true }", is_open="yes")  # type: ignore[arg-type]


def test_init_backed_by_file_as_int_raises_type_error() -> None:
    """backed_by_file=1 raises TypeError (lines 150-151)."""
    with pytest.raises(TypeError, match="Document backed_by_file flag must be a boolean"):
        DocumentContext(
            uri="file://x.yar",
            text="rule x { condition: true }",
            backed_by_file=1,  # type: ignore[arg-type]
        )


def test_init_language_mode_as_string_raises_type_error() -> None:
    """language_mode='yara' raises TypeError (lines 153-154)."""
    with pytest.raises(TypeError, match="Document language_mode must be a LanguageMode"):
        DocumentContext(
            uri="file://x.yar",
            text="rule x { condition: true }",
            language_mode="yara",  # type: ignore[arg-type]
        )


# ---------------------------------------------------------------------------
# get_cached: stale-revision eviction (lines 178-179)
# ---------------------------------------------------------------------------


def test_get_cached_returns_none_after_revision_changes() -> None:
    """Cached entry is evicted when the document's revision_key changes (lines 178-179)."""
    doc = DocumentContext(uri="file://x.yar", text="rule x { condition: true }", version=1)
    doc.set_cached("analysis:foo", {"result": 42})

    # Confirm the entry is retrievable before changing the revision key.
    assert doc.get_cached("analysis:foo") == {"result": 42}

    # Changing the version changes revision_key() so the cached entry is stale.
    doc.version = 99
    evicted = doc.get_cached("analysis:foo")
    assert evicted is None

    # The stale entry is also removed from _analysis_cache by the eviction.
    assert "analysis:foo" not in doc._analysis_cache


def test_get_cached_returns_value_when_revision_matches() -> None:
    """Cached entry survives unchanged revision key (set/get round-trip)."""
    doc = _doc(_SINGLE_RULE)
    doc.set_cached("key", "value")
    assert doc.get_cached("key") == "value"


# ---------------------------------------------------------------------------
# update(): type validation branches (lines 197-204)
# ---------------------------------------------------------------------------


def test_update_version_as_bool_raises_type_error() -> None:
    """update(version=False) raises TypeError because bool is excluded (lines 198-199)."""
    doc = _doc(_SINGLE_RULE)
    with pytest.raises(TypeError, match="Document version must be an integer or None"):
        doc.update(text="rule y { condition: true }", version=False)


def test_update_is_open_as_non_bool_raises_type_error() -> None:
    """update(is_open='yes') raises TypeError (lines 202-204)."""
    doc = _doc(_SINGLE_RULE)
    with pytest.raises(TypeError, match="Document is_open flag must be a boolean"):
        doc.update(text="rule y { condition: true }", is_open="yes")  # type: ignore[arg-type]


def test_update_with_valid_is_open_bool_updates_flag() -> None:
    """update(is_open=True) successfully updates the flag (normal path through line 201-205)."""
    doc = DocumentContext(uri="file://x.yar", text=_SINGLE_RULE, is_open=False)
    doc.update(text=_SINGLE_RULE, is_open=True)
    assert doc.is_open is True


# ---------------------------------------------------------------------------
# set_language_mode(): TypeError branch (lines 215-216)
# ---------------------------------------------------------------------------


def test_set_language_mode_non_enum_raises_type_error() -> None:
    """set_language_mode('yara') raises TypeError (lines 215-216)."""
    doc = _doc(_SINGLE_RULE)
    with pytest.raises(TypeError, match="Document language_mode must be a LanguageMode"):
        doc.set_language_mode("yara")  # type: ignore[arg-type]


def test_set_language_mode_same_value_is_noop() -> None:
    """set_language_mode with the current mode returns without any state change (line 218)."""
    doc = DocumentContext(uri="file://x.yar", text=_SINGLE_RULE, language_mode=LanguageMode.YARA)
    doc.ast()
    ast_before = doc._ast

    doc.set_language_mode(LanguageMode.YARA)  # same mode -> early return

    # AST is unchanged because the early-return skipped invalidation.
    assert doc._ast is ast_before


def test_set_language_mode_different_value_invalidates_cache() -> None:
    """set_language_mode with a different mode invalidates the AST cache."""
    doc = DocumentContext(uri="file://x.yar", text=_SINGLE_RULE, language_mode=LanguageMode.YARA)
    doc.ast()
    assert doc._ast is not None

    doc.set_language_mode(LanguageMode.AUTO)

    assert doc._ast is None
    assert doc._dialect is None


# ---------------------------------------------------------------------------
# find_string_definition: rule_scope filtering and None return (lines 263-267)
# ---------------------------------------------------------------------------


def test_find_string_definition_with_correct_rule_scope_returns_location() -> None:
    """find_string_definition with matching rule_scope returns the Location."""
    doc = _doc(_TWO_RULES_SAME_STRING)
    loc = doc.find_string_definition("$a", rule_scope="beta")
    assert loc is not None
    assert loc.uri == "file://test.yar"


def test_find_string_definition_with_wrong_rule_scope_skips_and_returns_none() -> None:
    """$a exists but in rule 'alpha', not 'gamma' -> loop body skips (line 265) -> None (line 267)."""
    doc = _doc(_TWO_RULES_SAME_STRING)
    # 'gamma' does not exist in the document; both $a entries are skipped via line 265.
    loc = doc.find_string_definition("$a", rule_scope="gamma")
    assert loc is None


def test_find_string_definition_nonexistent_identifier_returns_none() -> None:
    """Identifier not present at all -> loop never enters continue path -> None (line 267)."""
    doc = _doc(_SINGLE_RULE)
    loc = doc.find_string_definition("$nonexistent")
    assert loc is None


def test_find_string_definition_no_scope_returns_first_match() -> None:
    """Without rule_scope, returns first matching Location regardless of rule."""
    doc = _doc(_TWO_RULES_SAME_STRING)
    loc = doc.find_string_definition("$a")
    assert loc is not None


# ---------------------------------------------------------------------------
# rule_name_at_position: ast=None branch, inside-rule branch, no-match branch
# (lines 272, 279, 281-283)
# ---------------------------------------------------------------------------


def test_rule_name_at_position_with_unparseable_doc_returns_none() -> None:
    """When ast() is None, rule_name_at_position returns None immediately (line 272)."""
    doc = _doc(_BROKEN_YARA)
    result = doc.rule_name_at_position(Position(line=0, character=0))
    assert result is None


def test_rule_name_at_position_inside_rule_returns_name() -> None:
    """Position inside a rule's range returns that rule's name (line 279)."""
    doc = _doc(_SINGLE_RULE)
    assert doc.ast() is not None
    # Line 1 (0-indexed) is inside the 'alpha' rule body.
    result = doc.rule_name_at_position(Position(line=1, character=4))
    assert result == "alpha"


def test_rule_name_at_position_outside_all_rules_returns_none() -> None:
    """Position beyond all rule ranges returns None (line 283)."""
    doc = _doc(_SINGLE_RULE)
    result = doc.rule_name_at_position(Position(line=999, character=0))
    assert result is None


# ---------------------------------------------------------------------------
# get_rule: no matching rule returns None (line 295)
# ---------------------------------------------------------------------------


def test_get_rule_nonexistent_name_returns_none() -> None:
    """get_rule with a name not in the document returns None (line 295)."""
    doc = _doc(_SINGLE_RULE)
    assert doc.ast() is not None
    result = doc.get_rule("nonexistent_rule")
    assert result is None


def test_get_rule_existing_name_returns_rule() -> None:
    """get_rule with an existing rule name returns the rule object."""
    doc = _doc(_SINGLE_RULE)
    rule = doc.get_rule("alpha")
    assert rule is not None
    assert getattr(rule, "name", None) == "alpha"


# ---------------------------------------------------------------------------
# _unique_symbol_names: dedup branch (line 307->306)
# ---------------------------------------------------------------------------


def test_get_import_modules_deduplicates_repeated_imports() -> None:
    """Duplicate import declarations produce only one entry (line 307->306 branch)."""
    doc = _doc(_DOUBLE_IMPORT)
    imports = doc.get_import_modules()
    assert imports == ["pe"]
    assert imports.count("pe") == 1


def test_get_include_paths_deduplicates_repeated_includes() -> None:
    """Duplicate include declarations produce only one entry (dedup branch)."""
    yara = 'include "./other.yar"\ninclude "./other.yar"\nrule x { condition: true }\n'
    doc = _doc(yara)
    paths = doc.get_include_paths()
    assert paths == ["./other.yar"]


# ---------------------------------------------------------------------------
# get_module_info: unknown module returns None (line 334)
# ---------------------------------------------------------------------------


def test_get_module_info_unknown_module_returns_none() -> None:
    """Module not in MODULE_DOCS -> return None (line 324)."""
    doc = _doc(_SINGLE_RULE)
    result = doc.get_module_info("totally_unknown_module_xyz")
    assert result is None


def test_get_module_info_known_module_returns_dict() -> None:
    """Known module ('pe') returns a dict with name and description."""
    doc = _doc(_SINGLE_RULE)
    result = doc.get_module_info("pe")
    assert result is not None
    assert result["name"] == "pe"
    assert "description" in result


# ---------------------------------------------------------------------------
# get_include_target_uri: delegate to lookup (line 354-355)
# ---------------------------------------------------------------------------


def test_get_include_target_uri_resolves_existing_file() -> None:
    """get_include_target_uri returns the resolved URI for an existing neighbour file."""
    with tempfile.TemporaryDirectory() as tmpdir:
        neighbour = os.path.join(tmpdir, "other.yar")
        with open(neighbour, "w") as f:
            f.write("rule included { condition: true }\n")

        main_path = os.path.join(tmpdir, "main.yar")
        text = 'include "other.yar"\nrule x { condition: true }\n'
        with open(main_path, "w") as f:
            f.write(text)

        doc = DocumentContext(uri="file://" + main_path, text=text, backed_by_file=True)
        result = doc.get_include_target_uri("other.yar")
        assert result is not None
        assert result.endswith("other.yar")


def test_get_include_target_uri_nonexistent_returns_none() -> None:
    """get_include_target_uri returns None when the target file does not exist."""
    doc = _doc('include "missing.yar"\nrule x { condition: true }\n')
    result = doc.get_include_target_uri("missing.yar")
    assert result is None


# ---------------------------------------------------------------------------
# get_dotted_symbol_at_position: delegate to lookup (line 357-358)
# ---------------------------------------------------------------------------


def test_get_dotted_symbol_at_position_returns_symbol_and_range() -> None:
    """Position inside 'pe.is_dll' returns the dotted name and its Range."""
    doc = _doc(_MODULE_USE)
    result = doc.get_dotted_symbol_at_position(Position(line=0, character=20))
    assert result is not None
    symbol_name, symbol_range = result
    assert "pe" in symbol_name
    assert isinstance(symbol_range, Range)


def test_get_dotted_symbol_at_position_on_plain_keyword_returns_none() -> None:
    """Position inside 'rule' keyword (no dot) returns None."""
    doc = _doc(_MODULE_USE)
    result = doc.get_dotted_symbol_at_position(Position(line=0, character=2))
    assert result is None


def test_get_dotted_symbol_at_position_out_of_range_line_returns_none() -> None:
    """Position on a line beyond the document returns None."""
    doc = _doc(_MODULE_USE)
    result = doc.get_dotted_symbol_at_position(Position(line=999, character=0))
    assert result is None


# ---------------------------------------------------------------------------
# Revision key and cache coherence: ensure revision_key reflects both text and version
# ---------------------------------------------------------------------------


def test_revision_key_differs_after_version_change() -> None:
    """revision_key changes when only version changes, even if text stays the same."""
    doc = DocumentContext(uri="file://x.yar", text=_SINGLE_RULE, version=1)
    key_v1 = doc.revision_key()
    doc.version = 2
    key_v2 = doc.revision_key()
    assert key_v1 != key_v2


def test_revision_key_differs_after_text_change() -> None:
    """revision_key changes when text changes."""
    doc = DocumentContext(uri="file://x.yar", text="rule x { condition: true }")
    k1 = doc.revision_key()
    doc.update(text="rule y { condition: false }")
    k2 = doc.revision_key()
    assert k1 != k2


def test_revision_key_includes_noversion_when_version_is_none() -> None:
    """revision_key contains 'noversion' prefix when version is None."""
    doc = _doc(_SINGLE_RULE)
    assert doc.revision_key().startswith("noversion:")
